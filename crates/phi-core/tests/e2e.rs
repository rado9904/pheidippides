use anyhow::{Result, ensure};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use phi_core::*;
use phi_proto::*;
use phi_server::{
    Server,
    config::{Config, Creation},
};
use rusqlite::OptionalExtension;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Default)]
struct Faults {
    omit_device: Option<DeviceId>,
    hide_revocations: bool,
    inflate_cursor: bool,
    corrupt_event: Option<MessageId>,
    unsigned_retention: Option<u32>,
    backdate_messages: bool,
    fail_metadata: Option<ChannelId>,
    fail_revocations: bool,
    fail_message: Option<MessageId>,
    lose_revocation_response: bool,
    directory_reads: usize,
    drop_event_polls: usize,
}
async fn hostile_host(
    State(faults): State<Arc<Mutex<Faults>>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let Ok((faults, drop_poll)) = faults.lock().map(|mut f| {
        if path.ends_with("/devices") {
            f.directory_reads += 1;
        }
        let drop_poll = path.ends_with("/events") && f.drop_event_polls > 0;
        if drop_poll {
            f.drop_event_polls -= 1;
        }
        (f.clone(), drop_poll)
    }) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if drop_poll {
        // What nginx returns when its proxy_read_timeout cuts an idle long-poll.
        return (StatusCode::BAD_GATEWAY, "<html>502 Bad Gateway</html>").into_response();
    }
    if (faults
        .fail_metadata
        .is_some_and(|id| path == format!("/v1/channels/{id}"))
        && request.method() == Method::PATCH)
        || (faults.fail_revocations
            && path.ends_with("/revocations")
            && request.method() == Method::POST)
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error":"interrupted publication"})),
        )
            .into_response();
    }
    if faults
        .fail_message
        .is_some_and(|id| path == format!("/v1/messages/{id}"))
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error":"temporary failure"})),
        )
            .into_response();
    }
    let response = next.run(request).await;
    if faults.lose_revocation_response
        && path.ends_with("/revocations")
        && response.status().is_success()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"error":"lost response after commit"})),
        )
            .into_response();
    }
    if !response.status().is_success()
        || !response
            .headers()
            .get("content-type")
            .is_some_and(|v| v.as_bytes().starts_with(b"application/json"))
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, 32 * 1024 * 1024).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    if path.ends_with("/devices") {
        if let Some(id) = faults.omit_device {
            if let Some(devices) = value.get_mut("devices").and_then(|v| v.as_array_mut()) {
                devices.retain(|device| device["cert"]["data"]["device_id"] != id.to_string());
            }
        }
        if faults.hide_revocations {
            value["directory"]["revocations"] = serde_json::json!([]);
        }
    }
    if value.get("settings").is_some() {
        if let Some(retention) = faults.unsigned_retention {
            value["settings"]["retention_days"] = retention.into();
            value["settings_change"] = serde_json::Value::Null;
        }
    }
    if path.ends_with("/events") {
        if faults.inflate_cursor {
            value["next_after"] = 1_000_000.into();
        }
        if let Some(id) = faults.corrupt_event {
            if let Some(events) = value.get_mut("events").and_then(|v| v.as_array_mut()) {
                for event in events {
                    if event["event"]["data"]["id"] == id.to_string() {
                        event["event"]["data"]["signature"] =
                            serde_json::to_value(Signature::from_bytes([0; 64]))
                                .unwrap_or_default();
                    }
                }
            }
        }
    }
    if faults.backdate_messages {
        backdate(&mut value);
    }
    parts.headers.remove("content-length");
    match serde_json::to_vec(&value) {
        Ok(body) => Response::from_parts(parts, Body::from(body)),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
fn backdate(value: &mut serde_json::Value) {
    if value.get("envelope").is_some() && value.get("author_device").is_some() {
        value["created_at"] = 1.into();
    }
    match value {
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                backdate(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                backdate(value);
            }
        }
        _ => {}
    }
}
use tempfile::TempDir;

struct Fixture {
    dir: TempDir,
    url: String,
    server: Server,
    task: tokio::task::JoinHandle<()>,
    faults: Arc<Mutex<Faults>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Result<Self> {
        Self::configured(|_| {}).await
    }
    async fn configured(update: impl FnOnce(&mut Config)) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = Config {
            data_dir: dir.path().join("server"),
            allow_space_creation: Creation::Anyone,
            ..Config::default()
        };
        update(&mut config);
        let server = Server::open(config)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let faults = Arc::new(Mutex::new(Faults::default()));
        let router = server.router().layer(axum::middleware::from_fn_with_state(
            faults.clone(),
            hostile_host,
        ));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok(Self {
            dir,
            url,
            server,
            task,
            faults,
        })
    }
    fn faults(&self, update: impl FnOnce(&mut Faults)) -> Result<()> {
        let mut faults = self
            .faults
            .lock()
            .map_err(|_| anyhow::anyhow!("fault mutex poisoned"))?;
        update(&mut faults);
        Ok(())
    }
    fn store(&self, name: &str) -> Store {
        Store::new(
            self.dir.path().join(name).join("config"),
            self.dir.path().join(name).join("cache"),
        )
    }
    async fn alice(&self) -> Result<Client> {
        Ok(Client::create(self.store("alice"), &self.url, "game", "alice", None).await?)
    }
    async fn pair(&self) -> Result<(Client, Client)> {
        let mut alice = self.alice().await?;
        let link = alice.invite(false, false).await?;
        let bob = Client::join(self.store("bob"), &link, "bob").await?;
        alice.refresh().await?;
        Ok((alice, bob))
    }
}
fn options(body: &str) -> SendOptions {
    SendOptions {
        body: body.into(),
        summary: Some(format!("Summary: {body}")),
        files: vec![],
    }
}

#[tokio::test]
async fn create_invite_join_attachment_fetch_read_reply() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let path = f.dir.path().join("shot.png");
    std::fs::write(&path, b"image bytes")?;
    let mut message = options("Please review repo foo at abc123.");
    message.files.push(path);
    for (name, bytes) in [
        ("renderer.PY", b"print('hello')\n".as_slice()),
        ("settings.toml", b"enabled = true\n".as_slice()),
        ("notes.custom", b"plain text\n".as_slice()),
        ("opaque.bin", b"\0\xff".as_slice()),
    ] {
        let path = f.dir.path().join(name);
        std::fs::write(&path, bytes)?;
        message.files.push(path);
    }
    let root = alice.send("@bob/cli", "Review PR", message).await?;
    ensure!(bob.fetch().await?.contains("1 unread threads"));
    ensure!(bob.fetch().await?.contains("1 mention"));
    let inbox = bob.inbox().await?;
    ensure!(inbox.len() == 1 && inbox[0].mentioned && inbox[0].title == "Review PR");
    let waited = bob.wait_text(0).await?;
    ensure!(
        waited.starts_with(&format!("{UNTRUSTED_BANNER}\n"))
            && !waited.contains("UNTRUSTED")
            && waited.contains("to: @bob/cli (you)")
    );
    let downloaded = f.store("bob").cache_dir(&bob.profile).join("blobs");
    let paths = std::fs::read_dir(&downloaded)?.collect::<std::io::Result<Vec<_>>>()?;
    let image = paths
        .into_iter()
        .map(|entry| entry.path().join("shot.png"))
        .find(|path| path.exists());
    ensure!(
        image
            .as_ref()
            .is_some_and(|path| waited.contains(&path.display().to_string()))
    );
    ensure!(
        std::fs::read(image.ok_or_else(|| anyhow::anyhow!("missing downloaded image"))?)?
            == b"image bytes"
    );
    ensure!(bob.fetch().await?.is_empty());
    let view = bob.read(root.id, ReadOptions::default()).await?;
    ensure!(
        view.text().starts_with(&format!("{UNTRUSTED_BANNER}\n"))
            && !view.text().contains("UNTRUSTED")
            && view.text().contains("alice/cli (agent)")
    );
    ensure!(std::fs::read(&view.messages[0].attachments[0])? == b"image bytes");
    let mimes: Vec<_> = view.messages[0]
        .content
        .attachments
        .iter()
        .map(|a| a.mime.as_str())
        .collect();
    ensure!(
        mimes
            == [
                "image/png",
                "text/x-python",
                "text/plain",
                "text/plain",
                "application/octet-stream"
            ]
    );
    ensure!(view.messages[0].reference().to_string() == format!("{}#1", root.id));
    ensure!(bob.fetch().await?.is_empty());
    let reply = bob.reply(root.id, options("Looks good")).await?;
    let view = alice
        .read(
            root.id,
            ReadOptions {
                all: true,
                last: None,
            },
        )
        .await?;
    ensure!(view.messages.len() == 2 && view.summary_covers_seq == Some(root.seq));
    ensure!(view.messages[1].message.id == reply.id && view.newer_messages == 0);
    ensure!(view.text().contains("summary (as of #2; up to date)"));
    let own_tail = bob
        .read(
            root.id,
            ReadOptions {
                all: false,
                last: Some(1),
            },
        )
        .await?;
    ensure!(
        own_tail.messages.len() == 1 && own_tail.messages[0].perspective == MessagePerspective::You
    );
    ensure!(
        own_tail.text().matches(UNTRUSTED_BANNER).count() == 1,
        "the foreign root title stays framed even when only an own reply is shown"
    );
    let own = format_message(&view.messages[0], &alice.names());
    ensure!(
        own.contains("(you · agent)")
            && !own.contains(UNTRUSTED_BANNER)
            && !own.contains("UNTRUSTED")
    );
    let foreign = format_message(&view.messages[1], &alice.names());
    ensure!(
        foreign.starts_with(&format!("{UNTRUSTED_BANNER}\n"))
            && !foreign.contains("UNTRUSTED")
            && foreign.contains(&reply.id.to_string())
    );
    let reference: MessageRef = format!("{}#2", root.id).parse()?;
    ensure!(alice.resolve_message(reference).await? == reply.id);
    ensure!(alice.resolve_thread(reference).await? == root.id);
    ensure!(alice.resolve_thread(MessageRef::Id(reply.id)).await? == root.id);
    let target = alice.resolve_message(reference).await?;
    alice.react(target, ReactionKind::Ack, false).await?;
    ensure!(
        alice
            .resolve_message(format!("{}#999", root.id).parse()?)
            .await
            .is_err()
    );
    let mut reads_before = 0;
    f.faults(|faults| reads_before = faults.directory_reads)?;
    let mut fresh = Client::open(f.store("alice"), alice.profile.clone(), None).await?;
    let resolved = fresh
        .resolve_thread(format!("{}#1", root.id).parse()?)
        .await?;
    fresh.read(resolved, ReadOptions::default()).await?;
    f.faults(|faults| {
        assert_eq!(
            faults.directory_reads,
            reads_before + 1,
            "opening/resolution/read share one verified snapshot"
        )
    })?;
    for suffix in ["0", "-1", "abc", "1#2"] {
        ensure!(
            format!("{}#{suffix}", root.id)
                .parse::<MessageRef>()
                .is_err()
        );
    }
    Ok(())
}
#[tokio::test]
async fn claim_exclusivity_reactions_unread_and_person_cursor() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let invite = alice.invite(false, false).await?;
    let mut carol = Client::join(f.store("carol"), &invite, "carol").await?;
    let root = alice.send("#all", "Task", options("review")).await?;
    carol.wait(0).await?;
    bob.react(root.id, ReactionKind::Claim, false).await?;
    ensure!(bob.fetch().await?.contains("1 claimed by you"));
    let events = carol.wait(0).await?;
    ensure!(events.is_empty());
    let view = carol.read(root.id, ReadOptions::default()).await?;
    ensure!(view.text().contains("claimed by bob/cli"));
    let conflict = alice
        .react(root.id, ReactionKind::Claim, false)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("claim conflict must fail"))?;
    ensure!(conflict.to_string() == "already claimed by bob/cli just now");
    ensure!(alice.wait_text(0).await? == format!("bob/cli claim {}#1 (Task)\n", root.id));
    alice.react(root.id, ReactionKind::Ack, false).await?;
    let view = alice.read(root.id, ReadOptions::default()).await?;
    ensure!(view.text().contains("claimed by bob/cli") && view.text().contains("ack by alice/cli"));
    let mut other_handle =
        Client::open(f.store("alice"), alice.profile.clone(), Some("reviewer")).await?;
    other_handle
        .react(root.id, ReactionKind::Ack, false)
        .await?;
    let reply = alice.reply(root.id, options("work ready")).await?;
    carol.react(reply.id, ReactionKind::Down, false).await?;
    let view = carol
        .read(
            root.id,
            ReadOptions {
                all: true,
                last: None,
            },
        )
        .await?;
    let rendered = view.text();
    ensure!(rendered.matches(UNTRUSTED_BANNER).count() == 1 && !rendered.contains("UNTRUSTED"));
    let (first, second) = rendered
        .split_once("── #2")
        .ok_or_else(|| anyhow::anyhow!("missing reply"))?;
    ensure!(
        first.contains("ack by alice/cli, alice/reviewer") && first.contains("claimed by bob/cli")
    );
    ensure!(
        !second.contains("ack by")
            && !second.contains("claimed by")
            && second.contains("down by carol/cli")
    );
    bob.unread(root.id).await?;
    let inbox = bob.inbox().await?;
    ensure!(
        format_inbox(&inbox, &bob.names())
            .matches(UNTRUSTED_BANNER)
            .count()
            == 1
    );
    let preview = inbox
        .iter()
        .find(|entry| entry.id == root.id)
        .ok_or_else(|| anyhow::anyhow!("missing inbox entry"))?
        .text(&bob.names());
    ensure!(
        preview.contains("latest message reactions: down by carol/cli · 4 reactions in thread")
            && !preview.contains("ack by")
            && !preview.contains("claimed by")
    );
    carol.wait(0).await?;
    bob.react(root.id, ReactionKind::Claim, true).await?;
    ensure!(alice.wait_text(0).await? == format!("bob/cli unclaim {}#1 (Task)\n", root.id));
    ensure!(carol.wait(0).await?.is_empty());
    ensure!(
        !carol
            .read(root.id, ReadOptions::default())
            .await?
            .text()
            .contains("claimed by bob/cli")
    );

    alice.react(root.id, ReactionKind::Claim, false).await?;
    bob.read(root.id, ReadOptions::default()).await?;
    ensure!(bob.counts().await?.unread_threads == 0);
    bob.unread(root.id).await?;
    ensure!(bob.counts().await?.unread_threads == 1);
    let mut second = Client::open(f.store("bob"), bob.profile.clone(), Some("other")).await?;
    second.read(root.id, ReadOptions::default()).await?;
    ensure!(bob.counts().await?.unread_threads == 0);
    carol
        .reply(root.id, options("now participating by authoring a reply"))
        .await?;
    carol.wait(0).await?;
    alice.react(reply.id, ReactionKind::Up, false).await?;
    alice.react(reply.id, ReactionKind::Down, false).await?;
    ensure!(carol.wait_text(0).await?.is_empty());
    bob.react(reply.id, ReactionKind::Ack, false).await?;
    ensure!(
        carol.wait_text(0).await?.is_empty(),
        "authoring another message in a thread does not qualify"
    );
    ensure!(
        alice
            .wait_text(0)
            .await?
            .contains(&format!("bob/cli ack {}#2 (Task)", root.id))
    );
    let carol_reply = carol
        .reply(root.id, options("carol owns this message"))
        .await?;
    bob.react(carol_reply.id, ReactionKind::Claim, false)
        .await?;
    ensure!(carol.wait_text(0).await? == format!("bob/cli claim {}#4 (Task)\n", root.id));
    bob.react(carol_reply.id, ReactionKind::Claim, true).await?;
    let notice = carol.wait_json(0).await?;
    ensure!(notice["events"][0]["type"] == "reaction" && notice["events"][0]["kind"] == "unclaim");
    ensure!(
        notice["events"][0]["trusted"] == false
            && notice["events"][0]["message_id"] == carol_reply.id.to_string()
    );
    let threads = alice.discover_threads(Some("#all")).await?;
    ensure!(threads[0].id == root.id && threads[0].message_count == 4);
    ensure!(threads[0].participants.iter().any(|p| p == "carol/cli"));
    ensure!(
        format_threads(&threads, &alice.names())
            .matches(UNTRUSTED_BANNER)
            .count()
            == 1
    );
    ensure!(alice.discover_threads(Some("@bob")).await?.is_empty());
    let channels = carol.channel_views().await?;
    ensure!(
        channels
            .iter()
            .any(|c| c.name == "#all" && c.members.len() == 3)
    );
    ensure!(!alice.who().await?.contains("#all:"));
    let later = alice
        .send("#all", "Later thread", options("later activity"))
        .await?;
    ensure!(alice.discover_threads(None).await?[0].id == later.id);
    bob.react(root.id, ReactionKind::Down, false).await?;
    let reordered = alice.discover_threads(None).await?;
    ensure!(
        reordered[0].id == root.id
            && reordered[0].last_activity_seq > reordered[1].last_activity_seq,
        "reaction activity reorders discovery even within one second"
    );
    ensure!(reordered[0].unread_count == 1 && reordered[0].unread);

    Ok(())
}
#[tokio::test]
async fn wait_backlog_wakes_on_reply_and_keeps_per_handle_cursor() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let root = alice.send("@bob", "Task", options("hello")).await?;
    ensure!(alice.wait(0).await?.is_empty());
    f.faults(|faults| faults.inflate_cursor = true)?;
    let events = bob.wait(0).await?;
    ensure!(events.iter().any(|e| matches!(e, WaitEntry::Message(_))));
    let output = bob.format_wait_entry(&events[0]).await?;
    ensure!(
        output.contains(&format!("thread {} · Task", root.id))
            && output.contains(&format!("{}#1", root.id))
            && output.contains("hello")
            && output.matches(UNTRUSTED_BANNER).count() == 1
            && !output.contains("UNTRUSTED")
            && !output.contains("summary (as of")
            && !output.contains("phi read")
    );
    ensure!(bob.wait(0).await?.is_empty());
    let unread_before = bob.counts().await?.unread_threads;
    let ack_sender = async {
        tokio::time::sleep(Duration::from_millis(40)).await;
        alice.react(root.id, ReactionKind::Ack, false).await
    };
    let (notice, sent) = tokio::join!(bob.wait_text(1), ack_sender);
    sent?;
    ensure!(
        notice?.is_empty(),
        "being addressed in a thread does not qualify for reactions to others' messages"
    );
    ensure!(
        bob.counts().await?.unread_threads == unread_before,
        "reaction-only wait does not mark the thread read"
    );
    f.faults(|faults| faults.inflate_cursor = false)?;
    bob.react(root.id, ReactionKind::Claim, false).await?;
    let own = bob.reply(root.id, options("my reply")).await?;
    let mut alice_reviewer =
        Client::open(f.store("alice"), alice.profile.clone(), Some("reviewer")).await?;
    ensure!(
        alice_reviewer
            .wait(0)
            .await?
            .iter()
            .any(|event| matches!(event,
        WaitEntry::Message(entry) if entry.latest_seq == own.seq))
    );
    ensure!(alice_reviewer.fetch().await?.contains("1 unread threads"));
    ensure!(alice.counts().await?.unread_threads == 1);
    let events = alice.wait(0).await?;
    let mut output = String::new();
    for event in &events {
        output.push_str(&alice.format_wait_entry(event).await?);
    }
    ensure!(
        output.contains(&format!("reaction context · {}#1:", root.id))
            && output.contains("claimed by bob/cli")
            && output.contains("summary (as of #2; up to date)")
            && output.contains("my reply")
            && output.contains(&format!("{}#2", root.id))
            && output.contains(&own.id.to_string())
    );
    let mut parallel = Client::open(f.store("bob"), bob.profile.clone(), None).await?;
    let second_waiter = parallel.wait(3);
    let waiter = bob.wait(3);
    let sender = async {
        tokio::time::sleep(Duration::from_millis(40)).await;
        alice.reply(root.id, options("new reply")).await
    };
    let (events, second_events, message) = tokio::join!(waiter, second_waiter, sender);
    let message = message?;
    for entries in [events?, second_events?] {
        ensure!(entries.len() == 1);
        let output = bob.format_wait_entry(&entries[0]).await?;
        ensure!(
            output.contains(&format!("{}#3", root.id))
                && output.contains(&message.id.to_string())
                && !output.contains(&own.id.to_string())
        );
    }
    ensure!(bob.wait(0).await?.is_empty());
    let mut second = Client::open(f.store("bob"), bob.profile.clone(), Some("second")).await?;
    let entries = second.wait(0).await?;
    ensure!(entries.iter().any(|event| matches!(event,
        WaitEntry::Message(entry) if entry.latest_seq == message.seq)));
    ensure!(entries.iter().all(|event| !matches!(event,
        WaitEntry::Message(entry) if entry.latest_seq == own.seq)));
    ensure!(second.counts().await?.unread_threads == 1);
    let mut reopened = Client::open(f.store("bob"), bob.profile.clone(), None).await?;
    ensure!(reopened.wait(0).await?.is_empty());
    // An own-only backlog consumes the original timeout instead of waking the session.
    bob.react(message.id, ReactionKind::Ack, false).await?;
    let started = std::time::Instant::now();
    ensure!(bob.wait(1).await?.is_empty());
    ensure!(started.elapsed() >= Duration::from_millis(900));
    let ack = alice.wait_text(0).await?;
    ensure!(ack == format!("bob/cli ack {}#3 (Task)\n", root.id));
    let next_message = bob
        .reply(root.id, options("next message carries reaction context"))
        .await?;
    bob.react(next_message.id, ReactionKind::Up, false).await?;
    let next = alice.wait_text(0).await?;
    ensure!(
        next.contains("up by bob/cli")
            && next.contains(&format!("reaction context · {}#3: ack by bob/cli", root.id))
            && next.contains("to: @bob")
    );
    ensure!(alice.wait_text(0).await?.is_empty());
    let mut reviewer = Client::open(f.store("bob"), bob.profile.clone(), Some("reviewer")).await?;
    reviewer.wait(0).await?;
    let other = alice
        .send("@bob/other", "Other handle", options("not for reviewer"))
        .await?;
    let targeted = bob
        .send(
            "@bob/reviewer",
            "For reviewer",
            options("own other session"),
        )
        .await?;
    let general = alice
        .send("#all", "General", options("for everyone"))
        .await?;
    let entries = reviewer.wait(0).await?;
    ensure!(
        matches!(&entries[0], WaitEntry::Message(entry) if entry.id == targeted.id && entry.to == "@bob/reviewer (you)")
    );
    ensure!(
        entries
            .iter()
            .any(|e| matches!(e, WaitEntry::Message(entry) if entry.id == other.id))
    );
    ensure!(
        entries
            .iter()
            .any(|e| matches!(e, WaitEntry::Message(entry) if entry.id == general.id))
    );
    ensure!(reviewer.counts().await?.unread_threads == 3);
    // Inbox remains person-wide; notification routing does not change read state.
    let inbox = reviewer.inbox().await?;
    ensure!(inbox[0].id == targeted.id && inbox[0].to == "@bob/reviewer (you)");
    bob.react(targeted.id, ReactionKind::Ack, false).await?;
    let start = std::time::Instant::now();
    ensure!(reviewer.wait(1).await?.is_empty());
    ensure!(start.elapsed() >= Duration::from_millis(900));
    let started = std::time::Instant::now();
    let unrelated = async {
        tokio::time::sleep(Duration::from_millis(40)).await;
        bob.reply(targeted.id, options("own untargeted reply"))
            .await
    };
    let (waiting, sent) = tokio::join!(reviewer.wait(1), unrelated);
    sent?;
    ensure!(waiting?.is_empty());
    ensure!(started.elapsed() >= Duration::from_millis(900));
    let external = alice
        .reply(root.id, options("reply for every bob handle"))
        .await?;
    ensure!(reviewer.wait(0).await?.iter().any(|event| matches!(event,
        WaitEntry::Message(entry) if entry.latest_seq == external.seq)));
    let direct = alice
        .send("@bob/reviewer", "Called reviewer", options("please review"))
        .await?;
    ensure!(reviewer.wait(0).await?.len() == 1);
    bob.react(direct.id, ReactionKind::Ack, false).await?;
    ensure!(reviewer.wait(0).await?.is_empty());
    alice.reply(direct.id, options("carries context")).await?;
    let entries = reviewer.wait(0).await?;
    ensure!(
        matches!(&entries[0], WaitEntry::Message(entry) if entry.reactions.iter().any(|r| r.data.kind == ReactionKind::Ack))
    );
    let batch = alice
        .send("@bob/reviewer", "Whole batch", options("batch root body"))
        .await?;
    let sibling = alice
        .send("#all", "Parallel batch", options("parallel root body"))
        .await?;
    alice.reply(batch.id, options("batch first reply")).await?;
    let last = alice.reply(batch.id, options("batch final reply")).await?;
    let sibling_last = alice
        .reply(sibling.id, options("parallel reply body"))
        .await?;
    alice
        .send("@bob/other", "Unrelated", options("not displayed"))
        .await?;
    let output = reviewer.wait_text(0).await?;
    ensure!(
        output
            .matches(&format!("thread {} · Whole batch", batch.id))
            .count()
            == 1
    );
    ensure!(
        ["batch root body", "batch first reply", "batch final reply"]
            .iter()
            .all(|body| output.contains(body))
    );
    ensure!(
        !output.contains("summary (as of #3;")
            && output.matches(UNTRUSTED_BANNER).count() == 1
            && !output.contains("UNTRUSTED")
    );
    let sibling_header = format!("thread {} · Parallel batch", sibling.id);
    ensure!(output.matches(&sibling_header).count() == 1);
    ensure!(output.find("batch final reply") < output.find(&sibling_header));
    ensure!(output.contains("parallel root body") && output.contains("parallel reply body"));
    ensure!(output.contains("not displayed") && !output.contains("phi read"));
    let cache =
        rusqlite::Connection::open(f.store("bob").cache_dir(&bob.profile).join("cache.db"))?;
    let cursor: u64 = cache.query_row(
        "SELECT seq FROM cursors WHERE thread=?",
        [batch.id.to_string()],
        |r| r.get(0),
    )?;
    ensure!(cursor == last.seq);
    let sibling_cursor: u64 = cache.query_row(
        "SELECT seq FROM cursors WHERE thread=?",
        [sibling.id.to_string()],
        |r| r.get(0),
    )?;
    ensure!(sibling_cursor == sibling_last.seq);
    let mut same_person =
        Client::open(f.store("bob"), bob.profile.clone(), Some("another")).await?;
    ensure!(
        same_person
            .inbox()
            .await?
            .iter()
            .all(|entry| entry.id != batch.id && entry.id != sibling.id)
    );
    ensure!(reviewer.wait_text(0).await?.is_empty());
    alice
        .group_create("notifications", &["@bob".into()])
        .await?;
    let grouped = alice
        .send(
            "#notifications",
            "Group task",
            options("for all bob handles"),
        )
        .await?;
    for client in [&mut reviewer, &mut second] {
        ensure!(client.wait(0).await?.iter().any(|event| matches!(event,
            WaitEntry::Message(entry) if entry.id == grouped.id)));
        ensure!(
            client
                .counts()
                .await?
                .channels
                .iter()
                .any(|channel| channel.channel_id == grouped.envelope.channel_id
                    && channel.unread_threads == 1)
        );
    }
    let read_before_wait = alice
        .send(
            "@bob",
            "Read before wait",
            options("do not replay this body"),
        )
        .await?;
    let json = reviewer
        .read(read_before_wait.id, ReadOptions::default())
        .await?
        .json();
    ensure!(json["messages"][0]["trusted"] == false && json["next_reply"]["required"] == false);
    let mut reopened = Client::open(f.store("bob"), bob.profile.clone(), Some("reviewer")).await?;
    ensure!(
        reopened.wait_text(0).await?.is_empty(),
        "read then wait must not replay the same handle's body"
    );
    let mut independent =
        Client::open(f.store("bob"), bob.profile.clone(), Some("independent")).await?;
    ensure!(
        independent
            .wait_text(0)
            .await?
            .contains("do not replay this body"),
        "different handles retain independent notification history"
    );
    let fresh = alice
        .reply(read_before_wait.id, options("fresh after read"))
        .await?;
    let delivered = reopened.wait_json(0).await?;
    ensure!(delivered["events"][0]["thread"]["messages"][0]["id"] == fresh.id.to_string());
    ensure!(delivered["events"][0]["thread"]["messages"][0]["trusted"] == false);
    ensure!(
        reopened.wait_json(0).await?["events"]
            .as_array()
            .is_some_and(|e| e.is_empty())
    );
    Ok(())
}
#[tokio::test]
async fn summaries_required_off_explicit_and_local_summarizer() -> Result<()> {
    let f = Fixture::new().await?;
    let mut alice = f.alice().await?;
    let unsummarized = alice
        .send("#all", "No summary", SendOptions::default())
        .await?;
    alice.reply(unsummarized.id, SendOptions::default()).await?;
    let preflight = alice.read(unsummarized.id, ReadOptions::default()).await?;
    ensure!(preflight.next_reply.required && preflight.next_reply.messages_since_summary == 3);
    ensure!(
        preflight
            .text()
            .contains("next reply: --summary required (3 since last")
    );
    let error = alice
        .reply(unsummarized.id, SendOptions::default())
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("third message must require a summary"))?;
    ensure!(
        error
            .to_string()
            .contains("3 messages since the last summary")
            && error
                .to_string()
                .contains("including this message; threshold 3")
    );
    alice
        .reply(unsummarized.id, options("first summary"))
        .await?;
    for _ in 0..2 {
        alice.reply(unsummarized.id, SendOptions::default()).await?;
    }
    ensure!(
        alice
            .reply(unsummarized.id, SendOptions::default())
            .await
            .is_err()
    );
    alice.set_settings("summary_every", "5").await?;
    for _ in 0..2 {
        alice.reply(unsummarized.id, SendOptions::default()).await?;
    }
    let error = alice
        .reply(unsummarized.id, SendOptions::default())
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("fifth message requires a summary"))?;
    ensure!(
        error
            .to_string()
            .contains("5 messages since the last summary")
            && error.to_string().contains("threshold 5")
    );
    ensure!(alice.set_settings("summary_every", "0").await.is_err());
    ensure!(
        alice
            .set_settings("summary_every", "4294967296")
            .await
            .is_err()
    );
    alice.set_settings("summary_every", "1").await?;
    ensure!(
        alice
            .send("#all", "Every message", SendOptions::default())
            .await
            .is_err()
    );
    let reopened = Client::open(f.store("alice"), alice.profile.clone(), None).await?;
    ensure!(reopened.settings.summary_every == 1);
    alice.profile.summarizer = Some("echo local-summary".into());
    let root = alice
        .send(
            "#all",
            "Local summary",
            SendOptions {
                body: "x".repeat(100_000),
                ..Default::default()
            },
        )
        .await?;
    ensure!(
        alice
            .read(root.id, ReadOptions::default())
            .await?
            .summary
            .as_deref()
            == Some("local-summary")
    );
    let explicit = alice
        .send("#all", "Explicit", options("explicit wins"))
        .await?;
    ensure!(
        alice
            .read(explicit.id, ReadOptions::default())
            .await?
            .summary
            .as_deref()
            == Some("Summary: explicit wins")
    );
    alice.profile.summarizer = Some("exit 9".into());
    ensure!(
        alice
            .send("#all", "Failure", SendOptions::default())
            .await
            .is_err()
    );
    alice.profile.summarizer = None;
    // Summarizers run under the host shell (cmd on Windows, sh elsewhere) and
    // their stdout is kept verbatim apart from trimming, so cmd's CRLF stays.
    #[cfg(windows)]
    let (summarizer, expected) = (
        "(echo first line& echo second line)",
        "first line\r\nsecond line",
    );
    #[cfg(not(windows))]
    let (summarizer, expected) = (
        "printf 'first line\nsecond line\n'",
        "first line\nsecond line",
    );
    alice.profile.summarizer = Some(summarizer.into());
    let multiline = alice
        .send(
            "#all",
            "Multiline",
            SendOptions {
                body: "body".into(),
                ..Default::default()
            },
        )
        .await?;
    ensure!(
        alice
            .read(multiline.id, ReadOptions::default())
            .await?
            .summary
            .as_deref()
            == Some(expected)
    );
    alice.profile.summarizer = None;
    alice.set_settings("summary_mode", "off").await?;
    alice.reply(unsummarized.id, SendOptions::default()).await?;
    alice
        .send("#all", "No summary needed", SendOptions::default())
        .await?;
    Ok(())
}
#[tokio::test]
async fn read_composes_summary_coverage_tail_and_all() -> Result<()> {
    let f = Fixture::new().await?;
    let mut alice = f.alice().await?;
    let root = alice.send("#all", "Long thread", options("root")).await?;
    for n in 0..7 {
        alice.reply(root.id, options(&format!("reply {n}"))).await?;
    }
    alice.set_settings("summary_mode", "off").await?;
    for n in 0..2 {
        alice
            .reply(
                root.id,
                SendOptions {
                    body: format!("human-like {n}"),
                    ..Default::default()
                },
            )
            .await?;
    }
    let view = alice.read(root.id, ReadOptions::default()).await?;
    ensure!(view.messages.len() == 5 && view.newer_messages == 2);
    ensure!(view.summary_number == Some(8) && view.messages[0].number == 6);
    ensure!(
        view.text()
            .contains("summary (as of #8; 2 newer messages below)")
    );
    let view = alice
        .read(
            root.id,
            ReadOptions {
                last: Some(1),
                all: false,
            },
        )
        .await?;
    ensure!(
        view.messages.len() == 2 && view.messages[0].number == 9 && view.messages[1].number == 10
    );
    let view = alice
        .read(
            root.id,
            ReadOptions {
                last: None,
                all: true,
            },
        )
        .await?;
    ensure!(view.messages.len() == 10);
    Ok(())
}
#[tokio::test]
async fn enrollment_history_revoke_device_rotates_and_invalidates_token() -> Result<()> {
    let f = Fixture::new().await?;
    let mut alice = f.alice().await?;
    let root = alice.send("#all", "Old history", options("old")).await?;
    let link = alice.invite(true, true).await?;
    let mut laptop = Client::join(f.store("laptop"), &link, "ignored-enroll-name").await?;
    ensure!(
        laptop.profile.person_id == alice.profile.person_id
            && laptop.profile.display_name == "alice"
    );
    ensure!(laptop.wait(0).await?.is_empty());
    let own_history = laptop.read(root.id, ReadOptions::default()).await?.text();
    ensure!(
        own_history.contains("your other session")
            && !own_history.contains(UNTRUSTED_BANNER)
            && !own_history.contains("UNTRUSTED")
    );
    ensure!(
        laptop
            .read(root.id, ReadOptions::default())
            .await?
            .messages
            .len()
            == 1
    );
    let all = alice
        .channels
        .iter()
        .find(|c| c.channel.kind == ChannelKind::All)
        .ok_or_else(|| anyhow::anyhow!("all missing"))?
        .channel
        .id;
    f.faults(|faults| {
        faults.omit_device = Some(laptop.profile.device_id);
        faults.hide_revocations = true;
        faults.fail_revocations = true;
    })?;
    ensure!(
        alice
            .revoke(RevocationTarget::Device {
                device_id: laptop.profile.device_id
            })
            .await
            .is_err()
    );
    let cache =
        rusqlite::Connection::open(f.store("alice").cache_dir(&alice.profile).join("cache.db"))?;
    let pinned: String =
        cache.query_row("SELECT value FROM state WHERE name='trust'", [], |r| {
            r.get(0)
        })?;
    let pinned: serde_json::Value = serde_json::from_str(&pinned)?;
    ensure!(
        pinned["bundle"]["revocations"]
            .as_array()
            .is_some_and(|r| r.len() == 1)
    );
    ensure!(
        cache.query_row("SELECT COUNT(*) FROM pending_revocations", [], |r| r
            .get::<_, u64>(0))?
            == 1
    );
    f.faults(|faults| {
        faults.fail_revocations = false;
        faults.lose_revocation_response = true;
        faults.fail_metadata = Some(all);
    })?;
    ensure!(
        Client::open(f.store("alice"), alice.profile.clone(), None)
            .await
            .is_err()
    );
    ensure!(matches!(laptop.counts().await, Err(Error::Auth)));
    f.faults(|faults| faults.lose_revocation_response = false)?;
    ensure!(
        Client::open(f.store("alice"), alice.profile.clone(), None)
            .await
            .is_err()
    );
    ensure!(
        cache.query_row("SELECT COUNT(*) FROM pending_revocations", [], |r| r
            .get::<_, u64>(0))?
            == 0
    );
    // Every channel was processed even though the all-channel metadata PATCH failed.
    alice.refresh().await?;
    ensure!(alice.channels.iter().all(|c| if c.channel.id == all {
        c.channel.current_epoch == 0
    } else {
        c.channel.current_epoch == 1
    }));
    let protected: Option<String> = cache
        .query_row(
            "SELECT value FROM state WHERE name=?",
            [format!("protected/{all}")],
            |r| r.get(0),
        )
        .optional()?;
    ensure!(protected.is_none());
    f.faults(|faults| faults.fail_metadata = None)?;
    alice = Client::open(f.store("alice"), alice.profile.clone(), None).await?;
    ensure!(alice.channels.iter().all(|c| c.channel.current_epoch == 1));
    ensure!(matches!(laptop.counts().await, Err(Error::Auth)));
    let new = alice.send("#all", "New key", options("private")).await?;
    ensure!(new.envelope.epoch == 1);
    ensure!(
        alice.read(new.id, ReadOptions::default()).await?.messages[0]
            .content
            .body
            == "private"
    );
    Ok(())
}
#[tokio::test]
async fn removal_rotates_all_dm_and_group_and_isolates_removed_person() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    alice.group_create("backend", &["@bob".into()]).await?;
    alice.send("@bob", "DM", options("before removal")).await?;
    alice
        .revoke(RevocationTarget::Person {
            person_id: bob.profile.person_id,
        })
        .await?;
    ensure!(matches!(bob.counts().await, Err(Error::Auth)));
    ensure!(
        alice
            .channels
            .iter()
            .filter(|c| c.channel.kind != ChannelKind::SelfChannel)
            .all(|c| c.channel.current_epoch == 1)
    );
    let root = alice
        .send("#all", "After removal", options("future secret"))
        .await?;
    ensure!(root.envelope.epoch == 1);
    alice.read(root.id, ReadOptions::default()).await?;
    remaining_members_rekey_private_channels_unknown_to_removal_issuer().await?;
    Ok(())
}
#[tokio::test]
async fn groups_add_remove_rotate_and_enroll_after_rotation() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let group = alice.group_create("backend", &[]).await?;
    alice
        .send(
            "#backend",
            "Before Bob joined",
            options("private old history"),
        )
        .await?;
    f.faults(|faults| faults.fail_metadata = Some(group))?;
    ensure!(alice.group_member("backend", "@bob", false).await.is_err());
    f.faults(|faults| faults.fail_metadata = None)?;
    alice = Client::open(f.store("alice"), alice.profile.clone(), None).await?;
    ensure!(
        alice
            .channels
            .iter()
            .find(|c| c.channel.id == group)
            .is_some_and(|c| c.channel.current_epoch == 0
                && !c.channel.members.contains(&bob.profile.person_id))
    );
    alice.group_member("backend", "@bob", false).await?;
    ensure!(
        alice
            .channels
            .iter()
            .find(|c| c.channel.id == group)
            .is_some_and(|c| c.channel.current_epoch == 1)
    );
    let root = alice.send("#backend", "Group", options("shared")).await?;
    ensure!(
        bob.read(root.id, ReadOptions::default()).await?.messages[0]
            .content
            .body
            == "shared"
    );
    ensure!(
        bob.inbox()
            .await?
            .iter()
            .any(|e| e.title == "[unavailable encrypted title]")
    );
    let enrollment = bob.invite(true, false).await?;
    let mut bob_laptop = Client::join(f.store("bob-laptop"), &enrollment, "bob").await?;
    ensure!(
        bob_laptop
            .read(root.id, ReadOptions::default())
            .await?
            .messages[0]
            .content
            .body
            == "shared"
    );
    alice.group_member("backend", "@bob", true).await?;
    bob.refresh().await?;
    ensure!(!bob.channels.iter().any(|c| c.meta.name == "backend"));
    let link = alice.invite(true, false).await?;
    let mut laptop = Client::join(f.store("laptop"), &link, "alice").await?;
    let root = alice
        .send("#backend", "After rotation", options("new group key"))
        .await?;
    ensure!(
        laptop.read(root.id, ReadOptions::default()).await?.messages[0]
            .content
            .body
            == "new group key"
    );
    Ok(())
}
#[tokio::test]
async fn profile_resolution_binding_ambiguity_and_space_isolation() -> Result<()> {
    let f = Fixture::new().await?;
    let mut alice = f.alice().await?;
    let repo = f.dir.path().join("repo");
    std::fs::create_dir_all(&repo)?;
    ensure!(f.store("alice").bind(&repo, None)?.space_id == alice.profile.space_id);
    let other = Client::create(f.store("alice"), &f.url, "company", "alice", None).await?;
    let store = f.store("alice");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            std::fs::metadata(store.profile_dir(&alice.profile).join("keys"))?
                .permissions()
                .mode()
                & 0o777
                == 0o600
        );
        ensure!(
            std::fs::metadata(store.profile_dir(&alice.profile))?
                .permissions()
                .mode()
                & 0o777
                == 0o700
        );
    }
    let file_keys = FileKeyStore::open(&store.profile_dir(&alice.profile).join("keys"))?;
    let prior = file_keys.get("identity")?;
    ensure!(file_keys.put("identity", b"conflicting key").is_err());
    ensure!(file_keys.get("identity")? == prior);
    ensure!(store.resolve(f.dir.path(), None).is_err());
    let error = store
        .bind(&repo, None)
        .err()
        .ok_or_else(|| anyhow::anyhow!("ambiguous init must fail"))?
        .to_string();
    for profile in [&alice.profile, &other.profile] {
        ensure!(
            error.contains(&format!("{} ({})", profile.name, profile.space_id))
                && error.contains(&format!("phi init {}", profile.space_id))
        );
    }
    let nested = repo.join("deep");
    std::fs::create_dir_all(&nested)?;
    store.bind(&repo, Some("game"))?;
    ensure!(store.resolve(&nested, None)?.space_id == alice.profile.space_id);
    ensure!(store.resolve(&nested, Some("company"))?.space_id == other.profile.space_id);
    let message = alice.send("#all", "Isolated", options("space A")).await?;
    let mut other = Client::open(store, other.profile, None).await?;
    ensure!(
        other
            .read(message.id, ReadOptions::default())
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn names_slug_collisions_self_channel_and_link_content() -> Result<()> {
    let f = Fixture::new().await?;
    let mut alice = f.alice().await?;
    let link = alice.invite(false, false).await?;
    let bob = Client::join(f.store("bob"), &link, "Alice").await?;
    ensure!(bob.profile.display_name == "alice-2");
    alice.refresh().await?;
    let root = alice
        .send(
            "@alice/second",
            "Self task",
            options("message to another session"),
        )
        .await?;
    ensure!(alice.counts().await?.unread_threads == 0);
    let mut other_session =
        Client::open(f.store("alice"), alice.profile.clone(), Some("second")).await?;
    ensure!(!other_session.fetch().await?.is_empty());
    ensure!(alice.wait(0).await?.is_empty());
    ensure!(
        other_session
            .wait(0)
            .await?
            .iter()
            .any(|e| matches!(e, WaitEntry::Message(_)))
    );
    let own_view = other_session.read(root.id, ReadOptions::default()).await?;
    ensure!(
        own_view.text().contains("your other session")
            && !own_view.text().contains(UNTRUSTED_BANNER)
            && !own_view.text().contains("UNTRUSTED")
    );
    ensure!(alice.counts().await?.unread_threads == 0);
    ensure!(
        alice.read(root.id, ReadOptions::default()).await?.messages[0]
            .message
            .envelope
            .mentions[0]
            .handle
            .as_ref()
            .is_some_and(|h| h.as_str() == "second")
    );
    let called = alice
        .send(
            "@alice/cli",
            "Explicit self-call",
            options("for this handle"),
        )
        .await?;
    ensure!(alice.counts().await?.unread_threads == 1);
    ensure!(alice.wait(0).await?.iter().any(|event| matches!(event,
        WaitEntry::Message(entry) if entry.id == called.id)));
    ensure!(other_session.wait(0).await?.is_empty());
    for body in ["phi://host/space#secret", "PHIS://host/space#secret"] {
        let linked = alice.send("#all", body, options(body)).await?;
        let reply = alice.reply(linked.id, options(body)).await?;
        let view = alice
            .read(
                linked.id,
                ReadOptions {
                    all: true,
                    last: None,
                },
            )
            .await?;
        ensure!(
            view.title == body
                && view
                    .messages
                    .iter()
                    .all(|message| message.content.body == body)
        );
        ensure!(
            view.messages
                .last()
                .is_some_and(|message| message.message.id == reply.id)
        );
        ensure!(view.summary.as_deref() == Some(format!("Summary: {body}").as_str()));
    }
    Ok(())
}
#[tokio::test]
async fn local_cache_search_and_retention_prune_on_startup() -> Result<()> {
    let f = Fixture::new().await?;
    let mut alice = f.alice().await?;
    alice.set_settings("retention_days", "2").await?;
    f.faults(|faults| {
        faults.backdate_messages = true;
        faults.unsigned_retention = Some(0);
    })?;
    let root = alice
        .send("#all", "Needle", options("searchable plaintext"))
        .await?;
    ensure!(alice.search("searchable").await?.len() == 1);
    ensure!(alice.search("absent").await?.is_empty());
    let cache = f.store("alice").cache_dir(&alice.profile).join("cache.db");
    let conn = rusqlite::Connection::open(cache)?;
    let mut reopened = Client::open(f.store("alice"), alice.profile.clone(), None).await?;
    ensure!(reopened.settings.retention_days == 2);
    ensure!(reopened.search("searchable").await?.len() == 1);
    let observed: u64 = conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM state WHERE name=?",
        [format!("activity/{}", root.id)],
        |r| r.get(0),
    )?;
    ensure!(observed > 1);
    conn.execute("UPDATE messages SET created=1", [])?;
    conn.execute(
        "UPDATE state SET value='1' WHERE name LIKE 'activity/%'",
        [],
    )?;
    // Reading identical signed evidence must not refresh retention.
    reopened.read(root.id, ReadOptions::default()).await?;
    let activity: String = conn.query_row(
        "SELECT value FROM state WHERE name=?",
        [format!("activity/{}", root.id)],
        |r| r.get(0),
    )?;
    ensure!(activity == "1");
    let mut reopened = Client::open(f.store("alice"), alice.profile.clone(), None).await?;
    ensure!(reopened.search("searchable").await?.is_empty());
    reopened.read(root.id, ReadOptions::default()).await?;
    ensure!(reopened.search("searchable").await?.len() == 1);
    f.server.sweep(u64::MAX / 2).await?;
    ensure!(reopened.search("searchable").await?.len() == 1);
    Ok(())
}
#[tokio::test]
async fn http_errors_admin_token_rate_limit_protocol_and_auth() -> Result<()> {
    let f = Fixture::configured(|c| {
        c.allow_space_creation = Creation::Token;
        c.admin_token = Some("admin-secret".into());
        c.limits.messages_per_min = 1;
        c.limits.max_blob_bytes = 32;
    })
    .await?;
    ensure!(
        Client::create(f.store("bad"), &f.url, "game", "alice", None)
            .await
            .is_err()
    );
    let mut alice = Client::create(
        f.store("alice"),
        &f.url,
        "game",
        "alice",
        Some("admin-secret".into()),
    )
    .await?;
    ensure!(alice.limits.max_attachment_bytes == 32);
    let file = f.dir.path().join("limit.txt");
    std::fs::write(&file, [b'x'; 33])?;
    let mut too_large = options("over advertised limit");
    too_large.files.push(file.clone());
    ensure!(alice.send("#all", "Too large", too_large).await.is_err());
    std::fs::write(&file, [b'x'; 32])?;
    let mut allowed = options("one");
    allowed.files.push(file);
    alice.send("#all", "First", allowed).await?;
    let error = alice
        .send("#all", "Second", options("two"))
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("expected rate limit"))?;
    ensure!(matches!(error, Error::RateLimited(_)) && error.exit_code() == 2);
    let response = reqwest::Client::new()
        .get(format!("{}/v1/spaces/{}", f.url, alice.profile.space_id))
        .header("Phi-Protocol", PROTOCOL_MAJOR + 1)
        .send()
        .await?;
    ensure!(response.status().as_u16() == 426);
    ensure!(Error::Upgrade(2).exit_code() == 4 && Error::Auth.exit_code() == 3);
    Ok(())
}
#[tokio::test]
async fn persisted_trust_rejects_omitted_certificate_and_roster_rollback() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, bob) = f.pair().await?;
    alice.group_create("backend", &["@bob".into()]).await?;
    let link = alice.invite(true, false).await?;
    let mut laptop = Client::join(f.store("laptop"), &link, "alice").await?;
    alice.group_member("backend", "@bob", true).await?;
    let connection = rusqlite::Connection::open(f.dir.path().join("server/phi.db"))?;
    let channel = alice
        .channels
        .iter()
        .find(|c| c.meta.name == "backend")
        .ok_or_else(|| anyhow::anyhow!("missing group"))?
        .channel
        .clone();
    let accounts =
        FileKeyStore::open(&f.store("laptop").profile_dir(&laptop.profile).join("keys"))?;
    let epoch_account = format!("channel/{}/1", channel.id);
    ensure!(accounts.get(&epoch_account)?.is_none());
    let mut invalid_meta = channel.clone();
    invalid_meta.meta.ciphertext = Base64Bytes::new(vec![0; channel.meta.ciphertext.len()]);
    connection.execute(
        "UPDATE channels SET json=? WHERE id=?",
        rusqlite::params![
            serde_json::to_string(&invalid_meta)?,
            channel.id.to_string()
        ],
    )?;
    ensure!(laptop.refresh().await.is_err());
    ensure!(accounts.get(&epoch_account)?.is_none());
    // A former key holder can produce a valid sealed box and metadata under old
    // bytes relabeled as an existing new epoch. Only the signed commitment detects it.
    let prior = accounts
        .get(&format!("channel/{}/0", channel.id))?
        .ok_or_else(|| anyhow::anyhow!("old key missing"))?;
    let prior: KeyBytes = serde_json::from_slice(&prior)?;
    let recipient = laptop
        .devices
        .iter()
        .find(|d| d.cert.data.device_id == laptop.profile.device_id)
        .ok_or_else(|| anyhow::anyhow!("recipient missing"))?
        .clone();
    let mut entropy =
        |bytes: &mut [u8]| getrandom::fill(bytes).map_err(|_| phi_crypto::CryptoError::Entropy);
    let context = serde_json::to_vec(&(
        "phi wrapped key v1",
        (
            laptop.profile.space_id,
            channel.id,
            1_u64,
            laptop.profile.device_id,
        ),
    ))?;
    let forged = WrappedKey {
        channel_id: channel.id,
        epoch: 1,
        device_id: laptop.profile.device_id,
        sealed: phi_crypto::seal(
            &recipient.cert.data.kex_pub,
            prior.as_bytes(),
            &context,
            &mut entropy,
        )?,
    };
    let original_wrap: String = connection.query_row(
        "SELECT json FROM wrapped_keys WHERE channel_id=? AND epoch=1 AND device_id=?",
        rusqlite::params![channel.id.to_string(), laptop.profile.device_id.to_string()],
        |r| r.get(0),
    )?;
    let meta = alice
        .channels
        .iter()
        .find(|c| c.channel.id == channel.id)
        .ok_or_else(|| anyhow::anyhow!("meta missing"))?
        .meta
        .clone();
    let old_as_new = phi_crypto::ChannelKey::from_bytes(
        laptop.profile.space_id,
        channel.id,
        1,
        *prior.as_bytes(),
    );
    let mut forged_channel = channel.clone();
    forged_channel.meta = phi_crypto::encrypt_channel_metadata(
        &old_as_new,
        &serde_json::to_vec(&meta)?,
        &mut entropy,
    )?;
    connection.execute(
        "UPDATE channels SET json=? WHERE id=?",
        rusqlite::params![
            serde_json::to_string(&forged_channel)?,
            channel.id.to_string()
        ],
    )?;
    connection.execute(
        "UPDATE wrapped_keys SET json=? WHERE channel_id=? AND epoch=1 AND device_id=?",
        rusqlite::params![
            serde_json::to_string(&forged)?,
            channel.id.to_string(),
            laptop.profile.device_id.to_string()
        ],
    )?;
    ensure!(laptop.refresh().await.is_err());
    ensure!(accounts.get(&epoch_account)?.is_none());
    let pinned = rusqlite::Connection::open(
        f.store("laptop")
            .cache_dir(&laptop.profile)
            .join("cache.db"),
    )?;
    let roster: String = pinned.query_row(
        "SELECT value FROM state WHERE name=?",
        [format!("roster/{}", channel.id)],
        |r| r.get(0),
    )?;
    ensure!(
        serde_json::from_str::<ChannelMembership>(&roster)?
            .data
            .epoch
            == 0
    );
    connection.execute(
        "UPDATE channels SET json=? WHERE id=?",
        rusqlite::params![serde_json::to_string(&channel)?, channel.id.to_string()],
    )?;
    connection.execute(
        "UPDATE wrapped_keys SET json=? WHERE channel_id=? AND epoch=1 AND device_id=?",
        rusqlite::params![
            original_wrap,
            channel.id.to_string(),
            laptop.profile.device_id.to_string()
        ],
    )?;
    laptop.refresh().await?;
    ensure!(accounts.get(&epoch_account)?.is_some());
    // Even a correctly encrypted box for an uncommitted future epoch cannot reserve an account.
    let future_context = serde_json::to_vec(&(
        "phi wrapped key v1",
        (
            laptop.profile.space_id,
            channel.id,
            99_u64,
            laptop.profile.device_id,
        ),
    ))?;
    let future = WrappedKey {
        epoch: 99,
        sealed: phi_crypto::seal(
            &recipient.cert.data.kex_pub,
            prior.as_bytes(),
            &future_context,
            &mut entropy,
        )?,
        ..forged
    };
    connection.execute(
        "INSERT INTO wrapped_keys VALUES(?,?,?,?)",
        rusqlite::params![
            channel.id.to_string(),
            99,
            laptop.profile.device_id.to_string(),
            serde_json::to_string(&future)?
        ],
    )?;
    ensure!(laptop.refresh().await.is_err());
    ensure!(
        accounts
            .get(&format!("channel/{}/99", channel.id))?
            .is_none()
    );
    connection.execute(
        "DELETE FROM wrapped_keys WHERE channel_id=? AND epoch=99",
        [channel.id.to_string()],
    )?;
    let mut rollback = channel.clone();
    rollback.membership = rollback
        .membership_history
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing history"))?
        .clone();
    rollback.membership_history.clear();
    rollback.current_epoch = 0;
    rollback.members = rollback.membership.data.members.clone();
    connection.execute(
        "UPDATE channels SET json=? WHERE id=?",
        rusqlite::params![serde_json::to_string(&rollback)?, channel.id.to_string()],
    )?;
    ensure!(alice.refresh().await.is_err());
    connection.execute(
        "UPDATE channels SET json=? WHERE id=?",
        rusqlite::params![serde_json::to_string(&channel)?, channel.id.to_string()],
    )?;
    connection.execute_batch("PRAGMA foreign_keys=OFF")?;
    connection.execute(
        "DELETE FROM devices WHERE id=?",
        [bob.profile.device_id.to_string()],
    )?;
    ensure!(alice.refresh().await.is_err());
    Ok(())
}
#[tokio::test]
async fn tampered_message_attachment_and_sequence_are_rejected() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let path: PathBuf = f.dir.path().join("file.txt");
    std::fs::write(&path, b"safe")?;
    let mut opts = options("signed body");
    opts.files.push(path);
    let root = alice.send("#all", "Signed", opts).await?;
    let blobs = std::fs::read_dir(f.dir.path().join("server/blobs"))?
        .collect::<std::io::Result<Vec<_>>>()?;
    let blob = blobs
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing uploaded blob"))?
        .path();
    let ciphertext = std::fs::read(&blob)?;
    std::fs::write(&blob, b"tampered")?;
    ensure!(bob.wait_text(0).await.is_err());
    ensure!(bob.counts().await?.unread_threads == 1);
    std::fs::write(&blob, ciphertext)?;
    let output = bob.wait_text(0).await?;
    ensure!(output.contains("signed body") && output.contains("attachments:"));
    ensure!(bob.counts().await?.unread_threads == 0);
    alice.react(root.id, ReactionKind::Up, false).await?;
    let connection = rusqlite::Connection::open(f.dir.path().join("server/phi.db"))?;
    let original = serde_json::to_string(&root)?;
    let mut tampered = root.clone();
    tampered.seq += 100;
    connection.execute(
        "UPDATE messages SET json=? WHERE id=?",
        rusqlite::params![serde_json::to_string(&tampered)?, root.id.to_string()],
    )?;
    ensure!(alice.read(root.id, ReadOptions::default()).await.is_err());
    tampered = root.clone();
    tampered.envelope.ciphertext = Base64Bytes::new(vec![0; root.envelope.ciphertext.len()]);
    connection.execute(
        "UPDATE messages SET json=? WHERE id=?",
        rusqlite::params![serde_json::to_string(&tampered)?, root.id.to_string()],
    )?;
    ensure!(alice.read(root.id, ReadOptions::default()).await.is_err());
    ensure!(bob.wait_text(0).await?.is_empty());
    connection.execute(
        "UPDATE messages SET json=? WHERE id=?",
        rusqlite::params![original, root.id.to_string()],
    )?;
    ensure!(bob.wait_text(0).await?.is_empty());
    let bad = alice
        .send("#all", "Bad event", options("host corrupts this event"))
        .await?;
    let good = alice
        .send("#all", "Good event", options("delivered after rejection"))
        .await?;
    f.faults(|faults| {
        faults.corrupt_event = Some(bad.id);
        faults.inflate_cursor = true;
    })?;
    let events = bob.wait(0).await?;
    ensure!(
        events
            .iter()
            .any(|e| matches!(e, WaitEntry::VerificationFailure { seq, .. } if *seq == bad.seq))
    );
    ensure!(
        events
            .iter()
            .any(|e| matches!(e, WaitEntry::Message(entry) if entry.latest_seq == good.seq))
    );
    let cache =
        rusqlite::Connection::open(f.store("bob").cache_dir(&bob.profile).join("cache.db"))?;
    ensure!(
        cache.query_row(
            "SELECT COUNT(*) FROM wait_outcomes WHERE error IS NOT NULL",
            [],
            |r| r.get::<_, u64>(0)
        )? == 1
    );
    f.faults(|faults| {
        faults.corrupt_event = None;
        faults.inflate_cursor = false;
    })?;
    let later = alice
        .send("#all", "Still live", options("cursor not poisoned"))
        .await?;
    let events = bob.wait(0).await?;
    ensure!(
        events
            .iter()
            .any(|e| matches!(e, WaitEntry::Message(entry) if entry.latest_seq == later.seq))
    );
    ensure!(bob.wait(0).await?.is_empty());
    let paths: Vec<_> = std::fs::read_dir(f.dir.path().join("server/blobs"))?
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!paths.is_empty());
    std::fs::write(paths[0].path(), b"tampered")?;
    ensure!(alice.read(root.id, ReadOptions::default()).await.is_err());
    f.server.sweep(u64::MAX / 2).await?;
    Ok(())
}

fn gui_device() -> DeviceOptions {
    DeviceOptions {
        kind: DeviceKind::Gui,
        name: "desktop".into(),
    }
}
#[tokio::test]
async fn gui_file_storage_and_self_declared_device_kind() -> Result<()> {
    let f = Fixture::new().await?;
    let mut origin = Client::create_for_device(
        f.store("origin"),
        &f.url,
        "gui-space",
        "alice",
        None,
        gui_device(),
    )
    .await?;
    let first = origin.invite(true, false).await?;
    let competing = origin.invite(true, false).await?;
    let mut gui = Client::join_for_device(f.store("gui"), &first, "alice", gui_device()).await?;
    // A profile left by the external-key prototype must not block re-enrollment.
    let legacy_store = f.store("competing-gui");
    legacy_store.save_profile(&gui.profile)?;
    ensure!(legacy_store.profiles()?.is_empty());
    let competing_gui =
        Client::join_for_device(legacy_store.clone(), &competing, "alice", gui_device()).await?;
    ensure!(legacy_store.profiles()?.len() == 1);
    ensure!(competing_gui.profile.kind == DeviceKind::Gui);
    let keys_path = f.store("gui").profile_dir(&gui.profile).join("keys");
    ensure!(keys_path.is_file());
    ensure!(
        f.store("origin")
            .profile_dir(&origin.profile)
            .join("keys")
            .is_file()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(std::fs::metadata(&keys_path)?.permissions().mode() & 0o777 == 0o600);
    }
    let link = gui.invite(true, false).await?;
    let mut cli = Client::join(f.store("cli"), &link, "alice").await?;
    let root = gui
        .send(
            "#all",
            "Human message",
            SendOptions {
                body: "from desktop".into(),
                ..Default::default()
            },
        )
        .await?;
    ensure!(
        cli.read(root.id, ReadOptions::default())
            .await?
            .text()
            .contains("human · sent from GUI")
    );
    ensure!(cli.inbox().await?.is_empty());
    let threads = cli.threads().await?;
    ensure!(
        threads.len() == 1
            && !threads[0].unread
            && !threads[0].own_agent_activity
            && !format_threads(&threads, &cli.names()).contains(UNTRUSTED_BANNER)
    );
    cli.reply(root.id, options("Agent follow-up")).await?;
    ensure!(gui.threads().await?[0].own_agent_activity);
    gui.set_display_name("Alice Desktop").await?;
    cli.refresh().await?;
    ensure!(cli.person_name(gui.profile.person_id) == "alice-desktop");
    let mention = cli
        .send(
            "@alice-desktop/reviewer",
            "Agent mention",
            options("For your reviewer"),
        )
        .await?;
    ensure!(
        gui.inbox()
            .await?
            .iter()
            .any(|entry| entry.id == mention.id && entry.mentioned)
    );
    let cli_gui_enroll = cli.invite(true, false).await?;
    let cli_enrolled_gui = Client::join_for_device(
        f.store("cli-enrolled-gui"),
        &cli_gui_enroll,
        "alice",
        gui_device(),
    )
    .await?;
    ensure!(cli_enrolled_gui.profile.kind == DeviceKind::Gui);
    let gui_code = gui.invite(true, true).await?;
    let recovered_cli = Client::join(f.store("recovered-cli"), &gui_code, "alice").await?;
    ensure!(recovered_cli.profile.kind == DeviceKind::Cli);
    let gui_code = cli.invite(true, false).await?;
    let gui2 = Client::join_for_device(f.store("gui2"), &gui_code, "alice", gui_device()).await?;
    ensure!(
        gui2.profile.kind == DeviceKind::Gui && gui2.profile.person_id == gui.profile.person_id
    );
    let mut reopened = Client::open(f.store("gui"), gui.profile.clone(), None).await?;
    ensure!(
        reopened
            .read(root.id, ReadOptions::default())
            .await?
            .text()
            .contains("from desktop")
    );
    // The shared core can be moved into a GUI async task without a local executor.
    tokio::spawn(async move {
        let mut client = reopened;
        client.counts().await
    })
    .await??;
    Ok(())
}

async fn remaining_members_rekey_private_channels_unknown_to_removal_issuer() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let invite = alice.invite(false, false).await?;
    let mut charlie = Client::join(f.store("charlie"), &invite, "charlie").await?;
    let private = bob.group_create("private", &["@charlie".into()]).await?;
    let old = bob
        .send("#private", "Before removal", options("old group secret"))
        .await?;
    charlie.read(old.id, ReadOptions::default()).await?;
    alice.refresh().await?;
    ensure!(!alice.channels.iter().any(|c| c.channel.id == private));
    alice
        .revoke(RevocationTarget::Person {
            person_id: charlie.profile.person_id,
        })
        .await?;
    let new = bob
        .send("#private", "After removal", options("new group secret"))
        .await?;
    ensure!(new.envelope.epoch == 1);
    ensure!(
        bob.channels
            .iter()
            .find(|c| c.channel.id == private)
            .is_some_and(|c| c.channel.members == vec![bob.profile.person_id])
    );
    let next = bob.reply(new.id, options("still safe")).await?;
    ensure!(next.envelope.epoch == 1);
    ensure!(matches!(charlie.counts().await, Err(Error::Auth)));
    let conn = rusqlite::Connection::open(f.dir.path().join("server/phi.db"))?;
    let leaked: u64 = conn.query_row(
        "SELECT COUNT(*) FROM wrapped_keys WHERE channel_id=? AND epoch=1 AND device_id=?",
        rusqlite::params![private.to_string(), charlie.profile.device_id.to_string()],
        |r| r.get(0),
    )?;
    ensure!(leaked == 0);
    Ok(())
}

#[tokio::test]
async fn wait_survives_transient_gateway_errors() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    alice
        .send("@bob/cli", "Ping", options("Proxy restarted mid-wait."))
        .await?;
    f.faults(|f| f.drop_event_polls = 2)?;
    let waited = bob.wait_text(10).await?;
    ensure!(waited.contains("Proxy restarted mid-wait."));
    f.faults(|f| f.drop_event_polls = 4)?;
    let error = bob.wait_text(10).await.err().map(|e| e.to_string());
    ensure!(error.as_deref().is_some_and(|e| e.contains("HTTP 502")));
    Ok(())
}

#[tokio::test]
async fn revoking_the_space_root_is_refused() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let link = alice.invite(false, false).await?;
    let mut carol = Client::join(f.store("carol"), &link, "carol").await?;
    for target in [
        RevocationTarget::Person {
            person_id: alice.profile.person_id,
        },
        RevocationTarget::Device {
            device_id: alice.profile.device_id,
        },
    ] {
        let error = bob.revoke(target).await.err().map(|e| e.to_string());
        ensure!(
            error.as_deref().is_some_and(|e| e.contains("root")),
            "root revocation accepted: {error:?}"
        );
    }
    carol.refresh().await?;
    bob.fetch().await?;
    alice
        .send("#all", "Still here", options("root keeps working"))
        .await?;
    ensure!(carol.wait_text(0).await?.contains("root keeps working"));
    Ok(())
}

#[tokio::test]
async fn revoked_member_history_stays_verifiable() -> Result<()> {
    let f = Fixture::new().await?;
    let (mut alice, mut bob) = f.pair().await?;
    let link = alice.invite(false, false).await?;
    let mut carol = Client::join(f.store("carol"), &link, "carol").await?;
    bob.set_settings("summary_every", "5").await?;
    bob.group_create("backend", &["@carol".into()]).await?;
    let root = bob
        .send("#all", "Hello", options("signed before revocation"))
        .await?;
    bob.send("#backend", "Group", options("group history"))
        .await?;
    carol.wait_text(0).await?;
    alice
        .revoke(RevocationTarget::Person {
            person_id: bob.profile.person_id,
        })
        .await?;
    carol.refresh().await?;
    ensure!(carol.settings.summary_every == 5);
    let view = carol.read(root.id, ReadOptions::default()).await?;
    ensure!(view.text().contains("signed before revocation"));
    let enrollment = carol.invite(true, false).await?;
    let mut laptop = Client::join(f.store("carol-laptop"), &enrollment, "carol").await?;
    ensure!(laptop.settings.summary_every == 5);
    let sent = laptop
        .send("#backend", "After", options("group still usable"))
        .await?;
    let view = carol.read(sent.id, ReadOptions::default()).await?;
    ensure!(view.text().contains("group still usable"));
    ensure!(alice.counts().await.is_ok());
    Ok(())
}
