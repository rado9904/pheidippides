use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use phi_crypto::*;
use phi_proto::*;
use phi_server::{
    Server,
    config::{Config, Creation},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

type TestResult<T = ()> = anyhow::Result<T>;
static NEXT: AtomicU64 = AtomicU64::new(1);
fn bytes() -> [u8; 16] {
    let mut b = [0; 16];
    b[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    b
}
fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn keys() -> DeviceKeys {
    let b = bytes();
    let mut seed = [0; 32];
    seed[..16].copy_from_slice(&b);
    seed[16..].copy_from_slice(&b);
    DeviceKeys::from_secrets(seed, [7; 32])
}
fn cipher(n: usize) -> Ciphertext {
    Ciphertext {
        nonce: Nonce::from_bytes([2; 24]),
        ciphertext: Base64Bytes::new(vec![8; n]),
    }
}
fn wrapped(cid: ChannelId, did: DeviceId, epoch: u64) -> WrappedKey {
    WrappedKey {
        channel_id: cid,
        device_id: did,
        epoch,
        sealed: SealedBox {
            ephemeral_pub: PublicKey::from_bytes([1; 32]),
            nonce: Nonce::from_bytes([2; 24]),
            ciphertext: Base64Bytes::new(vec![3; 48]),
        },
    }
}
fn roster(
    cert: &DeviceCertificate,
    key: &DeviceKeys,
    channel_id: ChannelId,
    epoch: Epoch,
    kind: ChannelKind,
    members: Vec<PersonId>,
) -> Result<ChannelMembership, CryptoError> {
    sign_membership(
        ChannelMembershipData {
            key_commitment: PublicKey::from_bytes([42; 32]),
            previous: None,
            space_id: cert.data.space_id,
            channel_id,
            epoch,
            kind,
            members,
            issuer_device: cert.data.device_id,
        },
        key,
    )
}
fn next_roster(
    cert: &DeviceCertificate,
    key: &DeviceKeys,
    prior: &ChannelMembership,
    epoch: Epoch,
    members: Vec<PersonId>,
) -> Result<ChannelMembership, CryptoError> {
    sign_membership(
        ChannelMembershipData {
            key_commitment: PublicKey::from_bytes([42; 32]),
            previous: Some(prior.signature.clone()),
            epoch,
            members,
            issuer_device: cert.data.device_id,
            ..prior.data.clone()
        },
        key,
    )
}
fn token(t: &Base64<32>) -> TestResult<String> {
    Ok(serde_json::to_value(t)?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("token"))?
        .into())
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: impl Serialize,
) -> TestResult<(StatusCode, Value, HeaderMap)> {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("Phi-Protocol", PROTOCOL_MAJOR)
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(serde_json::to_vec(&body)?))?)
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let data = to_bytes(response.into_body(), 100 * 1024 * 1024).await?;
    Ok((status, serde_json::from_slice(&data)?, headers))
}
async fn ok<T: DeserializeOwned>(
    app: &Router,
    method: &str,
    path: &str,
    t: Option<&str>,
    body: impl Serialize,
) -> TestResult<T> {
    let (status, data, _) = request(app, method, path, t, body).await?;
    assert_eq!(status, StatusCode::OK, "{data}");
    Ok(serde_json::from_value(data)?)
}
struct Actor {
    key: DeviceKeys,
    cert: DeviceCertificate,
    token: String,
}
struct Fixture {
    dir: tempfile::TempDir,
    config: Config,
    server: Server,
    app: Router,
    root: Actor,
    sid: SpaceId,
    all: ChannelId,
    own: ChannelId,
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        Self::with_config(|_| {}).await
    }
    async fn with_config(change: impl FnOnce(&mut Config)) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = Config {
            data_dir: dir.path().into(),
            allow_space_creation: Creation::Anyone,
            ..Config::default()
        };
        change(&mut config);
        let server = Server::open(config.clone())?;
        let app = server.router();
        let key = keys();
        let sid = space_id(&key.sign_public());
        let did = DeviceId::from_bytes(bytes());
        let pid = PersonId::from_bytes(bytes());
        let cert = certify_device(
            DeviceCertificateData {
                space_id: sid,
                person_id: pid,
                device_id: did,
                kind: DeviceKind::Cli,
                sign_pub: key.sign_public(),
                kex_pub: key.kex_public(),
                created_at: timestamp() - 1000,
                issuer: CertificateIssuer::Device { device_id: did },
            },
            &key,
        )?;
        let all = ChannelId::from_bytes(bytes());
        let own = ChannelId::from_bytes(bytes());
        let channel = |id, kind| -> TestResult<CreateChannelRequest> {
            Ok(CreateChannelRequest {
                membership: roster(&cert, &key, id, 0, kind, vec![pid])?,
                id,
                space_id: sid,
                kind,
                meta: cipher(16),
                members: vec![pid],
                wrapped_keys: vec![wrapped(id, did, 0)],
            })
        };
        let response: CreateSpaceResponse = ok(
            &app,
            "POST",
            "/v1/spaces",
            config.admin_token.as_deref(),
            CreateSpaceRequest {
                root_cert: cert.clone(),
                all_channel: channel(all, ChannelKind::All)?,
                self_channel: channel(own, ChannelKind::SelfChannel)?,
            },
        )
        .await?;
        Ok(Self {
            dir,
            config,
            server,
            app,
            root: Actor {
                key,
                cert,
                token: token(&response.device_token)?,
            },
            sid,
            all,
            own,
        })
    }
    fn space(&self, suffix: &str) -> String {
        format!("/v1/spaces/{}{suffix}", self.sid)
    }
    async fn grant(
        &self,
        issuer: &Actor,
        kind: GrantKind,
        expires: Option<u64>,
    ) -> TestResult<(Grant, GrantKeys)> {
        let grant = GrantSecret::from_bytes({
            let mut s = [9; 32];
            s[..16].copy_from_slice(&bytes());
            s
        })
        .derive()?;
        let person = if kind == GrantKind::Enroll {
            issuer.cert.data.person_id
        } else {
            PersonId::from_bytes(bytes())
        };
        let record = sign_grant(
            GrantRecordData {
                space_id: self.sid,
                grant_id: grant.id(),
                grant_pub: grant.public(),
                kind,

                person_id: person,
                created_at: (timestamp() - 10).max(issuer.cert.data.created_at),
                expires_at: expires,
                issuer_device: issuer.cert.data.device_id,
            },
            &issuer.key,
        )?;
        let channels: ListChannelsResponse = ok(
            &self.app,
            "GET",
            &self.space("/channels"),
            Some(&issuer.token),
            json!(null),
        )
        .await?;
        let sealed_keys = channels
            .channels
            .into_iter()
            .filter(|c| kind == GrantKind::Enroll || c.kind == ChannelKind::All)
            .map(|c| GrantSealedKey {
                channel_id: c.id,
                epoch: c.current_epoch,
                sealed: cipher(48),
            })
            .collect();
        let result = ok(
            &self.app,
            "POST",
            &self.space("/grants"),
            Some(&issuer.token),
            CreateGrantRequest {
                record,
                sealed_keys,
            },
        )
        .await?;
        Ok((result, grant))
    }
    fn redeem_request(
        &self,
        g: &Grant,
        k: &GrantKeys,
    ) -> TestResult<(DeviceKeys, RedeemGrantRequest)> {
        let key = keys();
        let cert = certify_with_grant(
            DeviceCertificateData {
                space_id: self.sid,
                person_id: g.record.data.person_id,
                device_id: DeviceId::from_bytes(bytes()),
                kind: DeviceKind::Cli,
                sign_pub: key.sign_public(),
                kex_pub: key.kex_public(),
                created_at: timestamp(),
                issuer: CertificateIssuer::Grant { grant_id: k.id() },
            },
            k,
        )?;
        Ok((key, RedeemGrantRequest { certificate: cert }))
    }
    async fn join(&self, issuer: &Actor, kind: GrantKind) -> TestResult<Actor> {
        let (grant, k) = self.grant(issuer, kind, Some(timestamp() + 10000)).await?;
        let (key, r) = self.redeem_request(&grant, &k)?;
        let cert = r.certificate.clone();
        let result: RedeemGrantResponse = ok(
            &self.app,
            "POST",
            &format!("/v1/grants/{}/redeem", k.id()),
            None,
            r,
        )
        .await?;
        Ok(Actor {
            key,
            cert,
            token: token(&result.device_token)?,
        })
    }
    fn message(
        &self,
        a: &Actor,
        cid: ChannelId,
        thread: Option<MessageId>,
        mentions: Vec<Mention>,
    ) -> TestResult<SendMessageRequest> {
        let id = MessageId::from_bytes(bytes());
        let envelope = MessageEnvelope {
            id,
            summary_covers_seq: Some(0),
            space_id: self.sid,
            channel_id: cid,
            thread_id: thread,
            epoch: 0,
            handle: "main".parse()?,
            mentions,
            nonce: Nonce::from_bytes([1; 24]),
            ciphertext: Base64Bytes::new(vec![2; 16]),
        };
        let signature = a.key.sign(&message_signing_bytes(&envelope)?);
        Ok(SendMessageRequest {
            id,
            envelope,
            signature,
            has_summary: true,
            blob_ids: vec![],
        })
    }
    async fn send(
        &self,
        a: &Actor,
        cid: ChannelId,
        thread: Option<MessageId>,
    ) -> TestResult<Message> {
        ok(
            &self.app,
            "POST",
            &format!("/v1/channels/{cid}/messages"),
            Some(&a.token),
            self.message(a, cid, thread, vec![])?,
        )
        .await
    }
    fn reaction(
        &self,
        a: &Actor,
        mid: MessageId,
        kind: ReactionKind,
        handle: &str,
        remove: bool,
    ) -> TestResult<ReactionRequest> {
        Ok(ReactionRequest {
            reaction: sign_reaction(
                ReactionData {
                    space_id: self.sid,
                    message_id: mid,
                    person_id: a.cert.data.person_id,
                    device_id: a.cert.data.device_id,
                    handle: handle.parse()?,
                    kind,
                    created_at: timestamp(),
                    remove,
                },
                &a.key,
            )?,
        })
    }
}

#[tokio::test]
async fn bootstrap_persists_only_hashed_tokens_and_reopens() -> TestResult {
    let f = Fixture::new().await?;
    let s: GetSpaceResponse = ok(
        &f.app,
        "GET",
        &f.space(""),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(s.settings, SpaceSettings::default());
    let conn = rusqlite::Connection::open(f.dir.path().join("phi.db"))?;
    let hash: String = conn.query_row("SELECT token_hash FROM devices", [], |r| r.get(0))?;
    assert_ne!(hash, f.root.token);
    assert_eq!(hash.len(), 64);
    let reopened = Server::open(f.config.clone())?;
    let channels: ListChannelsResponse = ok(
        &reopened.router(),
        "GET",
        &f.space("/channels"),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(channels.channels.len(), 2);
    Ok(())
}
#[tokio::test]
async fn admin_creation_auth_and_major_version_are_enforced() -> TestResult {
    assert!(matches!(
        Config::default().allow_space_creation,
        Creation::Token
    ));
    let f = Fixture::with_config(|c| {
        c.allow_space_creation = Creation::Token;
        c.admin_token = Some("admin-secret".into())
    })
    .await?;
    for method in ["GET", "HEAD"] {
        for major in [None, Some("99"), Some("invalid")] {
            let mut req = Request::builder().method(method).uri("/healthz");
            if let Some(major) = major {
                req = req.header(PROTOCOL_HEADER, major);
            }
            let response = f.app.clone().oneshot(req.body(Body::empty())?).await?;
            assert_eq!(response.status(), 200);
            let body = to_bytes(response.into_body(), 1000).await?;
            if method == "HEAD" {
                assert!(body.is_empty());
            } else {
                assert_eq!(
                    serde_json::from_slice::<Value>(&body)?,
                    json!({"status": "ok", "protocol_major": PROTOCOL_MAJOR})
                );
            }
        }
    }
    for (method, path) in [("POST", "/healthz"), ("GET", "/healthz/"), ("GET", "/")] {
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), 426);
    }
    let (s, _, _) = request(&f.app, "GET", &f.space(""), None, json!(null)).await?;
    assert_eq!(s, 401);
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(f.space(""))
                .header("Phi-Protocol", "99")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), 426);
    let err: ErrorBody = serde_json::from_slice(&to_bytes(response.into_body(), 1000).await?)?;
    assert_eq!(
        err,
        ErrorBody::Upgrade {
            required_major: PROTOCOL_MAJOR
        }
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/grants/nope")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), 426);
    let (s, _, _) = request(
        &f.app,
        "POST",
        "/v1/spaces",
        None,
        json!({"root_cert":f.root.cert,"all_channel":{"bad":0}}),
    )
    .await?;
    assert_eq!(s, 403);
    let conn = rusqlite::Connection::open(f.dir.path().join("phi.db"))?;
    let channels: Vec<String> = {
        let mut q = conn.prepare("SELECT json FROM channels ORDER BY kind")?;
        q.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    let all: Channel = serde_json::from_str(&channels[0])?;
    let own: Channel = serde_json::from_str(&channels[1])?;
    let req = CreateSpaceRequest {
        root_cert: f.root.cert.clone(),
        all_channel: CreateChannelRequest {
            membership: all.membership,
            id: all.id,
            space_id: f.sid,
            kind: all.kind,
            meta: all.meta,
            members: all.members,
            wrapped_keys: vec![wrapped(all.id, f.root.cert.data.device_id, 0)],
        },
        self_channel: CreateChannelRequest {
            membership: own.membership,
            id: own.id,
            space_id: f.sid,
            kind: own.kind,
            meta: own.meta,
            members: own.members,
            wrapped_keys: vec![wrapped(own.id, f.root.cert.data.device_id, 0)],
        },
    };
    assert_eq!(
        request(&f.app, "POST", "/v1/spaces", Some("wrong"), req)
            .await?
            .0,
        403
    );
    Ok(())
}
#[tokio::test]
async fn validation_rejects_nested_fields_formats_and_bounds() -> TestResult {
    let f = Fixture::new().await?;
    let path = format!("/v1/channels/{}/messages", f.all);
    let mut value = serde_json::to_value(f.message(&f.root, f.all, None, vec![])?)?;
    value["envelope"]["unknown"] = json!(1);
    let (s, e, _) = request(&f.app, "POST", &path, Some(&f.root.token), value).await?;
    assert_eq!(s, 400);
    assert!(e.to_string().contains("unknown"));
    for suffix in ["?limit=0", "?limit=1001", "?surprise=1"] {
        assert_eq!(
            request(
                &f.app,
                "GET",
                &format!("{path}{suffix}"),
                Some(&f.root.token),
                json!(null)
            )
            .await?
            .0,
            400
        );
    }
    let mut r = f.message(&f.root, f.all, None, vec![])?;
    r.envelope.ciphertext = Base64Bytes::new(vec![0; MAX_CIPHERTEXT_BYTES + 1]);
    assert_eq!(
        request(&f.app, "POST", &path, Some(&f.root.token), r)
            .await?
            .0,
        400
    );
    assert_eq!(
        request(
            &f.app,
            "GET",
            "/v1/channels/../messages",
            Some(&f.root.token),
            json!(null)
        )
        .await?
        .0,
        400
    );
    assert_eq!(
        request(
            &f.app,
            "GET",
            &f.space("/events?after=0&timeout=901"),
            Some(&f.root.token),
            json!(null)
        )
        .await?
        .0,
        400
    );
    Ok(())
}
#[tokio::test]
async fn invite_and_enrollment_preserve_signed_directory_and_membership() -> TestResult {
    let f = Fixture::new().await?;
    let person = f.join(&f.root, GrantKind::Invite).await?;
    let other = f.join(&person, GrantKind::Enroll).await?;
    assert_eq!(person.cert.data.person_id, other.cert.data.person_id);
    let directory: ListDevicesResponse = ok(
        &f.app,
        "GET",
        &f.space("/devices"),
        Some(&person.token),
        json!(null),
    )
    .await?;
    let trusted = verify_trust_bundle(f.sid, &directory.directory, timestamp(), None)?;
    assert_eq!(trusted.active_devices().count(), 3);
    assert_eq!(directory.persons.len(), 2);
    let list: ListChannelsResponse = ok(
        &f.app,
        "GET",
        &f.space("/channels"),
        Some(&person.token),
        json!(null),
    )
    .await?;
    assert_eq!(list.channels.len(), 1);
    assert_eq!(list.channels[0].id, f.all);
    let r = PutKeysRequest {
        epoch: 0,
        wrapped_keys: vec![wrapped(f.all, person.cert.data.device_id, 0)],
    };
    let _: GetKeysResponse = ok(
        &f.app,
        "PUT",
        &format!("/v1/channels/{}/keys", f.all),
        Some(&person.token),
        r,
    )
    .await?;
    let keys: GetKeysResponse = ok(
        &f.app,
        "GET",
        &format!("/v1/channels/{}/keys/mine", f.all),
        Some(&person.token),
        json!(null),
    )
    .await?;
    assert_eq!(keys.wrapped_keys.len(), 1);
    Ok(())
}
#[tokio::test]
async fn redeem_is_atomic_single_use_and_rejects_forged_certificates() -> TestResult {
    let f = Fixture::new().await?;
    let (grant, k) = f
        .grant(&f.root, GrantKind::Invite, Some(timestamp() + 100))
        .await?;
    let (_, r) = f.redeem_request(&grant, &k)?;
    let mut forged = r.clone();
    forged.certificate.signature = Signature::from_bytes([0; 64]);
    let path = format!("/v1/grants/{}/redeem", k.id());
    assert_eq!(request(&f.app, "POST", &path, None, forged).await?.0, 400);
    let mut declared_gui = r.clone();
    declared_gui.certificate.data.kind = DeviceKind::Gui;
    declared_gui.certificate = certify_with_grant(declared_gui.certificate.data, &k)?;

    let (a, b) = tokio::join!(
        request(&f.app, "POST", &path, None, &declared_gui),
        request(&f.app, "POST", &path, None, &declared_gui)
    );
    let mut status = [a?.0, b?.0];
    status.sort();
    assert_eq!(status, [StatusCode::OK, StatusCode::CONFLICT]);
    let g: Grant = ok(
        &f.app,
        "GET",
        &format!("/v1/grants/{}", k.id()),
        None,
        json!(null),
    )
    .await?;
    assert!(g.used_at.is_some());
    Ok(())
}
#[tokio::test]
async fn expired_grants_and_revoked_issuers_cannot_redeem() -> TestResult {
    let f = Fixture::new().await?;
    // Timestamps are whole seconds and a grant is dead once `now >= expires_at`,
    // so a two-second expiry leaves at least a full second for creation; then
    // wait for the wall clock to actually reach the expiry instant.
    let expires = timestamp() + 2;
    let (g, k) = f.grant(&f.root, GrantKind::Invite, Some(expires)).await?;
    let (_, r) = f.redeem_request(&g, &k)?;
    let expiry = UNIX_EPOCH + Duration::from_secs(expires);
    if let Ok(remaining) = expiry.duration_since(SystemTime::now()) {
        tokio::time::sleep(remaining).await;
    }
    assert_eq!(
        request(
            &f.app,
            "POST",
            &format!("/v1/grants/{}/redeem", k.id()),
            None,
            r
        )
        .await?
        .0,
        403
    );
    let child = f.join(&f.root, GrantKind::Enroll).await?;
    let (g, k) = f
        .grant(&child, GrantKind::Invite, Some(timestamp() + 100))
        .await?;
    let (_, r) = f.redeem_request(&g, &k)?;
    let rev = sign_revocation(
        RevocationData {
            space_id: f.sid,
            target: RevocationTarget::Device {
                device_id: child.cert.data.device_id,
            },
            issuer_device: f.root.cert.data.device_id,
            created_at: timestamp(),
        },
        &f.root.key,
    )?;
    let _: Revocation = ok(
        &f.app,
        "POST",
        &f.space("/revocations"),
        Some(&f.root.token),
        CreateRevocationRequest { revocation: rev },
    )
    .await?;
    assert_eq!(
        request(
            &f.app,
            "POST",
            &format!("/v1/grants/{}/redeem", k.id()),
            None,
            r
        )
        .await?
        .0,
        404
    );
    Ok(())
}
#[tokio::test]
async fn person_revocation_rejects_all_tokens_and_forgery() -> TestResult {
    let f = Fixture::new().await?;
    let person = f.join(&f.root, GrantKind::Invite).await?;
    let other = f.join(&person, GrantKind::Enroll).await?;
    let mut rev = sign_revocation(
        RevocationData {
            space_id: f.sid,
            target: RevocationTarget::Person {
                person_id: person.cert.data.person_id,
            },
            issuer_device: f.root.cert.data.device_id,
            created_at: person.cert.data.created_at,
        },
        &f.root.key,
    )?;
    rev.signature = Signature::from_bytes([0; 64]);
    assert_eq!(
        request(
            &f.app,
            "POST",
            &f.space("/revocations"),
            Some(&f.root.token),
            CreateRevocationRequest {
                revocation: rev.clone()
            }
        )
        .await?
        .0,
        400
    );
    rev.signature = f.root.key.sign(&revocation_signing_bytes(&rev.data)?);
    let _: Revocation = ok(
        &f.app,
        "POST",
        &f.space("/revocations"),
        Some(&f.root.token),
        CreateRevocationRequest { revocation: rev },
    )
    .await?;
    for actor in [&person, &other] {
        assert_eq!(
            request(&f.app, "GET", &f.space(""), Some(&actor.token), json!(null))
                .await?
                .0,
            401
        );
    }
    Ok(())
}
#[tokio::test]
async fn channels_enforce_membership_and_complete_rotation() -> TestResult {
    let f = Fixture::new().await?;
    let person = f.join(&f.root, GrantKind::Invite).await?;
    let outsider = f.join(&f.root, GrantKind::Invite).await?;
    let cid = ChannelId::from_bytes(bytes());
    let members = vec![f.root.cert.data.person_id, person.cert.data.person_id];
    let c: Channel = ok(
        &f.app,
        "POST",
        &f.space("/channels"),
        Some(&f.root.token),
        CreateChannelRequest {
            membership: roster(
                &f.root.cert,
                &f.root.key,
                cid,
                0,
                ChannelKind::Group,
                members.clone(),
            )?,
            id: cid,
            space_id: f.sid,
            kind: ChannelKind::Group,
            meta: cipher(16),
            members: members.clone(),
            wrapped_keys: vec![
                wrapped(cid, f.root.cert.data.device_id, 0),
                wrapped(cid, person.cert.data.device_id, 0),
            ],
        },
    )
    .await?;
    assert_eq!(c.current_epoch, 0);
    let directory: ListDevicesResponse = ok(
        &f.app,
        "GET",
        &f.space("/devices"),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    let trusted = verify_trust_bundle(f.sid, &directory.directory, timestamp(), None)?;
    trusted.verify_channel(&c, None)?;
    let mut injected = serde_json::to_value(&c)?;
    injected["members"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("members"))?
        .push(serde_json::to_value(outsider.cert.data.person_id)?);
    assert!(
        trusted
            .verify_channel(&serde_json::from_value(injected)?, Some(&c.membership))
            .is_err()
    );

    assert_eq!(
        request(
            &f.app,
            "GET",
            &format!("/v1/channels/{cid}/messages"),
            Some(&outsider.token),
            json!(null)
        )
        .await?
        .0,
        404
    );
    assert_eq!(
        request(
            &f.app,
            "PUT",
            &format!("/v1/channels/{cid}/keys"),
            Some(&f.root.token),
            PutKeysRequest {
                epoch: 1,
                wrapped_keys: vec![wrapped(cid, f.root.cert.data.device_id, 1)]
            }
        )
        .await?
        .0,
        403
    );
    let partial = UpdateChannelRequest {
        membership: next_roster(&f.root.cert, &f.root.key, &c.membership, 1, members.clone())?,
        epoch: 1,
        meta: cipher(16),
        members: members.clone(),
        wrapped_keys: vec![wrapped(cid, f.root.cert.data.device_id, 1)],
    };
    assert_eq!(
        request(
            &f.app,
            "PATCH",
            &format!("/v1/channels/{cid}"),
            Some(&f.root.token),
            &partial
        )
        .await?
        .0,
        400
    );
    let replacement = UpdateChannelRequest {
        wrapped_keys: vec![],
        membership: next_roster(
            &f.root.cert,
            &f.root.key,
            &c.membership,
            0,
            vec![f.root.cert.data.person_id, outsider.cert.data.person_id],
        )?,
        epoch: 0,
        meta: cipher(16),
        members: vec![f.root.cert.data.person_id, outsider.cert.data.person_id],
    };
    assert_eq!(
        request(
            &f.app,
            "PATCH",
            &format!("/v1/channels/{cid}"),
            Some(&f.root.token),
            replacement
        )
        .await?
        .0,
        409
    );
    let mut shrink = UpdateChannelRequest {
        wrapped_keys: vec![],
        membership: next_roster(
            &f.root.cert,
            &f.root.key,
            &c.membership,
            0,
            vec![f.root.cert.data.person_id],
        )?,
        epoch: 0,
        meta: cipher(16),
        members: vec![f.root.cert.data.person_id],
    };
    assert_eq!(
        request(
            &f.app,
            "PATCH",
            &format!("/v1/channels/{cid}"),
            Some(&f.root.token),
            &shrink
        )
        .await?
        .0,
        409
    );
    shrink.epoch = 1;
    shrink.membership = next_roster(
        &f.root.cert,
        &f.root.key,
        &c.membership,
        1,
        shrink.members.clone(),
    )?;
    assert_eq!(
        request(
            &f.app,
            "PATCH",
            &format!("/v1/channels/{cid}"),
            Some(&f.root.token),
            &shrink
        )
        .await?
        .0,
        400
    );
    // The old membership still works after both rejected publications.
    let _: GetKeysResponse = ok(
        &f.app,
        "GET",
        &format!("/v1/channels/{cid}/keys/mine"),
        Some(&person.token),
        json!(null),
    )
    .await?;
    shrink.wrapped_keys = vec![wrapped(cid, f.root.cert.data.device_id, 1)];
    let updated: Channel = ok(
        &f.app,
        "PATCH",
        &format!("/v1/channels/{cid}"),
        Some(&f.root.token),
        &shrink,
    )
    .await?;
    trusted.verify_channel(&updated, Some(&c.membership))?;
    assert_eq!(updated.current_epoch, 1);
    assert_eq!(
        request(
            &f.app,
            "PATCH",
            &format!("/v1/channels/{cid}"),
            Some(&f.root.token),
            &shrink
        )
        .await?
        .0,
        409
    );
    assert_eq!(
        request(
            &f.app,
            "GET",
            &format!("/v1/channels/{cid}/keys/mine"),
            Some(&person.token),
            json!(null)
        )
        .await?
        .0,
        404
    );
    let mut r = f.message(&f.root, cid, None, vec![])?;
    assert_eq!(
        request(
            &f.app,
            "POST",
            &format!("/v1/channels/{cid}/messages"),
            Some(&f.root.token),
            &r
        )
        .await?
        .0,
        400
    );
    r.envelope.epoch = 1;
    r.signature = f.root.key.sign(&message_signing_bytes(&r.envelope)?);
    let _: Message = ok(
        &f.app,
        "POST",
        &format!("/v1/channels/{cid}/messages"),
        Some(&f.root.token),
        r,
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn messages_check_signatures_threads_summaries_and_pagination() -> TestResult {
    let f = Fixture::new().await?;
    let path = format!("/v1/channels/{}/messages", f.all);
    let mut r = f.message(&f.root, f.all, None, vec![])?;
    r.has_summary = false;
    assert_eq!(
        request(&f.app, "POST", &path, Some(&f.root.token), &r)
            .await?
            .0,
        400
    );
    r.has_summary = true;
    r.signature = Signature::from_bytes([0; 64]);
    assert_eq!(
        request(&f.app, "POST", &path, Some(&f.root.token), r)
            .await?
            .0,
        400
    );
    let mut replay = f.message(&f.root, f.all, None, vec![])?;
    replay.id = MessageId::from_bytes(bytes());
    assert_eq!(
        request(&f.app, "POST", &path, Some(&f.root.token), replay)
            .await?
            .0,
        400
    );
    let mut unsummarized = f.message(&f.root, f.all, None, vec![])?;
    unsummarized.has_summary = false;
    unsummarized.envelope.summary_covers_seq = None;
    unsummarized.signature = f
        .root
        .key
        .sign(&message_signing_bytes(&unsummarized.envelope)?);
    let short: Message = ok(&f.app, "POST", &path, Some(&f.root.token), unsummarized).await?;
    let mut first_reply = f.message(&f.root, f.all, Some(short.id), vec![])?;
    first_reply.has_summary = false;
    first_reply.envelope.summary_covers_seq = None;
    first_reply.signature = f
        .root
        .key
        .sign(&message_signing_bytes(&first_reply.envelope)?);
    let _: Message = ok(&f.app, "POST", &path, Some(&f.root.token), first_reply).await?;
    let mut third = f.message(&f.root, f.all, Some(short.id), vec![])?;
    third.has_summary = false;
    third.envelope.summary_covers_seq = None;
    third.signature = f.root.key.sign(&message_signing_bytes(&third.envelope)?);
    let (status, error, _) = request(&f.app, "POST", &path, Some(&f.root.token), third).await?;
    assert_eq!(status, 400);
    assert!(
        error
            .to_string()
            .contains("3 messages since the last summary")
    );
    let root = f.send(&f.root, f.all, None).await?;
    let mut overclaim = f.message(&f.root, f.all, Some(root.id), vec![])?;
    overclaim.envelope.summary_covers_seq = Some(u64::MAX);
    overclaim.signature = f
        .root
        .key
        .sign(&message_signing_bytes(&overclaim.envelope)?);
    assert_eq!(
        request(&f.app, "POST", &path, Some(&f.root.token), overclaim)
            .await?
            .0,
        400
    );
    let reply = f.send(&f.root, f.all, Some(root.id)).await?;
    assert_eq!(reply.summary_covers_seq, Some(0));
    assert!(reply.seq > root.seq);
    let r = f.message(&f.root, f.all, Some(reply.id), vec![])?;
    assert_eq!(
        request(&f.app, "POST", &path, Some(&f.root.token), r)
            .await?
            .0,
        400
    );
    let page: ListMessagesResponse = ok(
        &f.app,
        "GET",
        &format!("{path}?thread={}&limit=1", root.id),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.next_after, Some(root.seq));
    let page: ListMessagesResponse = ok(
        &f.app,
        "GET",
        &format!("{path}?after={}&limit=1", root.seq),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(page.messages[0].id, reply.id);
    let foreign = f.send(&f.root, f.own, None).await?;
    let r = f.message(&f.root, f.all, Some(foreign.id), vec![])?;
    assert_eq!(
        request(&f.app, "POST", &path, Some(&f.root.token), r)
            .await?
            .0,
        400
    );
    Ok(())
}
#[tokio::test]
async fn claims_are_exclusive_and_owner_can_unclaim_from_another_handle() -> TestResult {
    let f = Fixture::new().await?;
    let p = f.join(&f.root, GrantKind::Invite).await?;
    let m = f.send(&f.root, f.all, None).await?;
    let path = format!("/v1/messages/{}/reactions", m.id);
    let r1 = f.reaction(&p, m.id, ReactionKind::Claim, "one", false)?;
    let r2 = f.reaction(&p, m.id, ReactionKind::Claim, "two", false)?;
    let (a, b) = tokio::join!(
        request(&f.app, "POST", &path, Some(&p.token), &r1),
        request(&f.app, "POST", &path, Some(&p.token), &r2)
    );
    let (a, b) = (a?, b?);
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
    let conflict = if a.0 == StatusCode::CONFLICT {
        a.1
    } else {
        b.1
    };
    match serde_json::from_value::<ErrorBody>(conflict)? {
        ErrorBody::Conflict {
            claim: Some(existing),
            message,
        } => {
            assert!(*existing == r1.reaction || *existing == r2.reaction);
            assert!(message.contains(&m.id.to_string()));
        }
        _ => anyhow::bail!("claim conflict lacks its signed current claim"),
    }
    let remove = format!("{path}/claim");
    assert_eq!(
        request(
            &f.app,
            "DELETE",
            &remove,
            Some(&f.root.token),
            f.reaction(&f.root, m.id, ReactionKind::Claim, "main", true)?
        )
        .await?
        .0,
        409
    );
    let _: Reaction = ok(
        &f.app,
        "DELETE",
        &remove,
        Some(&p.token),
        f.reaction(&p, m.id, ReactionKind::Claim, "third", true)?,
    )
    .await?;
    let _: Reaction = ok(
        &f.app,
        "POST",
        &path,
        Some(&f.root.token),
        f.reaction(&f.root, m.id, ReactionKind::Claim, "main", false)?,
    )
    .await?;
    let ack = f.reaction(&p, m.id, ReactionKind::Ack, "one", false)?;
    let _: Reaction = ok(&f.app, "POST", &path, Some(&p.token), &ack).await?;
    assert_eq!(
        request(&f.app, "POST", &path, Some(&p.token), ack).await?.0,
        409
    );
    let _: Reaction = ok(
        &f.app,
        "DELETE",
        &format!("{path}/ack"),
        Some(&p.token),
        f.reaction(&p, m.id, ReactionKind::Ack, "one", true)?,
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn counts_mentions_claims_and_read_cursors_are_per_person() -> TestResult {
    let f = Fixture::new().await?;
    let p = f.join(&f.root, GrantKind::Invite).await?;
    let device = f.join(&p, GrantKind::Enroll).await?;
    let r = f.message(
        &f.root,
        f.all,
        None,
        vec![Mention {
            person_id: p.cert.data.person_id,
            handle: Some("worker".parse()?),
        }],
    )?;
    let m: Message = ok(
        &f.app,
        "POST",
        &format!("/v1/channels/{}/messages", f.all),
        Some(&f.root.token),
        r,
    )
    .await?;
    let c: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts?handle=worker"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!((c.unread_threads, c.mentions), (1, 1));
    let all_handles: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!(all_handles.mentions, 1);
    // Existing databases backfill the index once without changing count semantics.
    let connection = rusqlite::Connection::open(f.dir.path().join("phi.db"))?;
    connection.execute_batch("DROP TABLE message_mentions; PRAGMA user_version=0;")?;
    let upgraded = Server::open(f.config.clone())?;
    let after_upgrade: Counts = ok(
        &upgraded.router(),
        "GET",
        &f.space("/counts?handle=worker"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!(
        (after_upgrade.unread_threads, after_upgrade.mentions),
        (1, 1)
    );
    let c: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts?handle=other"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!((c.unread_threads, c.mentions), (1, 0));
    let _: ReadCursor = ok(
        &f.app,
        "PUT",
        &format!("/v1/threads/{}/cursor", m.id),
        Some(&device.token),
        PutCursorRequest {
            last_read_seq: m.seq,
        },
    )
    .await?;
    let c: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!(c.unread_threads, 0);
    let _: ReadCursor = ok(
        &f.app,
        "PUT",
        &format!("/v1/threads/{}/cursor", m.id),
        Some(&p.token),
        PutCursorRequest {
            last_read_seq: m.seq - 1,
        },
    )
    .await?;
    let _: Reaction = ok(
        &f.app,
        "POST",
        &format!("/v1/messages/{}/reactions", m.id),
        Some(&device.token),
        f.reaction(&device, m.id, ReactionKind::Claim, "main", false)?,
    )
    .await?;
    let c: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts?handle=worker"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!((c.unread_threads, c.mentions, c.claimed_by_you), (1, 1, 1));
    // Foreign messages notify every handle; explicit addresses still contribute
    // only to that handle's mention count, without changing person-wide reads.
    let addressed: Message = ok(
        &f.app,
        "POST",
        &format!("/v1/channels/{}/messages", f.all),
        Some(&f.root.token),
        f.message(
            &f.root,
            f.all,
            Some(m.id),
            vec![Mention {
                person_id: p.cert.data.person_id,
                handle: Some("other".parse()?),
            }],
        )?,
    )
    .await?;
    let c: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts?handle=other"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!((c.unread_threads, c.mentions), (1, 1));
    let events: EventsResponse = ok(
        &f.app,
        "GET",
        &f.space(&format!("/events?after={}&timeout=0&handle=other", m.seq)),
        Some(&device.token),
        json!(null),
    )
    .await?;
    assert!(events.events.iter().any(|event| matches!(&event.event,
        EventData::Message(message) if message.id == addressed.id)));
    Ok(())
}
#[tokio::test]
async fn event_feed_hides_private_channels_and_shares_channel_reactions() -> TestResult {
    let f = Fixture::new().await?;
    let p = f.join(&f.root, GrantKind::Invite).await?;
    let private = f.send(&f.root, f.own, None).await?;
    let public = f.send(&f.root, f.all, None).await?;
    let r = f.reaction(&p, public.id, ReactionKind::Ack, "main", false)?;
    let _: Reaction = ok(
        &f.app,
        "POST",
        &format!("/v1/messages/{}/reactions", public.id),
        Some(&p.token),
        r,
    )
    .await?;
    let e: EventsResponse = ok(
        &f.app,
        "GET",
        &f.space("/events?after=0&timeout=0&handle=main"),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!(e.events.len(), 2);
    assert!(e.next_after > public.seq);
    assert!(e.events.iter().all(|e| e.seq != private.seq));
    let e: EventsResponse = ok(
        &f.app,
        "GET",
        &f.space(&format!("/events?after={}&timeout=0", public.seq)),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(e.events.len(), 1);
    assert!(matches!(e.events[0].event, EventData::Reaction(_)));
    let empty: EventsResponse = ok(
        &f.app,
        "GET",
        &f.space(&format!("/events?after={}&timeout=0", e.next_after)),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert!(empty.events.is_empty());
    assert_eq!(empty.next_after, e.next_after);
    let _invisible = f.send(&f.root, f.own, None).await?;
    let empty: EventsResponse = ok(
        &f.app,
        "GET",
        &f.space(&format!("/events?after={}&timeout=0", e.next_after)),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert!(empty.events.is_empty());
    assert_eq!(
        empty.next_after, e.next_after,
        "never jump to an undelivered high-water mark"
    );
    let _visible = f.send(&f.root, f.all, None).await?;
    let gap: EventsResponse = ok(
        &f.app,
        "GET",
        &f.space(&format!("/events?after={}&timeout=0", empty.next_after)),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!(gap.events.len(), 1);
    assert_eq!(gap.next_after, gap.events[0].seq);
    assert!(gap.events[0].seq > empty.next_after + 1);
    Ok(())
}
#[tokio::test]
async fn multiple_long_polls_wake_and_revocation_interrupts_waiters() -> TestResult {
    let f = Fixture::new().await?;
    let p = f.join(&f.root, GrantKind::Invite).await?;
    let conn = rusqlite::Connection::open(f.dir.path().join("phi.db"))?;
    conn.execute(
        "UPDATE devices SET json=json_set(json,'$.last_seen_at',1) WHERE id=?",
        [p.cert.data.device_id.to_string()],
    )?;
    let mut waiters = Vec::new();
    for _ in 0..1000 {
        let path = f.space("/events?after=0&timeout=10");
        let app = f.app.clone();
        let token = p.token.clone();
        waiters.push(tokio::spawn(async move {
            request(&app, "GET", &path, Some(&token), json!(null)).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let seen: u64 = conn.query_row(
        "SELECT json_extract(json,'$.last_seen_at') FROM devices WHERE id=?",
        [p.cert.data.device_id.to_string()],
        |r| r.get(0),
    )?;
    assert_eq!(seen, 1, "idle polls must not write last_seen");
    let _: Blob = ok(
        &f.app,
        "POST",
        "/v1/blobs",
        Some(&f.root.token),
        UploadBlobRequest {
            space_id: f.sid,
            ciphertext: Base64Bytes::new(vec![4; 32]),
        },
    )
    .await?;
    let quiet: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts"),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(quiet.latest_seq, 0);
    assert!(waiters.iter().all(|task| !task.is_finished()));
    let m = f.send(&f.root, f.all, None).await?;
    let _: ReadCursor = ok(
        &f.app,
        "PUT",
        &format!("/v1/threads/{}/cursor", m.id),
        Some(&f.root.token),
        PutCursorRequest {
            last_read_seq: m.seq,
        },
    )
    .await?;
    let counts: Counts = ok(
        &f.app,
        "GET",
        &f.space("/counts"),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(counts.latest_seq, m.seq);
    for task in waiters {
        let (status, value, _) = tokio::time::timeout(Duration::from_secs(5), task).await???;
        assert_eq!(status, 200);
        let events: EventsResponse = serde_json::from_value(value)?;
        assert_eq!(events.events[0].seq, m.seq);
    }
    let app = f.app.clone();
    let t = p.token.clone();
    let path = f.space(&format!("/events?after={}&timeout=5", m.seq));
    let wait =
        tokio::spawn(async move { request(&app, "GET", &path, Some(&t), json!(null)).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let rev = sign_revocation(
        RevocationData {
            space_id: f.sid,
            target: RevocationTarget::Device {
                device_id: p.cert.data.device_id,
            },
            issuer_device: f.root.cert.data.device_id,
            created_at: timestamp(),
        },
        &f.root.key,
    )?;
    let _: Revocation = ok(
        &f.app,
        "POST",
        &f.space("/revocations"),
        Some(&f.root.token),
        CreateRevocationRequest { revocation: rev },
    )
    .await?;
    let (status, _, _) = tokio::time::timeout(Duration::from_secs(1), wait).await???;
    assert_eq!(status, 401);
    Ok(())
}
#[tokio::test]
async fn blobs_enforce_size_quota_and_channel_scoped_downloads() -> TestResult {
    let f = Fixture::with_config(|c| {
        c.limits.max_blob_bytes = 32;
        c.limits.space_quota_bytes = 64
    })
    .await?;
    let p = f.join(&f.root, GrantKind::Invite).await?;
    let upload = |n| UploadBlobRequest {
        space_id: f.sid,
        ciphertext: Base64Bytes::new(vec![5; n]),
    };
    assert_eq!(
        request(&f.app, "POST", "/v1/blobs", Some(&f.root.token), upload(49))
            .await?
            .0,
        413
    );
    let blob: Blob = ok(&f.app, "POST", "/v1/blobs", Some(&f.root.token), upload(32)).await?;
    assert_eq!(blob.size, 32);
    assert_eq!(
        request(
            &f.app,
            "GET",
            &format!("/v1/blobs/{}", blob.id),
            Some(&p.token),
            json!(null)
        )
        .await?
        .0,
        404
    );
    let mut msg = f.message(&f.root, f.all, None, vec![])?;
    msg.blob_ids.push(blob.id);
    let _: Message = ok(
        &f.app,
        "POST",
        &format!("/v1/channels/{}/messages", f.all),
        Some(&f.root.token),
        msg,
    )
    .await?;
    let downloaded: DownloadBlobResponse = ok(
        &f.app,
        "GET",
        &format!("/v1/blobs/{}", blob.id),
        Some(&p.token),
        json!(null),
    )
    .await?;
    assert_eq!(downloaded.ciphertext.len(), 32);
    let _: Blob = ok(&f.app, "POST", "/v1/blobs", Some(&p.token), upload(32)).await?;
    assert_eq!(
        request(&f.app, "POST", "/v1/blobs", Some(&p.token), upload(16))
            .await?
            .0,
        413
    );
    let other = Fixture::new().await?;
    assert_eq!(
        request(
            &f.app,
            "GET",
            &f.space(""),
            Some(&other.root.token),
            json!(null)
        )
        .await?
        .0,
        401
    );
    assert_eq!(
        request(
            &f.app,
            "GET",
            &other.space(""),
            Some(&f.root.token),
            json!(null)
        )
        .await?
        .0,
        404
    );
    Ok(())
}
#[tokio::test]
async fn retention_deletes_whole_threads_and_orphan_blobs_but_keeps_activity() -> TestResult {
    let f = Fixture::with_config(|c| c.defaults.retention_days = 1).await?;
    let blob: Blob = ok(
        &f.app,
        "POST",
        "/v1/blobs",
        Some(&f.root.token),
        UploadBlobRequest {
            space_id: f.sid,
            ciphertext: Base64Bytes::new(vec![4; 32]),
        },
    )
    .await?;
    let mut r = f.message(&f.root, f.all, None, vec![])?;
    r.blob_ids.push(blob.id);
    let old: Message = ok(
        &f.app,
        "POST",
        &format!("/v1/channels/{}/messages", f.all),
        Some(&f.root.token),
        r,
    )
    .await?;
    let reply = f.send(&f.root, f.all, Some(old.id)).await?;
    let _: Reaction = ok(
        &f.app,
        "POST",
        &format!("/v1/messages/{}/reactions", old.id),
        Some(&f.root.token),
        f.reaction(&f.root, old.id, ReactionKind::Claim, "main", false)?,
    )
    .await?;
    let active = f.send(&f.root, f.all, None).await?;
    let conn = rusqlite::Connection::open(f.dir.path().join("phi.db"))?;
    conn.execute(
        "UPDATE threads SET activity=? WHERE id=?",
        rusqlite::params![timestamp() + 86401, active.id.to_string()],
    )?;
    assert_eq!(f.server.sweep(timestamp() + 86402).await?, 1);
    for table in ["messages", "reactions", "cursors", "events", "blobs"] {
        let count: u64 =
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
        assert_eq!(
            count,
            if matches!(table, "messages" | "events" | "cursors") {
                1
            } else {
                0
            },
            "{table}"
        );
    }
    assert!(
        !f.dir
            .path()
            .join("blobs")
            .join(blob.id.to_string())
            .exists()
    );
    assert_eq!(
        request(
            &f.app,
            "POST",
            &format!("/v1/channels/{}/messages", f.all),
            Some(&f.root.token),
            f.message(&f.root, f.all, Some(reply.id), vec![])?
        )
        .await?
        .0,
        404
    );
    Ok(())
}
#[tokio::test]
async fn backup_is_restorable_and_copies_ciphertext_blobs() -> TestResult {
    let f = Fixture::new().await?;
    let blob: Blob = ok(
        &f.app,
        "POST",
        "/v1/blobs",
        Some(&f.root.token),
        UploadBlobRequest {
            space_id: f.sid,
            ciphertext: Base64Bytes::new(vec![9; 32]),
        },
    )
    .await?;
    let m = f.send(&f.root, f.all, None).await?;
    let dest = f.dir.path().join("backup");
    f.server.backup(dest.clone()).await?;
    assert_eq!(
        std::fs::read(dest.join("blobs").join(blob.id.to_string()))?,
        vec![9; 32]
    );
    let restored = Server::open(Config {
        data_dir: dest.clone(),
        ..f.config.clone()
    })?;
    let messages: ListMessagesResponse = ok(
        &restored.router(),
        "GET",
        &format!("/v1/channels/{}/messages", f.all),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(messages.messages[0].id, m.id);
    assert!(f.server.backup(dest).await.is_err());
    Ok(())
}
#[tokio::test]
async fn token_buckets_return_retry_after_and_survive_restart() -> TestResult {
    let f = Fixture::with_config(|c| {
        c.limits.messages_per_min = 1;
        c.limits.messages_per_hour = 2
    })
    .await?;
    let mut garbage = f.message(&f.root, f.all, None, vec![])?;
    garbage.envelope.ciphertext = Base64Bytes::new(vec![8; MAX_CIPHERTEXT_BYTES]);
    garbage.signature = Signature::from_bytes([0; 64]);
    assert_eq!(
        request(
            &f.app,
            "POST",
            &format!("/v1/channels/{}/messages", f.all),
            Some(&f.root.token),
            garbage
        )
        .await?
        .0,
        400
    );

    let path = format!("/v1/channels/{}/messages", f.all);
    let r = f.message(&f.root, f.all, None, vec![])?;
    let (s, e, h) = request(&f.app, "POST", &path, Some(&f.root.token), &r).await?;
    assert_eq!(s, 429);
    assert!(h.get("Retry-After").is_some());
    assert_eq!(e["error"], "rate_limited");
    let reopened = Server::open(f.config.clone())?;
    assert_eq!(
        request(&reopened.router(), "POST", &path, Some(&f.root.token), &r)
            .await?
            .0,
        429
    );
    let conn = rusqlite::Connection::open(f.dir.path().join("phi.db"))?;
    conn.execute("UPDATE rate_buckets SET updated=updated-61", [])?;
    let _: Message = ok(&f.app, "POST", &path, Some(&f.root.token), r).await?;
    assert_eq!(
        request(
            &f.app,
            "POST",
            &path,
            Some(&f.root.token),
            f.message(&f.root, f.all, None, vec![])?
        )
        .await?
        .0,
        429
    );
    Ok(())
}
#[tokio::test]
async fn signed_settings_emit_events_and_forever_disables_retention() -> TestResult {
    let f = Fixture::new().await?;
    let root = f.send(&f.root, f.all, None).await?;
    let settings = SpaceSettings {
        retention_days: 0,
        summary_mode: SummaryMode::Off,
        ..SpaceSettings::default()
    };
    let mut change = sign_settings(
        SettingsChangeData {
            space_id: f.sid,
            issuer_device: f.root.cert.data.device_id,
            created_at: timestamp(),
            settings,
        },
        &f.root.key,
    )?;
    change.data.settings.retention_days = 1;
    assert_eq!(
        request(
            &f.app,
            "PATCH",
            &f.space("/settings"),
            Some(&f.root.token),
            UpdateSettingsRequest {
                change: change.clone()
            }
        )
        .await?
        .0,
        400
    );
    change.data.settings.retention_days = 0;
    let _: SettingsChange = ok(
        &f.app,
        "PATCH",
        &f.space("/settings"),
        Some(&f.root.token),
        UpdateSettingsRequest {
            change: change.clone(),
        },
    )
    .await?;
    let space: Space = ok(
        &f.app,
        "GET",
        &f.space(""),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert_eq!(space.settings_change, Some(change));
    let e: EventsResponse = ok(
        &f.app,
        "GET",
        &f.space(&format!("/events?after={}&timeout=0", root.seq)),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    assert!(matches!(e.events[0].event, EventData::Settings(_)));
    let mut r = f.message(&f.root, f.all, Some(root.id), vec![])?;
    r.has_summary = false;
    r.envelope.summary_covers_seq = None;
    r.signature = f.root.key.sign(&message_signing_bytes(&r.envelope)?);
    let _: Message = ok(
        &f.app,
        "POST",
        &format!("/v1/channels/{}/messages", f.all),
        Some(&f.root.token),
        r,
    )
    .await?;
    assert_eq!(f.server.sweep(timestamp() + 86400 * 100).await?, 0);
    Ok(())
}
#[tokio::test]
async fn config_cli_overrides_and_backup_use_deployment_contract() -> TestResult {
    let init_dir = tempfile::tempdir()?;
    let deployment = init_dir.path().join("deployment dir");
    let init = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_phi-server"))
            .args(["init", "--dir"])
            .arg(&deployment)
            .env("PHI_SERVER_CONFIG", "does-not-exist.toml")
            .output()
    };
    let output = init()?;
    assert!(output.status.success(), "{:?}", output.stderr);
    let instructions = String::from_utf8(output.stdout)?;
    #[cfg(windows)]
    assert!(instructions.contains("$env:PHI_ADMIN_TOKEN"));
    #[cfg(not(windows))]
    assert!(instructions.contains("PHI_ADMIN_TOKEN="));
    assert!(instructions.contains("phi-server --config server.toml"));
    let sample = std::fs::read_to_string(deployment.join("server.toml"))?;
    assert_eq!(sample, include_str!("../../../deploy/server.toml"));
    let env = std::fs::read_to_string(deployment.join(".env"))?;
    let admin = env
        .lines()
        .find_map(|line| line.strip_prefix("PHI_SERVER_ADMIN_TOKEN="))
        .ok_or_else(|| anyhow::anyhow!("missing generated token"))?;
    let _: Base64<32> = admin.parse()?;
    assert!(!instructions.contains(admin));
    let mut config: Config = toml::from_str(&sample)?;
    config.admin_token = Some(admin.into());
    config.validate()?;
    assert!(config.listen.ip().is_loopback());
    assert_eq!(config.listen.port(), 8443);
    assert!(matches!(config.allow_space_creation, Creation::Token));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(deployment.join(".env"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(deployment.join("server.toml"))?
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
    assert!(!init()?.status.success());
    assert_eq!(std::fs::read_to_string(deployment.join(".env"))?, env);
    assert_eq!(
        std::fs::read_to_string(deployment.join("server.toml"))?,
        sample
    );
    std::fs::remove_file(deployment.join("server.toml"))?;
    assert!(!init()?.status.success());
    assert!(!deployment.join("server.toml").exists());
    assert_eq!(std::fs::read_to_string(deployment.join(".env"))?, env);
    std::fs::remove_file(deployment.join(".env"))?;
    std::fs::write(deployment.join("server.toml"), &sample)?;
    assert!(!init()?.status.success());
    assert!(!deployment.join(".env").exists());
    assert_eq!(
        std::fs::read_to_string(deployment.join("server.toml"))?,
        sample
    );
    // No --dir means the current directory, with a fresh token each time.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_phi-server"))
        .arg("init")
        .current_dir(init_dir.path())
        .output()?;
    assert!(output.status.success());
    assert_ne!(std::fs::read_to_string(init_dir.path().join(".env"))?, env);
    assert!(!init_dir.path().join("data").exists());
    let f = Fixture::new().await?;
    let config_path = f.dir.path().join("server.toml");
    std::fs::write(
        &config_path,
        format!(
            "data_dir = {:?}\nallow_space_creation = 'token'\n[tls]\nmode = 'off'\n",
            f.dir.path()
        ),
    )?;
    let dest = f.dir.path().join("cli-backup");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_phi-server"))
        .arg("backup")
        .arg(&dest)
        .env("PHI_SERVER_CONFIG", &config_path)
        .env("PHI_SERVER_LISTEN", "127.0.0.1:12345")
        .env("PHI_SERVER_LIMITS__MESSAGES_PER_MIN", "10")
        .env("PHI_SERVER_ADMIN_TOKEN", admin)
        .status()?;
    assert!(status.success());
    assert!(dest.join("phi.db").is_file());
    std::fs::write(
        &config_path,
        "allow_space_creation='anyone'\n[tls]\nmode='acme'\n",
    )?;
    assert!(Config::load(&config_path).is_err());
    std::fs::write(&config_path, "allow_space_creation='anyone'\nunknown=1\n")?;
    assert!(Config::load(&config_path).is_err());
    Ok(())
}

#[tokio::test]
async fn upload_admission_precedes_body_reads_and_rechecks_revocation() -> TestResult {
    let f = Fixture::new().await?;
    let person = f.join(&f.root, GrantKind::Invite).await?;
    let polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let make_body = |polled: std::sync::Arc<std::sync::atomic::AtomicBool>| {
        Body::from_stream(futures_util::stream::once(async move {
            polled.store(true, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{}"))
        }))
    };
    let unauthorized = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/blobs")
                .header("Phi-Protocol", PROTOCOL_MAJOR)
                .body(make_body(polled.clone()))?,
        )
        .await?;
    assert_eq!(unauthorized.status(), 401);
    assert!(!polled.load(Ordering::SeqCst));
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let data = serde_json::to_vec(&UploadBlobRequest {
        space_id: f.sid,
        ciphertext: Base64Bytes::new(vec![5; 32]),
    })?;
    let (entered, resume) = (started.clone(), release.clone());
    let body = Body::from_stream(futures_util::stream::once(async move {
        entered.notify_one();
        resume.notified().await;
        Ok::<_, std::io::Error>(axum::body::Bytes::from(data))
    }));
    let first = Request::builder()
        .method("POST")
        .uri("/v1/blobs")
        .header("Phi-Protocol", PROTOCOL_MAJOR)
        .header("Authorization", format!("Bearer {}", person.token))
        .body(body)?;
    let app = f.app.clone();
    let pending = tokio::spawn(async move { app.oneshot(first).await });
    tokio::time::timeout(Duration::from_secs(2), started.notified()).await?;
    let second = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/blobs")
                .header("Phi-Protocol", PROTOCOL_MAJOR)
                .header("Authorization", format!("Bearer {}", f.root.token))
                .body(make_body(polled.clone()))?,
        )
        .await?;
    assert_eq!(second.status(), 429);
    assert!(!polled.load(Ordering::SeqCst));
    let _: Space = tokio::time::timeout(
        Duration::from_secs(1),
        ok(
            &f.app,
            "GET",
            &f.space(""),
            Some(&f.root.token),
            json!(null),
        ),
    )
    .await??;
    let rev = sign_revocation(
        RevocationData {
            space_id: f.sid,
            target: RevocationTarget::Device {
                device_id: person.cert.data.device_id,
            },
            issuer_device: f.root.cert.data.device_id,
            created_at: timestamp(),
        },
        &f.root.key,
    )?;
    let _: Revocation = ok(
        &f.app,
        "POST",
        &f.space("/revocations"),
        Some(&f.root.token),
        CreateRevocationRequest { revocation: rev },
    )
    .await?;
    release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), pending)
            .await???
            .status(),
        401
    );
    assert_eq!(std::fs::read_dir(f.dir.path().join("blobs"))?.count(), 0);
    let _: Blob = ok(
        &f.app,
        "POST",
        "/v1/blobs",
        Some(&f.root.token),
        UploadBlobRequest {
            space_id: f.sid,
            ciphertext: Base64Bytes::new(vec![6; 32]),
        },
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn space_root_cannot_be_revoked() -> TestResult {
    let f = Fixture::new().await?;
    let person = f.join(&f.root, GrantKind::Invite).await?;
    for target in [
        RevocationTarget::Person {
            person_id: f.root.cert.data.person_id,
        },
        RevocationTarget::Device {
            device_id: f.root.cert.data.device_id,
        },
    ] {
        let rev = sign_revocation(
            RevocationData {
                space_id: f.sid,
                target,
                issuer_device: person.cert.data.device_id,
                created_at: person.cert.data.created_at,
            },
            &person.key,
        )?;
        assert_eq!(
            request(
                &f.app,
                "POST",
                &f.space("/revocations"),
                Some(&person.token),
                CreateRevocationRequest { revocation: rev }
            )
            .await?
            .0,
            400
        );
    }
    let _: Space = ok(
        &f.app,
        "GET",
        &f.space(""),
        Some(&f.root.token),
        json!(null),
    )
    .await?;
    Ok(())
}
