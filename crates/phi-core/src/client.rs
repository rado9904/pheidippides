use crate::{
    storage::*,
    transport::{Http, token_string},
    *,
};
use phi_crypto::*;
use phi_proto::*;
use reqwest::Method;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use zeroize::Zeroizing;

/// Longest single long-poll `wait` issues; stays under common proxy idle limits.
const LONG_POLL_CHUNK_SECS: u64 = 45;
const GATEWAY_RETRIES: u8 = 3;
const GATEWAY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelMeta {
    pub name: String,
    pub space_name: String,
    pub people: BTreeMap<PersonId, String>,
    pub members: Vec<PersonId>,
}
#[derive(Clone, Debug)]
pub struct NamedChannel {
    pub channel: Channel,
    pub meta: ChannelMeta,
}
#[derive(Clone, Default)]
pub struct SendOptions {
    pub body: String,
    pub summary: Option<String>,
    pub files: Vec<PathBuf>,
}
pub struct DeviceOptions {
    pub kind: DeviceKind,
    pub name: String,
}
impl Default for DeviceOptions {
    fn default() -> Self {
        Self {
            kind: DeviceKind::Cli,
            name: "cli".into(),
        }
    }
}
impl DeviceOptions {
    fn validate(&self) -> Result<()> {
        let _: Handle = self.name.parse()?;
        Ok(())
    }
}

struct WaitBatch {
    events: Vec<WaitEntry>,
    cursor: String,
    next_after: Seq,
}

pub struct Client {
    pub profile: Profile,
    pub handle: Handle,
    pub channels: Vec<NamedChannel>,
    pub settings: SpaceSettings,
    pub devices: Vec<Device>,
    pub limits: ServerLimits,
    store: Store,
    keys: Box<dyn KeyStore>,
    identity: Identity,
    cache: Cache,
    http: Http,
    directory: VerifiedDirectory,
    // Opening prepares the first operation; resolution borrows it, later operations refresh.
    opening_snapshot: bool,
}
impl Client {
    pub async fn create(
        store: Store,
        server: &str,
        name: &str,
        display_name: &str,
        admin_token: Option<String>,
    ) -> Result<Self> {
        Self::create_for_device(
            store,
            server,
            name,
            display_name,
            admin_token,
            DeviceOptions::default(),
        )
        .await
    }
    pub async fn create_for_device(
        store: Store,
        server: &str,
        name: &str,
        display_name: &str,
        admin_token: Option<String>,
        device: DeviceOptions,
    ) -> Result<Self> {
        device.validate()?;
        validate_name(name)?;
        let keys = DeviceKeys::generate(&mut entropy)?;
        let sid = space_id(&keys.sign_public());
        let pid = PersonId::from_bytes(random_id(&mut entropy)?);
        let did = DeviceId::from_bytes(random_id(&mut entropy)?);
        let cert = certify_device(
            DeviceCertificateData {
                space_id: sid,
                person_id: pid,
                device_id: did,
                kind: device.kind,
                sign_pub: keys.sign_public(),
                kex_pub: keys.kex_public(),
                created_at: now(),
                issuer: CertificateIssuer::Device { device_id: did },
            },
            &keys,
        )?;
        let bundle = TrustBundle {
            root: cert.clone(),
            certificates: vec![],
            grants: vec![],
            revocations: vec![],
        };
        let directory = verify_trust_bundle(sid, &bundle, now(), None)?;
        let mut people = BTreeMap::new();
        people.insert(pid, unique_slug(display_name, &BTreeMap::new()));
        let meta = ChannelMeta {
            name: "all".into(),
            space_name: name.into(),
            people,
            members: vec![pid],
        };
        let (all, all_key) = channel_request(&cert, &keys, &directory, ChannelKind::All, &meta)?;
        let (own, own_key) = channel_request(
            &cert,
            &keys,
            &directory,
            ChannelKind::SelfChannel,
            &ChannelMeta {
                name: "self".into(),
                ..meta
            },
        )?;
        let http = Http::new(server, admin_token)?;
        let response: CreateSpaceResponse = http
            .send(
                Method::POST,
                "/spaces",
                &CreateSpaceRequest {
                    root_cert: cert.clone(),
                    all_channel: all,
                    self_channel: own,
                },
            )
            .await?;
        let profile = Profile {
            name: name.into(),
            server: http.base.clone(),
            space_id: sid,
            person_id: pid,
            device_id: did,
            device_name: device.name.clone(),
            display_name: unique_slug(display_name, &BTreeMap::new()),
            kind: device.kind,
            summarizer: None,
        };
        let (sign, kex) = keys.export_secrets();
        let identity = Identity {
            sign: KeyBytes::from_bytes(*sign),
            kex: KeyBytes::from_bytes(*kex),
            token: response.device_token,
            certificate: cert,
        };
        let key_store: Box<dyn KeyStore> = Box::new(FileKeyStore::open(
            &store.profile_dir(&profile).join("keys"),
        )?);
        store_json(key_store.as_ref(), "identity", &identity)?;
        save_channel_key(key_store.as_ref(), &all_key)?;
        save_channel_key(key_store.as_ref(), &own_key)?;
        let mut cache = Cache::open(&store.cache_dir(&profile).join("cache.db"))?;
        cache.trust(sid, &bundle)?;
        store.save_profile(&profile)?;
        Self::open_with_keystore(store, profile, None, key_store).await
    }
    pub async fn join(store: Store, encoded: &str, name: &str) -> Result<Self> {
        Self::join_for_device(store, encoded, name, DeviceOptions::default()).await
    }
    pub async fn join_for_device(
        store: Store,
        encoded: &str,
        name: &str,
        device: DeviceOptions,
    ) -> Result<Self> {
        device.validate()?;
        let link = GrantLink::parse(encoded)?;
        if store
            .profiles()?
            .iter()
            .any(|p| p.server == link.server_url() && p.space_id == link.space_id())
        {
            return Err(user(
                "a profile for this space already exists on this machine",
            ));
        }
        let grant_keys = link.secret().derive()?;
        let http = Http::new(&link.server_url(), None)?;
        let grant: GetGrantResponse = http.get(&format!("/grants/{}", grant_keys.id())).await?;
        grant.record.validate()?;
        let data = &grant.record.data;
        if data.space_id != link.space_id()
            || data.grant_id != grant_keys.id()
            || data.grant_pub != grant_keys.public()
        {
            return Err(user("grant does not match the link"));
        }
        let keys = DeviceKeys::generate(&mut entropy)?;
        let did = DeviceId::from_bytes(random_id(&mut entropy)?);
        let certificate = certify_with_grant(
            DeviceCertificateData {
                space_id: link.space_id(),
                person_id: data.person_id,
                device_id: did,
                kind: device.kind,
                sign_pub: keys.sign_public(),
                kex_pub: keys.kex_public(),
                created_at: now(),
                issuer: CertificateIssuer::Grant {
                    grant_id: grant_keys.id(),
                },
            },
            &grant_keys,
        )?;
        let response: RedeemGrantResponse = http
            .send(
                Method::POST,
                &format!("/grants/{}/redeem", grant_keys.id()),
                &RedeemGrantRequest {
                    certificate: certificate.clone(),
                },
            )
            .await?;
        if response.grant.record != grant.record
            || !response.directory.certificates.contains(&certificate)
        {
            return Err(user("redemption changed the signed grant or certificate"));
        }
        let directory = verify_trust_bundle(link.space_id(), &response.directory, now(), None)?;
        directory.device(did)?;
        let (sign, kex) = keys.export_secrets();
        let mut profile = Profile {
            name: link.space_id().to_string(),
            server: http.base,
            space_id: link.space_id(),
            person_id: data.person_id,
            device_id: did,
            device_name: device.name.clone(),
            display_name: unique_slug(name, &BTreeMap::new()),
            kind: device.kind,
            summarizer: None,
        };
        if store
            .profiles()?
            .iter()
            .any(|p| p.server == profile.server && p.space_id == profile.space_id)
        {
            return Err(user(
                "a profile for this space already exists on this machine",
            ));
        }
        let key_store: Box<dyn KeyStore> = Box::new(FileKeyStore::open(
            &store.profile_dir(&profile).join("keys"),
        )?);
        let identity = Identity {
            sign: KeyBytes::from_bytes(*sign),
            kex: KeyBytes::from_bytes(*kex),
            token: response.device_token,
            certificate,
        };
        store_json(key_store.as_ref(), "identity", &identity)?;
        let mut cache = Cache::open(&store.cache_dir(&profile).join("cache.db"))?;
        cache.trust(profile.space_id, &response.directory)?;
        let http = Http::new(&profile.server, Some(token_string(&identity.token)?))?;
        let channels: ListChannelsResponse = http
            .get(&format!("/spaces/{}/channels", profile.space_id))
            .await?;
        let grant_keys: Vec<ChannelKey> = response
            .grant
            .sealed_keys
            .iter()
            .map(|sealed| unseal_grant_key(profile.space_id, &grant_keys, sealed))
            .collect::<std::result::Result<_, _>>()?;
        for key in &grant_keys {
            let channel = channels
                .channels
                .iter()
                .find(|c| c.id == key.channel_id())
                .ok_or_else(|| user("grant channel missing"))?;
            let epochs = cache.channel_epochs(&directory, channel)?;
            validate_key(key, &epochs)?;
            let membership = directory.verify_channel(channel, None)?;
            let membership = if key.epoch() == channel.current_epoch {
                membership
            } else {
                let records: Vec<_> = channel
                    .membership_history
                    .iter()
                    .chain(std::iter::once(&channel.membership))
                    .collect();
                let index = records
                    .iter()
                    .rposition(|r| r.data.epoch == key.epoch())
                    .ok_or_else(|| user("historical epoch has no authenticated roster"))?;
                directory
                    .verify_membership(records[index], index.checked_sub(1).map(|i| records[i]))?
            };
            // Read and check encrypted peer context before giving a device any key.
            let meta_key = grant_keys
                .iter()
                .find(|key| key.channel_id() == channel.id && key.epoch() == channel.current_epoch)
                .ok_or_else(|| user("grant metadata key missing"))?;
            validate_key(meta_key, &epochs)?;
            let meta: ChannelMeta =
                serde_json::from_slice(&decrypt_channel_metadata(meta_key, &channel.meta)?)?;
            validate_meta(channel, &meta, profile.person_id)?;
            let recipient = directory.device(did)?;
            let wrapped = wrap_channel_key(key, &recipient, &membership, &mut entropy)?;
            let _: GetKeysResponse = http
                .send(
                    Method::PUT,
                    &format!("/channels/{}/keys", channel.id),
                    &PutKeysRequest {
                        epoch: key.epoch(),
                        wrapped_keys: vec![wrapped],
                    },
                )
                .await?;
            cache.channel(&directory, channel)?;
            save_channel_key(key_store.as_ref(), key)?;
            if channel.kind == ChannelKind::All {
                profile.name = meta.space_name;
            }
        }
        store.save_profile(&profile)?;
        let mut client = Self::open_with_keystore(store, profile, None, key_store).await?;
        client.register_name(name).await?;
        if !client
            .channels
            .iter()
            .any(|c| c.channel.kind == ChannelKind::SelfChannel)
        {
            client
                .new_channel(
                    ChannelKind::SelfChannel,
                    "self",
                    vec![client.profile.person_id],
                )
                .await?;
        }
        Ok(client)
    }
    pub async fn open(store: Store, profile: Profile, handle: Option<&str>) -> Result<Self> {
        let keys = FileKeyStore::open(&store.profile_dir(&profile).join("keys"))?;
        Self::open_with_keystore(store, profile, handle, Box::new(keys)).await
    }
    async fn open_with_keystore(
        store: Store,
        profile: Profile,
        handle: Option<&str>,
        keys: Box<dyn KeyStore>,
    ) -> Result<Self> {
        let identity: Identity = load_json(keys.as_ref(), "identity")?;
        let cert = &identity.certificate.data;
        if cert.space_id != profile.space_id
            || cert.person_id != profile.person_id
            || cert.device_id != profile.device_id
            || cert.kind != profile.kind
            || cert.sign_pub != identity.keys().sign_public()
            || cert.kex_pub != identity.keys().kex_public()
        {
            return Err(user("profile and private identity do not match"));
        }
        let mut cache = Cache::open(&store.cache_dir(&profile).join("cache.db"))?;
        let http = Http::new(&profile.server, Some(token_string(&identity.token)?))?;
        let devices: ListDevicesResponse = http
            .get(&format!("/spaces/{}/devices", profile.space_id))
            .await?;
        let directory = cache.trust(profile.space_id, &devices.directory)?;
        directory.device(profile.device_id)?;
        let handle = handle.unwrap_or(&profile.device_name).parse()?;
        let mut client = Self {
            profile,
            handle,
            channels: vec![],
            settings: SpaceSettings::default(),
            devices: devices.devices,
            limits: ServerLimits::default(),
            store,
            keys,
            identity,
            cache,
            http,
            directory,
            opening_snapshot: false,
        };
        client.refresh_channels().await?;
        if client.publish_pending_revocations().await? {
            client.refresh().await?;
        }
        client.resume_rotations().await?;
        client.prune()?;
        client.opening_snapshot = true;
        Ok(client)
    }
    pub async fn refresh(&mut self) -> Result<()> {
        let sid = self.profile.space_id;
        let devices: ListDevicesResponse = self.http.get(&format!("/spaces/{sid}/devices")).await?;
        self.directory = self.cache.trust(sid, &devices.directory)?;
        self.directory.device(self.profile.device_id)?;
        self.devices = devices.devices;
        self.refresh_channels().await
    }
    async fn begin_operation(&mut self) -> Result<()> {
        if !std::mem::take(&mut self.opening_snapshot) {
            self.refresh().await?;
        }
        Ok(())
    }
    async fn refresh_channels(&mut self) -> Result<()> {
        let sid = self.profile.space_id;
        let space: GetSpaceResponse = self.http.get(&format!("/spaces/{sid}")).await?;
        if space.id != sid {
            return Err(user("space response crossed profile boundary"));
        }
        self.limits = space.limits;
        self.settings = match space.settings_change {
            Some(change) => self.cache.accept_settings(&self.directory, &change)?,
            None => self.cache.trusted_settings()?,
        };
        let channels: ListChannelsResponse =
            self.http.get(&format!("/spaces/{sid}/channels")).await?;
        let mut accepted = Vec::new();
        for channel in channels.channels {
            let epochs = self.cache.channel_epochs(&self.directory, &channel)?;
            let response: GetKeysResponse = self
                .http
                .get(&format!("/channels/{}/keys/mine", channel.id))
                .await?;
            let mut candidates = Vec::new();
            for wrapped in response.wrapped_keys {
                if wrapped.channel_id != channel.id {
                    return Err(user("key response crossed channel boundary"));
                }
                let key = unwrap_channel_key(
                    sid,
                    self.profile.device_id,
                    &self.identity.keys(),
                    &wrapped,
                )?;
                validate_key(&key, &epochs)?;
                candidates.push(key);
            }
            let stored;
            let key = if let Some(key) = candidates
                .iter()
                .find(|key| key.epoch() == channel.current_epoch)
            {
                key
            } else {
                stored = self.key(channel.id, channel.current_epoch)?;
                &stored
            };
            validate_key(key, &epochs)?;
            let meta: ChannelMeta =
                serde_json::from_slice(&decrypt_channel_metadata(key, &channel.meta)?)?;
            validate_meta(&channel, &meta, self.profile.person_id)?;
            self.cache.channel(&self.directory, &channel)?;
            for key in &candidates {
                save_channel_key(self.keys.as_ref(), key)?;
            }
            accepted.push(NamedChannel { channel, meta });
        }
        self.channels = accepted;
        Ok(())
    }
    fn prune(&self) -> Result<()> {
        self.cache.prune(self.settings.retention_days)?;
        let blobs = self.store.cache_dir(&self.profile).join("blobs");
        if blobs.exists() {
            let mut stmt = self.cache.db.prepare("SELECT DISTINCT json_extract(value,'$.blob_id') FROM messages,json_each(messages.content,'$.attachments')")?;
            let live: BTreeSet<String> = stmt
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            for entry in std::fs::read_dir(blobs)? {
                let entry = entry?;
                if !live.contains(&entry.file_name().to_string_lossy().to_string()) {
                    std::fs::remove_dir_all(entry.path())?;
                }
            }
        }
        Ok(())
    }
    pub fn names(&self) -> BTreeMap<PersonId, String> {
        self.channels
            .iter()
            .find(|c| c.channel.kind == ChannelKind::All)
            .map(|c| c.meta.people.clone())
            .unwrap_or_default()
    }
    pub fn person_name(&self, id: PersonId) -> String {
        self.names()
            .get(&id)
            .cloned()
            .unwrap_or_else(|| id.to_string())
    }
    pub fn channel_name(&self, id: ChannelId) -> String {
        self.channels
            .iter()
            .find(|c| c.channel.id == id)
            .map(|c| match c.channel.kind {
                ChannelKind::All => "#all".into(),
                ChannelKind::Group => format!("#{}", c.meta.name),
                _ => format!(
                    "@{}",
                    self.person_name(
                        c.channel
                            .members
                            .iter()
                            .find(|p| **p != self.profile.person_id)
                            .copied()
                            .unwrap_or(self.profile.person_id)
                    )
                ),
            })
            .unwrap_or_else(|| id.to_string())
    }
    pub fn person(&self, name: &str) -> Result<PersonId> {
        let name = name.trim_start_matches('@');
        self.names()
            .iter()
            .find(|(id, n)| n.as_str() == name || id.to_string() == name)
            .map(|(id, _)| *id)
            .ok_or_else(|| user(format!("unknown person @{name}; run phi who")))
    }
    async fn register_name(&mut self, name: &str) -> Result<()> {
        self.opening_snapshot = false;
        let all = self
            .channels
            .iter()
            .find(|c| c.channel.kind == ChannelKind::All)
            .cloned()
            .ok_or_else(|| user("missing #all"))?;
        let mut meta = all.meta.clone();
        if let Some(existing) = meta.people.get(&self.profile.person_id) {
            self.profile.display_name = existing.clone();
        } else {
            let name = unique_slug(name, &meta.people);
            meta.people.insert(self.profile.person_id, name.clone());
            self.profile.display_name = name;
            self.update_channel(&all.channel, meta, all.channel.members.clone())
                .await?;
        }
        self.store.save_profile(&self.profile)?;
        self.refresh().await
    }
    /// Keep addressing and the human composer consistent across a person's devices.
    pub async fn set_display_name(&mut self, name: &str) -> Result<()> {
        if name.trim().is_empty() || name.len() > 120 {
            return Err(user("display name must be 1–120 bytes"));
        }
        self.begin_operation().await?;
        let all_id = self
            .channels
            .iter()
            .find(|c| c.channel.kind == ChannelKind::All)
            .map(|c| c.channel.id)
            .ok_or_else(|| user("missing #all"))?;
        self.ensure_safe_epoch(all_id).await?;
        let all = self
            .channels
            .iter()
            .find(|c| c.channel.id == all_id)
            .cloned()
            .ok_or_else(|| user("missing #all after rotation"))?;
        let mut meta = all.meta.clone();
        meta.people.remove(&self.profile.person_id);
        let name = unique_slug(name, &meta.people);
        meta.people.insert(self.profile.person_id, name.clone());
        self.update_channel(&all.channel, meta, all.channel.members.clone())
            .await?;
        self.profile.display_name = name;
        self.store.save_profile(&self.profile)?;
        self.refresh().await
    }
    fn key(&self, channel: ChannelId, epoch: Epoch) -> Result<ChannelKey> {
        let key: KeyBytes = load_json(self.keys.as_ref(), &format!("channel/{channel}/{epoch}"))?;
        Ok(ChannelKey::from_bytes(
            self.profile.space_id,
            channel,
            epoch,
            *key.as_bytes(),
        ))
    }
    pub async fn invite(&mut self, enroll: bool, never_expires: bool) -> Result<Zeroizing<String>> {
        self.begin_operation().await?;
        if !enroll && never_expires {
            return Err(user("only enrollment grants may have no expiry"));
        }
        let secret = GrantSecret::generate(&mut entropy)?;
        let grant = secret.derive()?;
        let record = sign_grant(
            GrantRecordData {
                space_id: self.profile.space_id,
                grant_id: grant.id(),
                grant_pub: grant.public(),
                kind: if enroll {
                    GrantKind::Enroll
                } else {
                    GrantKind::Invite
                },
                person_id: if enroll {
                    self.profile.person_id
                } else {
                    PersonId::from_bytes(random_id(&mut entropy)?)
                },
                created_at: now(),
                expires_at: if never_expires {
                    None
                } else {
                    Some(now() + DEFAULT_GRANT_LIFETIME_SECS)
                },
                issuer_device: self.profile.device_id,
            },
            &self.identity.keys(),
        )?;
        let mut sealed_keys = Vec::new();
        for channel in &self.channels {
            if enroll || channel.channel.kind == ChannelKind::All {
                let membership = self
                    .directory
                    .verify_channel(&channel.channel, Some(&channel.channel.membership))?;
                if !membership.members().contains(&self.profile.person_id) {
                    return Err(user("not a channel member"));
                }
                // Share history as well as the current epoch, including metadata encrypted under an older key.
                for epoch in 0..=channel.channel.current_epoch {
                    if epoch != channel.channel.current_epoch
                        && self
                            .keys
                            .get(&format!("channel/{}/{epoch}", channel.channel.id))?
                            .is_none()
                    {
                        continue;
                    }
                    sealed_keys.push(seal_grant_key(
                        &grant,
                        &self.key(channel.channel.id, epoch)?,
                        &mut entropy,
                    )?);
                }
            }
        }
        let _: CreateGrantResponse = self
            .http
            .send(
                Method::POST,
                &format!("/spaces/{}/grants", self.profile.space_id),
                &CreateGrantRequest {
                    record,
                    sealed_keys,
                },
            )
            .await?;
        let url =
            reqwest::Url::parse(&self.profile.server).map_err(|_| user("invalid server URL"))?;
        let authority = self
            .profile
            .server
            .split_once("://")
            .ok_or_else(|| user("invalid server origin"))?
            .1;
        Ok(GrantLink::new(
            url.scheme() == "https",
            authority.to_owned(),
            self.profile.space_id,
            secret,
        )?
        .encode())
    }
    async fn new_channel(
        &mut self,
        kind: ChannelKind,
        name: &str,
        mut members: Vec<PersonId>,
    ) -> Result<ChannelId> {
        members.sort();
        members.dedup();
        let meta = ChannelMeta {
            name: name.into(),
            space_name: self.profile.name.clone(),
            people: BTreeMap::new(),
            members,
        };
        let (request, key) = channel_request(
            &self.identity.certificate,
            &self.identity.keys(),
            &self.directory,
            kind,
            &meta,
        )?;
        let channel: CreateChannelResponse = self
            .http
            .send(
                Method::POST,
                &format!("/spaces/{}/channels", self.profile.space_id),
                &request,
            )
            .await?;
        self.cache.channel(&self.directory, &channel)?;
        save_channel_key(self.keys.as_ref(), &key)?;
        let id = channel.id;
        self.refresh().await?;
        Ok(id)
    }
    async fn destination(&mut self, to: &str) -> Result<(ChannelId, Vec<Mention>)> {
        if let Some(name) = to.strip_prefix('#') {
            let channel = self
                .channels
                .iter()
                .find(|c| {
                    matches!(c.channel.kind, ChannelKind::All | ChannelKind::Group)
                        && c.meta.name == name
                })
                .ok_or_else(|| user(format!("unknown channel #{name}")))?;
            return Ok((channel.channel.id, vec![]));
        }
        let recipient = to
            .strip_prefix('@')
            .ok_or_else(|| user("address must be @person[/handle] or #group"))?;
        let (name, handle) = recipient
            .split_once('/')
            .map_or((recipient, None), |(n, h)| (n, Some(h)));
        let person = self.person(name)?;
        let mentions = vec![Mention {
            person_id: person,
            handle: handle.map(str::parse).transpose()?,
        }];
        let kind = if person == self.profile.person_id {
            ChannelKind::SelfChannel
        } else {
            ChannelKind::Dm
        };
        let mut members = vec![self.profile.person_id, person];
        members.sort();
        members.dedup();
        if let Some(c) = self.channels.iter().find(|c| {
            c.channel.kind == kind
                && c.channel.members.iter().copied().collect::<BTreeSet<_>>()
                    == members.iter().copied().collect()
        }) {
            return Ok((c.channel.id, mentions));
        }
        Ok((self.new_channel(kind, "dm", members).await?, mentions))
    }
    fn next_reply(&self, history: &[DecodedMessage]) -> SummaryPreflight {
        let messages_since_summary = history
            .iter()
            .rposition(|m| m.content.summary.is_some())
            .map_or(history.len(), |i| history.len() - i - 1)
            .saturating_add(1);
        SummaryPreflight {
            required: self.profile.kind == DeviceKind::Cli
                && self.settings.summary_mode == SummaryMode::Required
                && u64::try_from(messages_since_summary).unwrap_or(u64::MAX)
                    >= u64::from(self.settings.summary_every),
            messages_since_summary,
            threshold: self.settings.summary_every,
            summarizer_configured: self.profile.summarizer.is_some(),
        }
    }
    pub fn save_draft(&self, body: &str) -> Result<PathBuf> {
        let dir = self.store.cache_dir(&self.profile).join("drafts");
        private_dir(&dir)?;
        let path = dir.join(format!(
            "{}.md",
            MessageId::from_bytes(random_id(&mut entropy)?)
        ));
        atomic_write(&path, body.as_bytes())?;
        Ok(path)
    }
    pub async fn send(&mut self, to: &str, title: &str, options: SendOptions) -> Result<Message> {
        self.begin_operation().await?;
        let (channel, mentions) = self.destination(to).await?;
        self.send_inner(channel, None, Some(title.into()), mentions, options, &[])
            .await
    }
    pub async fn reply(&mut self, thread: MessageId, options: SendOptions) -> Result<Message> {
        self.begin_operation().await?;
        let history = self.load_thread(thread).await?;
        let root = history.first().ok_or_else(|| user("thread not found"))?;
        let channel = root.message.envelope.channel_id;
        self.send_inner(channel, Some(thread), None, vec![], options, &history)
            .await
    }
    async fn send_inner(
        &mut self,
        channel: ChannelId,
        thread: Option<MessageId>,
        title: Option<String>,
        mentions: Vec<Mention>,
        mut options: SendOptions,
        history: &[DecodedMessage],
    ) -> Result<Message> {
        self.ensure_safe_epoch(channel).await?;
        let preflight = self.next_reply(history);
        let since_summary = preflight.messages_since_summary;
        let summary_every = preflight.threshold;
        let summary_required = preflight.required;
        if options.summary.is_none()
            && (summary_required || self.profile.summarizer.is_some())
            && history.iter().any(|m| m.verification_error.is_some())
        {
            return Err(user(
                "thread contains unverifiable or unavailable messages; supply an explicit whole-thread summary after reviewing the errors",
            ));
        }
        if options.summary.is_none() {
            if let Some(command) = &self.profile.summarizer {
                let mut input = summary_input(history);
                input.push_str(&format!(
                    "\nNew message (included in summary):\n{}\n{}\n",
                    title.as_deref().unwrap_or(""),
                    options.body
                ));
                options.summary = Some(run_summarizer(command, &input).await?);
            } else if summary_required {
                return Err(Error::SummaryRequired(format!(
                    "--summary is required now: {since_summary} messages since the last summary (including this message; threshold {summary_every}) and summary_mode=required; summarize the whole thread or configure a summarizer in profile.toml"
                )));
            }
        }
        if options.files.len() > MAX_ATTACHMENTS {
            return Err(user("at most 32 attachments"));
        }
        let mut attachments = Vec::new();
        for path in options.files {
            let metadata = std::fs::metadata(&path)?;
            if metadata.len() > self.limits.max_attachment_bytes {
                return Err(user(format!(
                    "attachment exceeds server limit of {} bytes",
                    self.limits.max_attachment_bytes
                )));
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| user("attachment filename must be UTF-8"))?
                .to_owned();
            let plaintext = Zeroizing::new(std::fs::read(&path)?);
            let (key, encrypted) = encrypt_attachment(&plaintext, &mut entropy)?;
            let blob: UploadBlobResponse = self
                .http
                .send(
                    Method::POST,
                    "/blobs",
                    &UploadBlobRequest {
                        space_id: self.profile.space_id,
                        ciphertext: encrypted.ciphertext,
                    },
                )
                .await?;
            attachments.push(Attachment {
                blob_id: blob.id,
                mime: mime(&name, &plaintext).into(),
                name,
                size: plaintext.len() as u64,
                key,
                nonce: encrypted.nonce,
            });
        }
        let epoch = self
            .channels
            .iter()
            .find(|c| c.channel.id == channel)
            .ok_or_else(|| user("channel missing"))?
            .channel
            .current_epoch;
        let content = MessageContent {
            title,
            body: options.body,
            summary: options.summary,
            attachments,
            display_name: self.profile.display_name.clone(),
        };
        let id = MessageId::from_bytes(random_id(&mut entropy)?);
        let coverage = content
            .summary
            .as_ref()
            .map(|_| history.last().map_or(0, |m| m.message.seq));
        content.validate_with_attachment_limit(self.limits.max_attachment_bytes)?;
        let (envelope, signature) = encrypt_message(
            &self.key(channel, epoch)?,
            &self.identity.keys(),
            MessageMetadata {
                id,
                summary_covers_seq: coverage,
                thread_id: thread,
                handle: self.handle.clone(),
                mentions,
            },
            &content,
            &mut entropy,
        )?;
        let message: SendMessageResponse = self
            .http
            .send(
                Method::POST,
                &format!("/channels/{channel}/messages"),
                &SendMessageRequest {
                    id,
                    envelope,
                    signature,
                    has_summary: content.summary.is_some(),
                    blob_ids: content.attachments.iter().map(|a| a.blob_id).collect(),
                },
            )
            .await?;
        self.directory.verify_message(&message)?;
        self.cache.message(&message, &content)?;
        if message.envelope.thread_id.is_none()
            || history
                .last()
                .is_some_and(|m| m.message.seq.checked_add(1) == Some(message.seq))
        {
            // Numbering is optional receipt decoration after publication has committed.
            let _ = self.cache.number(&message, history.len() + 1);
        }
        Ok(message)
    }
    pub async fn counts(&mut self) -> Result<Counts> {
        self.opening_snapshot = false;
        self.http
            .get(&format!(
                "/spaces/{}/counts?handle={}",
                self.profile.space_id, self.handle
            ))
            .await
    }
    pub async fn fetch(&mut self) -> Result<String> {
        let counts = self.counts().await?;
        if counts.unread_threads == 0 && counts.mentions == 0 && counts.claimed_by_you == 0 {
            return Ok(String::new());
        }
        let channels = counts
            .channels
            .iter()
            .map(|c| format!("{} {}", self.channel_name(c.channel_id), c.unread_threads))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(format!(
            "phi · {}: {} unread threads ({channels}) · {} mention(s) of you (@{}/{}) · {} claimed by you\n",
            self.profile.name,
            counts.unread_threads,
            counts.mentions,
            self.profile.display_name,
            self.handle,
            counts.claimed_by_you
        ))
    }
    async fn sync_channel(
        &mut self,
        channel: ChannelId,
        thread: Option<MessageId>,
    ) -> Result<Vec<DecodedMessage>> {
        let mut after = 0;
        let mut decoded = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let page: ListMessagesResponse = self
                .http
                .get(&format!(
                    "/channels/{channel}/messages?after={after}&limit=1000{}",
                    thread.map(|id| format!("&thread={id}")).unwrap_or_default()
                ))
                .await?;
            let count = page.messages.len();
            for message in page.messages {
                if message.envelope.channel_id != channel
                    || message.envelope.space_id != self.profile.space_id
                    || message.seq <= after
                    || !seen.insert(message.id)
                {
                    return Err(user(
                        "message page crossed scope, duplicated an ID, or changed order",
                    ));
                }
                after = message.seq;
                let verified = (|| -> Result<_> {
                    let author = self.directory.verify_message(&message)?;
                    let content = decrypt_message(
                        &self.key(channel, message.envelope.epoch)?,
                        &author,
                        &message.envelope,
                        &message.signature,
                    )?;
                    Ok((author.certificate().data.kind, content))
                })();
                let (author_kind, content, verification_error) = match verified {
                    Ok((kind, content)) => {
                        self.cache.message(&message, &content)?;
                        (kind, content, None)
                    }
                    Err(error) => {
                        let description = error.to_string();
                        (
                            DeviceKind::Cli,
                            MessageContent {
                                title: message
                                    .envelope
                                    .thread_id
                                    .is_none()
                                    .then(|| "[unavailable encrypted title]".into()),
                                body: String::new(),
                                summary: None,
                                attachments: vec![],
                                display_name: String::new(),
                            },
                            Some(description),
                        )
                    }
                };
                decoded.push(DecodedMessage {
                    number: 0,
                    perspective: self.perspective(&message),
                    message,
                    content,
                    attachments: vec![],
                    reactions: vec![],
                    author_kind,
                    verification_error,
                });
            }
            for cursor in page.cursors {
                if cursor.person_id != self.profile.person_id {
                    return Err(user("read cursor crossed person boundary"));
                }
                self.cache.db.execute("INSERT INTO cursors VALUES(?,?) ON CONFLICT(thread) DO UPDATE SET seq=excluded.seq", params![cursor.thread_id.to_string(), cursor.last_read_seq])?;
            }
            for activity in page.activities {
                if !decoded.iter().rev().take(count).any(|m| {
                    m.message.envelope.thread_id.unwrap_or(m.message.id) == activity.thread_id
                }) {
                    return Err(user("thread activity crossed page boundary"));
                }
                self.cache
                    .set(&format!("discovery/{}", activity.thread_id), &activity)?;
            }
            // A page contains authoritative current reactions for each returned message, including empty lists.
            for message in decoded.iter().rev().take(count) {
                self.cache.db.execute(
                    "DELETE FROM reactions WHERE message=?",
                    [message.message.id.to_string()],
                )?;
            }
            for reaction in page.reactions {
                if !decoded
                    .iter()
                    .rev()
                    .take(count)
                    .any(|m| m.message.id == reaction.data.message_id)
                {
                    return Err(user("reaction outside message page"));
                }
                self.directory.verify_reaction(&reaction)?;
                self.save_reaction(&reaction)?;
            }
            if count < 1000 {
                break;
            }
        }
        let mut numbers = BTreeMap::new();
        for message in &mut decoded {
            let next = numbers
                .entry(
                    message
                        .message
                        .envelope
                        .thread_id
                        .unwrap_or(message.message.id),
                )
                .or_insert(0);
            *next += 1;
            message.number = *next;
            if message.verification_error.is_none() {
                self.cache.number(&message.message, *next)?;
            }
            message.reactions = self.reactions(message.message.id)?;
        }
        Ok(decoded)
    }
    async fn sync_all(&mut self) -> Result<Vec<DecodedMessage>> {
        let ids: Vec<_> = self.channels.iter().map(|c| c.channel.id).collect();
        let mut messages = Vec::new();
        for channel in ids {
            messages.extend(self.sync_channel(channel, None).await?);
        }
        messages.sort_by_key(|m| m.message.seq);
        Ok(messages)
    }
    async fn load_thread(&mut self, thread: MessageId) -> Result<Vec<DecodedMessage>> {
        let root: Message = match self.cached_message(thread)? {
            Some(message) => message,
            None => self.http.get(&format!("/messages/{thread}")).await?,
        };
        if self.directory.device(root.author_device).is_err()
            || self
                .keys
                .get(&format!(
                    "channel/{}/{}",
                    root.envelope.channel_id, root.envelope.epoch
                ))?
                .is_none()
        {
            self.refresh().await?;
        }
        if root.id != thread || root.envelope.thread_id.is_some() {
            return Err(user("read requires a thread root ID"));
        }
        self.directory.verify_message(&root)?;
        let messages = self
            .sync_channel(root.envelope.channel_id, Some(thread))
            .await?;
        let messages: Vec<_> = messages
            .into_iter()
            .filter(|m| m.message.id == thread || m.message.envelope.thread_id == Some(thread))
            .collect();
        if let Some(root) = messages.first() {
            self.directory.verify_message(&root.message)?;
        }
        if messages
            .first()
            .is_none_or(|m| m.message.id != thread || m.content.title.is_none())
        {
            return Err(user(
                "thread not found; use the full thread ID from phi inbox",
            ));
        }
        Ok(messages)
    }
    fn perspective(&self, message: &Message) -> MessagePerspective {
        if message.author_person != self.profile.person_id {
            MessagePerspective::Other
        } else if message.author_device == self.profile.device_id
            && message.envelope.handle == self.handle
        {
            MessagePerspective::You
        } else {
            MessagePerspective::YourOtherSession
        }
    }
    fn cached_message(&self, id: MessageId) -> Result<Option<Message>> {
        self.cache
            .db
            .query_row(
                "SELECT raw FROM messages WHERE id=?",
                [id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
            .transpose()
    }
    pub fn cached_reference(&self, id: MessageId) -> Result<Option<MessageReference>> {
        self.cache
            .db
            .query_row(
                "SELECT thread,number FROM message_numbers WHERE id=?",
                [id.to_string()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, usize>(1)?)),
            )
            .optional()?
            .map(|(thread, number)| {
                Ok(MessageReference {
                    thread: thread.parse()?,
                    number,
                    id,
                })
            })
            .transpose()
    }
    /// Publication already committed: display must never turn it into a failed command.
    pub fn sent_text(&self, message: &Message) -> String {
        let thread = message.envelope.thread_id.unwrap_or(message.id);
        let label = self
            .cached_reference(message.id)
            .ok()
            .flatten()
            .map(|r| r.to_string())
            .unwrap_or_else(|| message.id.to_string());
        format!("thread {thread} · message {label} · id {}\n", message.id)
    }
    pub async fn resolve_message(&mut self, reference: MessageRef) -> Result<MessageId> {
        match reference {
            MessageRef::Id(id) => Ok(id),
            MessageRef::InThread { thread, number } => {
                let cached: Option<String> = self
                    .cache
                    .db
                    .query_row(
                        "SELECT id FROM message_numbers WHERE thread=? AND number=?",
                        params![thread.to_string(), number.get()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(id) = cached {
                    return Ok(id.parse()?);
                }
                self.load_thread(thread)
                    .await?
                    .get(number.get() - 1)
                    .filter(|m| m.verification_error.is_none())
                    .map(|m| m.message.id)
                    .ok_or_else(|| user(format!("thread {thread}: message #{number} unavailable")))
            }
        }
    }
    pub async fn resolve_thread(&mut self, reference: MessageRef) -> Result<MessageId> {
        if let MessageRef::InThread { thread, .. } = reference {
            self.resolve_message(reference).await?;
            return Ok(thread);
        }
        let id = self.resolve_message(reference).await?;
        if let Some(reference) = self.cached_reference(id)? {
            return Ok(reference.thread);
        }
        let message: Message = match self.cached_message(id)? {
            Some(message) => message,
            None => self.http.get(&format!("/messages/{id}")).await?,
        };
        self.directory.verify_message(&message)?;
        if message.id != id {
            return Err(user("message lookup changed requested ID"));
        }
        Ok(message.envelope.thread_id.unwrap_or(id))
    }
    pub async fn message_reference(&mut self, id: MessageId) -> Result<MessageReference> {
        if let Some(reference) = self.cached_reference(id)? {
            return Ok(reference);
        }
        let thread = self.resolve_thread(MessageRef::Id(id)).await?;
        self.load_thread(thread).await?;
        self.cached_reference(id)?
            .ok_or_else(|| user("message has no verified thread position"))
    }
    async fn wait_reference(
        &mut self,
        id: MessageId,
    ) -> Result<(Option<MessageReference>, String)> {
        match self.message_reference(id).await {
            Ok(reference) => Ok((Some(reference), String::new())),
            Err(error) => {
                // A valid event may refer to unavailable or corrupted history. Keep its
                // signed ID usable without letting that history block all later events.
                self.cache
                    .set(&format!("wait-reference/{id}"), &error.to_string())?;
                Ok((None, format!("  reference unavailable: {error}\n")))
            }
        }
    }
    pub async fn format_wait_entry(&mut self, event: &WaitEntry) -> Result<String> {
        Ok(self
            .format_wait_entries(std::slice::from_ref(event))
            .await?
            .0)
    }
    async fn format_wait_entries(
        &mut self,
        events: &[WaitEntry],
    ) -> Result<(String, Vec<(MessageId, Seq)>)> {
        let mut output = String::new();
        let mut read = Vec::new();
        let mut foreign_content = false;
        let mut seen = BTreeSet::new();
        for event in events {
            match event {
                WaitEntry::Message(entry) => {
                    if !seen.insert(entry.id) {
                        continue;
                    }
                    let sequences: BTreeSet<_> = events
                        .iter()
                        .filter_map(|event| match event {
                            WaitEntry::Message(other) if other.id == entry.id => {
                                Some(other.latest_seq)
                            }
                            _ => None,
                        })
                        .collect();
                    let latest = sequences.iter().next_back().copied().unwrap_or(0);
                    let (view, warnings, foreign) = self.wait_thread(entry, &sequences).await?;
                    output.push_str(&view.text_unwrapped());
                    output.push_str(&warnings);
                    foreign_content |= foreign;
                    read.push((entry.id, latest));
                }
                WaitEntry::VerificationFailure { seq, description } => {
                    output.push_str(&format!(
                        "verification failed · to: unavailable · event {seq}: {description} (recorded locally; skipped)\n"
                    ));
                }
                WaitEntry::Reaction(notice) => output.push_str(&notice.text()),
                WaitEntry::Settings(change) => {
                    output.push_str(&format!(
                        "to: #all · space settings changed: retention_days={} summary_mode={:?} summary_every={}\n",
                        change.data.settings.retention_days, change.data.settings.summary_mode, change.data.settings.summary_every
                    ));
                }
                WaitEntry::Revocation(revocation) => {
                    output.push_str(&format!(
                        "to: #all · signed revocation: {:?}\n",
                        revocation.data.target
                    ));
                }
            }
        }
        Ok((wrap_untrusted(output, foreign_content), read))
    }
    async fn wait_thread(
        &mut self,
        entry: &InboxEntry,
        sequences: &BTreeSet<Seq>,
    ) -> Result<(ThreadView, String, bool)> {
        let latest = sequences.iter().next_back().copied().unwrap_or(0);
        let mut warnings = String::new();
        for sequence in sequences {
            let raw: String = self.cache.db.query_row(
                "SELECT raw FROM messages WHERE seq=? AND thread=?",
                params![sequence, entry.id.to_string()],
                |r| r.get(0),
            )?;
            let message: Message = serde_json::from_str(&raw)?;
            warnings.push_str(&self.wait_reference(message.id).await?.1);
        }
        let raws: Vec<String> = self
            .cache
            .db
            .prepare("SELECT raw FROM messages WHERE thread=? AND seq<=? ORDER BY seq")?
            .query_map(params![entry.id.to_string(), latest], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let mut history = Vec::new();
        for raw in raws {
            let message: Message = serde_json::from_str(&raw)?;
            let selected = sequences.contains(&message.seq);
            match self.decode_cached_message(message) {
                Ok(message) => history.push(message),
                Err(error) if selected => return Err(error),
                // Rejected historical context must not hide a valid new message.
                Err(_) => {}
            }
        }
        let to = history
            .first()
            .filter(|m| m.message.id == entry.id)
            .map(|m| self.addressed_to(&m.message))
            .unwrap_or_else(|| entry.to.clone());
        let next_reply = self.next_reply(&history);
        let mut view = compose_thread(
            entry.id,
            history,
            ReadOptions {
                all: true,
                last: None,
            },
            &self.names(),
            to,
        )?;
        view.next_reply = next_reply;
        let foreign_content = view.has_foreign_content();
        let hidden_messages = view
            .messages
            .first()
            .is_none_or(|message| message.message.id != entry.id)
            || view
                .messages
                .iter()
                .any(|message| !sequences.contains(&message.message.seq));
        if !hidden_messages {
            view.summary = None;
            view.summary_perspective = None;
        }
        for message in &view.messages {
            if !sequences.contains(&message.message.seq) && !message.reactions.is_empty() {
                let text = format_reactions(&message.reactions, &view.names);
                if !text.is_empty() {
                    view.reaction_context
                        .push(format!("{}: {text}", message.reference()));
                }
            }
        }
        view.messages
            .retain(|message| sequences.contains(&message.message.seq));
        view.newer_messages = view
            .messages
            .iter()
            .filter(|message| {
                view.summary_covers_seq
                    .is_some_and(|coverage| message.message.seq > coverage)
                    && Some(message.number) != view.summary_number
            })
            .count();
        for message in &mut view.messages {
            for attachment in &message.content.attachments {
                message.attachments.push(self.download(attachment).await?);
            }
        }
        Ok((view, warnings, foreign_content))
    }
    pub async fn read(&mut self, thread: MessageId, options: ReadOptions) -> Result<ThreadView> {
        self.begin_operation().await?;
        let messages = self.load_thread(thread).await?;
        let latest = messages.last().map_or(0, |m| m.message.seq);
        let to = messages
            .first()
            .map(|m| self.addressed_to(&m.message))
            .unwrap_or_default();
        let next_reply = self.next_reply(&messages);
        let mut view = compose_thread(thread, messages, options, &self.names(), to)?;
        view.next_reply = next_reply;
        for message in &mut view.messages {
            for attachment in &message.content.attachments {
                message.attachments.push(self.download(attachment).await?);
            }
        }
        self.mark_read(thread, latest).await?;
        self.advance_wait(&format!("read/{}/{thread}", self.handle), latest)?;
        Ok(view)
    }
    async fn mark_read(&mut self, thread: MessageId, latest: Seq) -> Result<()> {
        let previous: Option<Seq> = self
            .cache
            .db
            .query_row(
                "SELECT seq FROM cursors WHERE thread=?",
                [thread.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        let latest = latest.max(previous.unwrap_or(0));
        let _: PutCursorResponse = self
            .http
            .send(
                Method::PUT,
                &format!("/threads/{thread}/cursor"),
                &PutCursorRequest {
                    last_read_seq: latest,
                },
            )
            .await?;
        self.cache.db.execute(
            "INSERT INTO cursors VALUES(?,?) ON CONFLICT(thread) DO UPDATE SET seq=excluded.seq",
            params![thread.to_string(), latest],
        )?;
        Ok(())
    }
    async fn download(&mut self, attachment: &Attachment) -> Result<PathBuf> {
        attachment.validate()?;
        let mut components = std::path::Path::new(&attachment.name).components();
        if attachment.name.contains(':')
            || !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(user(
                "attachment filename must be a contained, portable path segment",
            ));
        }
        let dir = self
            .store
            .cache_dir(&self.profile)
            .join("blobs")
            .join(attachment.blob_id.to_string());
        private_dir(&dir)?;
        let path = dir.join(&attachment.name);
        // Re-authenticate ciphertext even when a prior plaintext copy exists.
        let blob: DownloadBlobResponse = self
            .http
            .get(&format!("/blobs/{}", attachment.blob_id))
            .await?;
        if blob.blob.id != attachment.blob_id || blob.blob.space_id != self.profile.space_id {
            return Err(user("attachment response crossed scope"));
        }
        let plaintext = decrypt_attachment(
            &attachment.key,
            &Ciphertext {
                nonce: attachment.nonce.clone(),
                ciphertext: blob.ciphertext,
            },
        )?;
        if plaintext.len() as u64 != attachment.size {
            return Err(user("attachment size mismatch"));
        }
        atomic_write(&path, &plaintext)?;
        Ok(path)
    }
    fn addressed_to_me(&self, mentions: &[Mention]) -> bool {
        mentions.iter().any(|m| {
            m.person_id == self.profile.person_id
                && (self.profile.kind == DeviceKind::Gui
                    || m.handle.as_ref().is_none_or(|h| h == &self.handle))
        })
    }
    fn thread_root(&self, message: &Message) -> Result<Message> {
        Ok(match message.envelope.thread_id {
            Some(id) => self.cached_message(id)?.unwrap_or_else(|| message.clone()),
            None => message.clone(),
        })
    }
    fn addressed_to(&self, root: &Message) -> String {
        if root.envelope.mentions.is_empty() {
            return self.channel_name(root.envelope.channel_id);
        }
        root.envelope
            .mentions
            .iter()
            .map(|m| {
                format!(
                    "@{}{}{}",
                    self.person_name(m.person_id),
                    m.handle
                        .as_ref()
                        .map(|h| format!("/{h}"))
                        .unwrap_or_default(),
                    if self.addressed_to_me(std::slice::from_ref(m)) {
                        " (you)"
                    } else {
                        ""
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
    pub async fn inbox(&mut self) -> Result<Vec<InboxEntry>> {
        Ok(self
            .threads()
            .await?
            .into_iter()
            .filter(|entry| entry.unread)
            .collect())
    }
    /// The desktop keeps read threads visible without advancing their read cursors.
    pub async fn threads(&mut self) -> Result<Vec<InboxEntry>> {
        self.begin_operation().await?;
        let messages = self.sync_all().await?;
        let mut threads: BTreeMap<MessageId, Vec<DecodedMessage>> = BTreeMap::new();
        for message in messages {
            threads
                .entry(
                    message
                        .message
                        .envelope
                        .thread_id
                        .unwrap_or(message.message.id),
                )
                .or_default()
                .push(message);
        }
        let mut result = Vec::new();
        for (id, thread) in threads {
            let cursor: u64 = self
                .cache
                .db
                .query_row(
                    "SELECT seq FROM cursors WHERE thread=?",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let latest = thread.last().ok_or_else(|| user("empty thread"))?;
            let root = thread.first().ok_or_else(|| user("empty thread"))?;
            let mentions = (latest.message.seq > cursor
                && self.addressed_to_me(&root.message.envelope.mentions))
                || thread.iter().filter(|m| m.message.seq > cursor).any(|m| {
                    m.message.envelope.mentions.iter().any(|mention| {
                        mention.person_id == self.profile.person_id
                            && (self.profile.kind == DeviceKind::Gui
                                || mention.handle.as_ref().is_none_or(|h| h == &self.handle))
                    })
                });
            let activity = self
                .cache
                .get::<ThreadActivity>(&format!("discovery/{id}"))?;
            result.push(InboxEntry {
                id,
                channel: self.channel_name(root.message.envelope.channel_id),
                to: self.addressed_to(&root.message),
                title: root.content.title.clone().unwrap_or_default(),
                from: format!(
                    "{}/{}",
                    self.person_name(latest.message.author_person),
                    latest.message.envelope.handle
                ),
                created_at: latest.message.created_at,
                summary: thread
                    .iter()
                    .find_map(|m| {
                        m.verification_error
                            .as_ref()
                            .map(|e| format!("VERIFICATION FAILED / CONTENT UNAVAILABLE: {e}"))
                    })
                    .or_else(|| thread.iter().rev().find_map(|m| m.content.summary.clone())),
                foreign_content: thread
                    .iter()
                    .any(|m| m.perspective == MessagePerspective::Other),
                mentioned: mentions,
                unread: latest.message.seq > cursor,
                own_agent_activity: thread.iter().any(|m| {
                    m.message.author_person == self.profile.person_id
                        && m.author_kind == DeviceKind::Cli
                        && m.verification_error.is_none()
                }),
                reactions: thread.iter().flat_map(|m| m.reactions.clone()).collect(),
                latest_message: latest.message.id,
                latest_seq: latest.message.seq,
                channel_id: root.message.envelope.channel_id,
                participants: thread
                    .iter()
                    .map(|m| {
                        format!(
                            "{}/{}",
                            self.person_name(m.message.author_person),
                            m.message.envelope.handle
                        )
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                message_count: thread.len(),
                unread_count: thread.iter().filter(|m| m.message.seq > cursor).count(),
                last_activity: activity
                    .as_ref()
                    .map_or(latest.message.created_at, |a| a.last_activity),
                last_activity_seq: activity
                    .as_ref()
                    .map_or(latest.message.seq, |a| a.last_activity_seq),
            });
        }
        result.sort_by_key(|e| {
            (
                std::cmp::Reverse(e.mentioned),
                std::cmp::Reverse(e.latest_seq),
            )
        });
        Ok(result)
    }
    fn thread_reactions(&self, thread: MessageId) -> Result<Vec<Reaction>> {
        let mut stmt=self.cache.db.prepare("SELECT r.raw FROM reactions r JOIN messages m ON m.id=r.message WHERE m.thread=? ORDER BY m.seq,r.person,r.handle,r.kind")?;
        let raws = stmt
            .query_map([thread.to_string()], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        raws.into_iter()
            .map(|raw| {
                let reaction: Reaction = serde_json::from_str(&raw)?;
                self.directory.verify_reaction(&reaction)?;
                Ok(reaction)
            })
            .collect()
    }
    fn reactions(&self, message: MessageId) -> Result<Vec<Reaction>> {
        let mut stmt = self
            .cache
            .db
            .prepare("SELECT raw FROM reactions WHERE message=?")?;
        let raws = stmt
            .query_map([message.to_string()], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        raws.into_iter()
            .map(|s| {
                let reaction: Reaction = serde_json::from_str(&s)?;
                self.directory.verify_reaction(&reaction)?;
                Ok(reaction)
            })
            .collect()
    }
    fn save_reaction(&mut self, reaction: &Reaction) -> Result<()> {
        let d = &reaction.data;
        let kind = serde_json::to_string(&d.kind)?;
        if d.remove {
            if d.kind == ReactionKind::Claim {
                self.cache.db.execute(
                    "DELETE FROM reactions WHERE message=? AND person=? AND kind=?",
                    params![d.message_id.to_string(), d.person_id.to_string(), kind],
                )?;
            } else {
                self.cache.db.execute(
                    "DELETE FROM reactions WHERE message=? AND person=? AND handle=? AND kind=?",
                    params![
                        d.message_id.to_string(),
                        d.person_id.to_string(),
                        d.handle.as_str(),
                        kind
                    ],
                )?;
            }
        } else {
            self.cache.db.execute("INSERT INTO reactions VALUES(?,?,?,?,?) ON CONFLICT(message,person,handle,kind) DO UPDATE SET raw=excluded.raw", params![d.message_id.to_string(), d.person_id.to_string(), d.handle.as_str(), kind, serde_json::to_string(reaction)?])?;
        }
        let thread: Option<String> = self
            .cache
            .db
            .query_row(
                "SELECT thread FROM messages WHERE id=?",
                [d.message_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(thread) = thread {
            self.cache.activity(
                thread.parse()?,
                &format!("reaction/{}", serde_json::to_string(reaction)?),
            )?;
        }
        Ok(())
    }
    pub async fn react(
        &mut self,
        message: MessageId,
        kind: ReactionKind,
        remove: bool,
    ) -> Result<Reaction> {
        self.begin_operation().await?;
        let reaction = sign_reaction(
            ReactionData {
                space_id: self.profile.space_id,
                message_id: message,
                person_id: self.profile.person_id,
                device_id: self.profile.device_id,
                handle: self.handle.clone(),
                kind,
                created_at: now(),
                remove,
            },
            &self.identity.keys(),
        )?;
        let path = if remove {
            format!(
                "/messages/{message}/reactions/{}",
                serde_json::to_value(kind)?
                    .as_str()
                    .ok_or_else(|| user("invalid reaction"))?
            )
        } else {
            format!("/messages/{message}/reactions")
        };
        let response: Result<ReactionResponse> = self
            .http
            .send(
                if remove { Method::DELETE } else { Method::POST },
                &path,
                &ReactionRequest {
                    reaction: reaction.clone(),
                },
            )
            .await;
        let response = match response {
            Err(Error::ClaimConflict(claim)) => {
                if self.directory.certificate(claim.data.device_id).is_err() {
                    self.refresh().await?;
                }
                self.directory.verify_reaction(&claim)?;
                if claim.data.message_id != message
                    || claim.data.kind != ReactionKind::Claim
                    || claim.data.remove
                {
                    return Err(user("server returned an invalid conflicting claim"));
                }
                return Err(user(format!(
                    "already claimed by {}/{} {}",
                    self.person_name(claim.data.person_id),
                    claim.data.handle,
                    format_last_seen(claim.data.created_at)
                )));
            }
            result => result?,
        };
        self.directory.verify_reaction(&response)?;
        if response != reaction {
            return Err(user("server changed reaction"));
        }
        self.save_reaction(&response)?;
        Ok(response)
    }
    pub async fn unread(&mut self, thread: MessageId) -> Result<()> {
        self.begin_operation().await?;
        let messages = self.load_thread(thread).await?;
        let latest = messages
            .last()
            .ok_or_else(|| user("thread not found"))?
            .message
            .seq;
        let cursor = latest.saturating_sub(1);
        let _: PutCursorResponse = self
            .http
            .send(
                Method::PUT,
                &format!("/threads/{thread}/cursor"),
                &PutCursorRequest {
                    last_read_seq: cursor,
                },
            )
            .await?;
        self.cache.db.execute(
            "INSERT INTO cursors VALUES(?,?) ON CONFLICT(thread) DO UPDATE SET seq=excluded.seq",
            params![thread.to_string(), cursor],
        )?;
        Ok(())
    }
    pub async fn wait(&mut self, seconds: u16) -> Result<Vec<WaitEntry>> {
        self.begin_operation().await?;
        let batch = self.wait_batch(seconds).await?;
        self.advance_wait(&batch.cursor, batch.next_after)?;
        Ok(batch.events)
    }
    /// Finish rendering/downloads before acknowledging messages, so failed reads remain retryable.
    pub async fn wait_text(&mut self, seconds: u16) -> Result<String> {
        self.begin_operation().await?;
        let batch = self.wait_batch(seconds).await?;
        let (output, read) = self.format_wait_entries(&batch.events).await?;
        for (thread, latest) in read {
            self.mark_read(thread, latest).await?;
        }
        self.advance_wait(&batch.cursor, batch.next_after)?;
        Ok(output)
    }
    /// JSON uses the same verified views, downloads and commit boundary as text delivery.
    pub async fn wait_json(&mut self, seconds: u16) -> Result<serde_json::Value> {
        self.begin_operation().await?;
        let batch = self.wait_batch(seconds).await?;
        let mut events = Vec::new();
        let mut read = Vec::new();
        let mut seen = BTreeSet::new();
        for event in &batch.events {
            let value = match event {
                WaitEntry::Message(entry) => {
                    if !seen.insert(entry.id) {
                        continue;
                    }
                    let sequences = batch
                        .events
                        .iter()
                        .filter_map(|e| match e {
                            WaitEntry::Message(e) if e.id == entry.id => Some(e.latest_seq),
                            _ => None,
                        })
                        .collect::<BTreeSet<_>>();
                    let (view, warnings, _) = self.wait_thread(entry, &sequences).await?;
                    read.push((entry.id, sequences.last().copied().unwrap_or(0)));
                    serde_json::json!({"type": "thread", "thread": view.json(), "warnings": warnings})
                }
                WaitEntry::Reaction(notice) => {
                    serde_json::json!({"type": "reaction", "trusted": false, "author": notice.author, "kind": reaction_notice_kind(&notice.reaction), "reference": notice.reference.to_string(), "message_id": notice.reference.id, "thread_id": notice.reference.thread, "title": notice.title, "reaction": notice.reaction})
                }
                WaitEntry::Settings(change) => {
                    serde_json::json!({"type": "settings", "change": change})
                }
                WaitEntry::Revocation(revocation) => {
                    serde_json::json!({"type": "revocation", "revocation": revocation})
                }
                WaitEntry::VerificationFailure { seq, description } => {
                    serde_json::json!({"type": "verification_failure", "seq": seq, "description": description})
                }
            };
            events.push(value);
        }
        let output = serde_json::json!({"schema_version": 1, "command": "wait", "events": events});
        for (thread, seq) in read {
            self.mark_read(thread, seq).await?;
        }
        self.advance_wait(&batch.cursor, batch.next_after)?;
        Ok(output)
    }
    async fn wait_batch(&mut self, seconds: u16) -> Result<WaitBatch> {
        if seconds > 900 {
            return Err(user("wait supports 0–900 seconds"));
        }
        let name = format!("wait/{}", self.handle);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(u64::from(seconds));
        let mut gateway_failures = 0u8;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            // Reverse proxies cut idle upstream responses well under the 900 s the
            // server allows (nginx defaults to 60 s, Cloudflare to 100 s), so one wait
            // is served by several shorter polls against the same deadline.
            let timeout = (remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0))
                .min(u64::from(seconds))
                .min(LONG_POLL_CHUNK_SECS);
            let after = self.cache.get::<u64>(&name)?.unwrap_or(0);
            let mut response: EventsResponse = match self
                .http
                .get(&format!(
                    "/spaces/{}/events?after={after}&timeout={timeout}&handle={}",
                    self.profile.space_id, self.handle
                ))
                .await
            {
                Ok(response) => response,
                // A proxy that drops a poll (502/504) usually recovers at once; retry a
                // few times before giving up so an idle wait survives a proxy restart.
                Err(Error::Server {
                    status: 502..=504, ..
                }) if gateway_failures < GATEWAY_RETRIES
                    && std::time::Instant::now() < deadline =>
                {
                    gateway_failures += 1;
                    tokio::time::sleep(GATEWAY_RETRY_DELAY).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            gateway_failures = 0;
            // Drain an available backlog without another long-poll or a page-sized
            // truncation of what the user is about to read.
            let mut page_len = response.events.len();
            while page_len == MAX_PAGE_SIZE as usize {
                let after = response.events.last().map_or(after, |event| event.seq);
                let page: EventsResponse = self
                    .http
                    .get(&format!(
                        "/spaces/{}/events?after={after}&timeout=0&handle={}",
                        self.profile.space_id, self.handle
                    ))
                    .await?;
                if page.next_after < after
                    || page.events.first().is_some_and(|event| event.seq <= after)
                {
                    return Err(user("server rolled back event cursor"));
                }
                page_len = page.events.len();
                response.next_after = page.next_after;
                response.events.extend(page.events);
            }
            if response.next_after < after {
                return Err(user("server rolled back event cursor"));
            }
            if response.events.is_empty() {
                if std::time::Instant::now() < deadline {
                    continue;
                }
                return Ok(WaitBatch {
                    events: vec![],
                    cursor: name,
                    next_after: after,
                });
            }
            let mut changed = false;
            for event in &response.events {
                changed |= match &event.event {
                    EventData::Message(message) => {
                        self.directory.certificate(message.author_device).is_err()
                            || self
                                .keys
                                .get(&format!(
                                    "channel/{}/{}",
                                    message.envelope.channel_id, message.envelope.epoch
                                ))?
                                .is_none()
                    }
                    EventData::Reaction(reaction) => {
                        self.directory.certificate(reaction.data.device_id).is_err()
                    }
                    EventData::Settings(change) => self
                        .directory
                        .certificate(change.data.issuer_device)
                        .is_err(),
                    EventData::Revocation(revocation) => {
                        !self.directory.revocations().contains(revocation)
                    }
                };
            }
            if changed {
                self.refresh().await?;
            }
            let mut entries = Vec::new();
            let mut previous = after;
            for event in response.events {
                if event.space_id != self.profile.space_id
                    || event.seq <= previous
                    || event.seq > response.next_after
                {
                    return Err(user("invalid event sequence or scope"));
                }
                previous = event.seq;
                let result = match self.process_wait_event(&event).await {
                    Err(
                        error @ (Error::Network(_)
                        | Error::RateLimited(_)
                        | Error::Server { status: 500.., .. }),
                    ) => return Err(error),
                    result => result,
                };
                let error = result.as_ref().err().map(ToString::to_string);
                let unchanged = self
                    .cache
                    .wait_outcome(&self.handle, &event, error.as_deref())?;
                if !unchanged {
                    entries.push(WaitEntry::VerificationFailure {
                        seq: event.seq,
                        description: "server changed a previously observed event".into(),
                    });
                } else {
                    match result {
                        Ok(Some(entry)) => entries.push(entry),
                        Ok(None) => {}
                        Err(error) => entries.push(WaitEntry::VerificationFailure {
                            seq: event.seq,
                            description: error.to_string(),
                        }),
                    }
                }
            }
            // The cursor names only outcomes recorded locally, never an unsigned high-water mark.
            if !entries.is_empty() {
                for entry in &mut entries {
                    if let WaitEntry::Message(entry) = entry {
                        if self.cached_message(entry.id)?.is_none() {
                            if let Ok(root) = self
                                .http
                                .get::<Message>(&format!("/messages/{}", entry.id))
                                .await
                            {
                                let result = (|| -> Result<()> {
                                    if root.id != entry.id || root.envelope.thread_id.is_some() {
                                        return Err(user("root lookup changed thread"));
                                    }
                                    let author = self.directory.verify_message(&root)?;
                                    let content = decrypt_message(
                                        &self.key(root.envelope.channel_id, root.envelope.epoch)?,
                                        &author,
                                        &root.envelope,
                                        &root.signature,
                                    )?;
                                    self.cache.message(&root, &content)?;
                                    self.cache.number(&root, 1)
                                })();
                                if let Err(error) = result {
                                    self.cache.set(
                                        &format!("wait-reference/{}", entry.id),
                                        &error.to_string(),
                                    )?;
                                }
                            }
                        }
                        if let Some(root) = self.cached_message(entry.id)? {
                            entry.to = self.addressed_to(&root);
                            entry.mentioned = self.addressed_to_me(&root.envelope.mentions);
                        }
                        entry.reactions = self.thread_reactions(entry.id)?;
                    }
                }
                entries.sort_by_key(|e| !matches!(e, WaitEntry::Message(entry) if entry.mentioned));
                return Ok(WaitBatch {
                    events: entries,
                    cursor: name,
                    next_after: previous,
                });
            }
            self.advance_wait(&name, previous)?;
            if std::time::Instant::now() >= deadline {
                return Ok(WaitBatch {
                    events: entries,
                    cursor: name,
                    next_after: previous,
                });
            }
            // Ignored self-events still consume the cursor; keep waiting for someone else
            // with the original deadline, rather than returning a false notification.
        }
    }
    async fn process_wait_event(&mut self, event: &Event) -> Result<Option<WaitEntry>> {
        let entry = match event.event.clone() {
            EventData::Message(message) => {
                if message.seq != event.seq {
                    return Err(user("message/event sequence mismatch"));
                }
                let author = self.directory.verify_message(&message)?;
                let content = decrypt_message(
                    &self.key(message.envelope.channel_id, message.envelope.epoch)?,
                    &author,
                    &message.envelope,
                    &message.signature,
                )?;
                self.cache.message(&message, &content)?;
                let thread = message.envelope.thread_id.unwrap_or(message.id);
                let already_read = self
                    .cache
                    .get::<Seq>(&format!("read/{}/{thread}", self.handle))?
                    .unwrap_or(0);
                if message.seq <= already_read {
                    return Ok(None);
                }
                if message.author_person == self.profile.person_id
                    && !message.envelope.mentions.iter().any(|mention| {
                        mention.person_id == self.profile.person_id
                            && mention.handle.as_ref() == Some(&self.handle)
                    })
                {
                    return Ok(None);
                }
                if message.envelope.thread_id.is_none() {
                    self.cache.number(&message, 1)?;
                }
                let root = self.thread_root(&message)?;
                WaitEntry::Message(InboxEntry {
                    id: message.envelope.thread_id.unwrap_or(message.id),
                    channel: self.channel_name(message.envelope.channel_id),
                    to: self.addressed_to(&root),
                    title: content.title.unwrap_or_else(|| {
                        format!(
                            "reply to {}",
                            message
                                .envelope
                                .thread_id
                                .map(|id| id.to_string())
                                .unwrap_or_default()
                        )
                    }),
                    from: format!(
                        "{}/{}",
                        self.person_name(message.author_person),
                        message.envelope.handle
                    ),
                    created_at: message.created_at,
                    summary: content.summary,
                    foreign_content: message.author_person != self.profile.person_id
                        || root.author_person != self.profile.person_id,
                    mentioned: self.addressed_to_me(&root.envelope.mentions),
                    unread: true,
                    own_agent_activity: message.author_person == self.profile.person_id
                        && author.certificate().data.kind == DeviceKind::Cli,
                    reactions: self.thread_reactions(root.id)?,
                    latest_message: message.id,
                    latest_seq: message.seq,
                    channel_id: message.envelope.channel_id,
                    participants: vec![],
                    message_count: 0,
                    unread_count: 1,
                    last_activity: message.created_at,
                    last_activity_seq: message.seq,
                })
            }
            EventData::Reaction(reaction) => {
                self.directory.verify_reaction(&reaction)?;
                self.save_reaction(&reaction)?;
                if reaction.data.person_id == self.profile.person_id
                    || !matches!(
                        (reaction.data.kind, reaction.data.remove),
                        (ReactionKind::Ack, false) | (ReactionKind::Claim, _)
                    )
                {
                    return Ok(None);
                }
                let target = match self.cached_message(reaction.data.message_id)? {
                    Some(message) => message,
                    None => {
                        self.http
                            .get(&format!("/messages/{}", reaction.data.message_id))
                            .await?
                    }
                };
                if target.id != reaction.data.message_id {
                    return Err(user("reaction target lookup changed message"));
                }
                self.directory.verify_message(&target)?;
                let thread = target.envelope.thread_id.unwrap_or(target.id);
                if target.author_person != self.profile.person_id {
                    return Ok(None);
                }
                let history = self.load_thread(thread).await?;
                let message = history
                    .iter()
                    .find(|message| {
                        message.message.id == target.id && message.verification_error.is_none()
                    })
                    .ok_or_else(|| user("reaction target is unavailable or unverifiable"))?;
                let title = history
                    .first()
                    .and_then(|message| message.content.title.clone())
                    .ok_or_else(|| user("reaction thread title unavailable"))?;
                WaitEntry::Reaction(ReactionNotice {
                    author: format!(
                        "{}/{}",
                        self.person_name(reaction.data.person_id),
                        reaction.data.handle
                    ),
                    reference: message.reference(),
                    title,
                    reaction,
                })
            }
            EventData::Settings(change) => {
                self.settings = self.cache.accept_settings(&self.directory, &change)?;
                WaitEntry::Settings(change)
            }
            EventData::Revocation(revocation) => {
                if !self.directory.revocations().contains(&revocation) {
                    return Err(user("unverified revocation event"));
                }
                WaitEntry::Revocation(revocation)
            }
        };
        Ok(Some(entry))
    }
    fn advance_wait(&self, name: &str, sequence: u64) -> Result<()> {
        self.cache.db.execute("INSERT INTO state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=CAST(MAX(CAST(state.value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)", params![name, sequence.to_string()])?;
        Ok(())
    }
    pub async fn group_create(&mut self, name: &str, persons: &[String]) -> Result<ChannelId> {
        validate_name(name)?;
        self.begin_operation().await?;
        if name == "all"
            || self
                .channels
                .iter()
                .any(|c| c.channel.kind == ChannelKind::Group && c.meta.name == name)
        {
            return Err(user("group name already exists"));
        }
        let mut members = vec![self.profile.person_id];
        for person in persons {
            members.push(self.person(person)?);
        }
        self.new_channel(ChannelKind::Group, name, members).await
    }
    async fn update_channel(
        &mut self,
        channel: &Channel,
        meta: ChannelMeta,
        members: Vec<PersonId>,
    ) -> Result<Channel> {
        self.publish_channel(channel, meta, members, false).await
    }
    async fn publish_channel(
        &mut self,
        channel: &Channel,
        mut meta: ChannelMeta,
        members: Vec<PersonId>,
        rekey: bool,
    ) -> Result<Channel> {
        meta.members = members.clone();
        let rotating = rekey || channel.members != members;
        let key = if rotating {
            self.key(channel.id, channel.current_epoch)?
                .rotate(&mut entropy)?
        } else {
            self.key(channel.id, channel.current_epoch)?
        };
        let membership = sign_membership(
            ChannelMembershipData {
                previous: Some(channel.membership.signature.clone()),
                space_id: self.profile.space_id,
                channel_id: channel.id,
                epoch: key.epoch(),
                key_commitment: key.commitment(),
                kind: channel.kind,
                members: members.clone(),
                issuer_device: self.profile.device_id,
            },
            &self.identity.keys(),
        )?;
        let verified = self
            .directory
            .verify_membership(&membership, Some(&channel.membership))?;
        let mut wrapped_keys = Vec::new();
        if rotating {
            for device in self.directory.active_devices() {
                if members.contains(&device.certificate().data.person_id) {
                    wrapped_keys.push(wrap_channel_key(&key, &device, &verified, &mut entropy)?);
                }
            }
        }
        let meta = encrypt_channel_metadata(&key, &serde_json::to_vec(&meta)?, &mut entropy)?;
        let response: UpdateChannelResponse = self
            .http
            .send(
                Method::PATCH,
                &format!("/channels/{}", channel.id),
                &UpdateChannelRequest {
                    wrapped_keys,
                    membership: membership.clone(),
                    epoch: key.epoch(),
                    meta,
                    members,
                },
            )
            .await?;
        if response.id != channel.id || response.membership != membership {
            return Err(user("server changed membership publication"));
        }
        self.cache.channel(&self.directory, &response)?;
        if rotating {
            save_channel_key(self.keys.as_ref(), &key)?;
        }
        Ok(response)
    }
    pub async fn group_member(&mut self, name: &str, person: &str, remove: bool) -> Result<()> {
        self.begin_operation().await?;
        let person = self.person(person)?;
        let channel = self
            .channels
            .iter()
            .find(|c| {
                c.channel.kind == ChannelKind::Group && c.meta.name == name.trim_start_matches('#')
            })
            .cloned()
            .ok_or_else(|| user("group not found"))?;
        let mut members = channel.channel.members.clone();
        if remove {
            members.retain(|p| *p != person);
        } else if !members.contains(&person) {
            members.push(person);
        }
        members.sort();
        if !members.contains(&self.profile.person_id) {
            return Err(user(
                "cannot remove yourself while responsible for the key rotation",
            ));
        }
        self.update_channel(&channel.channel, channel.meta, members)
            .await?;
        self.refresh().await
    }
    async fn ensure_safe_epoch(&mut self, channel_id: ChannelId) -> Result<()> {
        let named = self
            .channels
            .iter()
            .find(|c| c.channel.id == channel_id)
            .cloned()
            .ok_or_else(|| user("channel missing"))?;
        let protected: BTreeSet<Signature> = self
            .cache
            .get(&format!("protected/{channel_id}"))?
            .unwrap_or_default();
        let mut relevant = false;
        for revocation in self.directory.revocations() {
            if protected.contains(&revocation.signature) {
                continue;
            }
            let person = self.revoked_person(&revocation.data.target)?;
            relevant |= named.channel.members.contains(&person);
        }
        if !relevant {
            return Ok(());
        }
        let removed: BTreeSet<_> = self
            .directory
            .revocations()
            .iter()
            .filter_map(|r| match r.data.target {
                RevocationTarget::Person { person_id } => Some(person_id),
                _ => None,
            })
            .collect();
        let original_epoch = named.channel.current_epoch;
        let channel = if named.channel.kind == ChannelKind::Group
            && named.channel.members.iter().any(|p| removed.contains(p))
        {
            let members = named
                .channel
                .members
                .iter()
                .filter(|p| !removed.contains(p))
                .copied()
                .collect();
            self.update_channel(&named.channel, named.meta, members)
                .await?
        } else {
            named.channel
        };
        // An issuer may not know another person's private groups. Their remaining members
        // must rekey before sending, even if another client may already have rotated once.
        if channel.current_epoch == original_epoch {
            self.rotate(&channel).await?;
        } else {
            self.mark_protected(channel.id)?;
        }
        self.refresh().await
    }
    fn revoked_person(&self, target: &RevocationTarget) -> Result<PersonId> {
        Ok(match target {
            RevocationTarget::Person { person_id } => *person_id,
            RevocationTarget::Device { device_id } => {
                self.directory.certificate(*device_id)?.data.person_id
            }
        })
    }
    fn mark_protected(&self, channel: ChannelId) -> Result<()> {
        let protected: BTreeSet<_> = self
            .directory
            .revocations()
            .iter()
            .map(|r| r.signature.clone())
            .collect();
        self.cache.set(&format!("protected/{channel}"), &protected)
    }
    async fn publish_pending_revocations(&mut self) -> Result<bool> {
        let pending: Vec<String> = self
            .cache
            .db
            .prepare("SELECT raw FROM pending_revocations ORDER BY rowid")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        for raw in &pending {
            let revocation: Revocation = serde_json::from_str(raw)?;
            let response: CreateRevocationResponse = self
                .http
                .send(
                    Method::POST,
                    &format!("/spaces/{}/revocations", self.profile.space_id),
                    &CreateRevocationRequest {
                        revocation: revocation.clone(),
                    },
                )
                .await?;
            if response != revocation {
                return Err(user("server changed signed revocation"));
            }
            self.cache
                .db
                .execute("DELETE FROM pending_revocations WHERE raw=?", [raw])?;
        }
        Ok(!pending.is_empty())
    }
    async fn resume_rotations(&mut self) -> Result<()> {
        let channels: Vec<_> = self.channels.clone();
        let mut first_error = None;
        for named in channels {
            let result = async { self.ensure_safe_epoch(named.channel.id).await }.await;
            if let Err(error) = result {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }
    async fn rotate(&mut self, channel: &Channel) -> Result<()> {
        let meta: ChannelMeta = serde_json::from_slice(&decrypt_channel_metadata(
            &self.key(channel.id, channel.current_epoch)?,
            &channel.meta,
        )?)?;
        self.publish_channel(channel, meta, channel.members.clone(), true)
            .await?;
        self.mark_protected(channel.id)?;
        Ok(())
    }
    pub async fn revoke(&mut self, target: RevocationTarget) -> Result<()> {
        self.begin_operation().await?;
        self.revoked_person(&target)?;
        if matches!(target, RevocationTarget::Device { device_id } if device_id == self.profile.device_id)
            || matches!(target, RevocationTarget::Person { person_id } if person_id == self.profile.person_id)
        {
            return Err(user(
                "use another device/person to revoke this device so it can finish key rotation",
            ));
        }
        let root = &self.directory.root().data;
        if matches!(target, RevocationTarget::Device { device_id } if device_id == root.device_id)
            || matches!(target, RevocationTarget::Person { person_id } if person_id == root.person_id)
        {
            return Err(user(
                "the space root cannot be revoked: every certificate chains to it; create a new space instead",
            ));
        }
        let revocation = sign_revocation(
            RevocationData {
                space_id: self.profile.space_id,
                target: target.clone(),
                issuer_device: self.profile.device_id,
                created_at: now(),
            },
            &self.identity.keys(),
        )?;
        self.directory = self.cache.record_revocation(&self.directory, &revocation)?;
        self.publish_pending_revocations().await?;
        self.refresh().await?;
        self.resume_rotations().await?;
        self.refresh().await
    }
    pub async fn set_settings(&mut self, key: &str, value: &str) -> Result<SettingsChange> {
        self.begin_operation().await?;
        let mut settings = self.settings.clone();
        match key {
            "retention" | "retention_days" => {
                settings.retention_days = value
                    .parse()
                    .map_err(|_| user("retention must be a number of days (0 means forever)"))?
            }
            "summary_mode" => {
                settings.summary_mode = match value {
                    "off" => SummaryMode::Off,
                    "required" => SummaryMode::Required,
                    _ => return Err(user("summary_mode must be required or off")),
                }
            }
            "summary_every" => {
                settings.summary_every = value
                    .parse()
                    .map_err(|_| user("summary_every must be a positive integer"))?;
            }
            _ => {
                return Err(user(
                    "setting must be retention_days, summary_mode or summary_every",
                ));
            }
        }
        let change = sign_settings(
            SettingsChangeData {
                space_id: self.profile.space_id,
                issuer_device: self.profile.device_id,
                created_at: now(),
                settings,
            },
            &self.identity.keys(),
        )?;
        let response: UpdateSettingsResponse = self
            .http
            .send(
                Method::PATCH,
                &format!("/spaces/{}/settings", self.profile.space_id),
                &UpdateSettingsRequest {
                    change: change.clone(),
                },
            )
            .await?;
        self.directory.verify_settings(&response)?;
        if response != change {
            return Err(user("server changed settings event"));
        }
        self.settings = self.cache.accept_settings(&self.directory, &response)?;
        Ok(response)
    }
    fn decode_cached_message(&self, message: Message) -> Result<DecodedMessage> {
        let author = self.directory.verify_message(&message)?;
        let content = decrypt_message(
            &self.key(message.envelope.channel_id, message.envelope.epoch)?,
            &author,
            &message.envelope,
            &message.signature,
        )?;
        Ok(DecodedMessage {
            number: self.cached_reference(message.id)?.map_or(0, |r| r.number),
            perspective: self.perspective(&message),
            reactions: self.reactions(message.id)?,
            author_kind: author.certificate().data.kind,
            message,
            content,
            attachments: vec![],
            verification_error: None,
        })
    }
    pub async fn search(&mut self, text: &str) -> Result<Vec<DecodedMessage>> {
        self.opening_snapshot = false;
        self.directory = self
            .cache
            .get::<PinnedTrustState>("trust")?
            .ok_or_else(|| user("local trust state missing"))?
            .verify(self.profile.space_id, now())?;
        let mut stmt = self.cache.db.prepare("SELECT raw FROM messages WHERE instr(lower(COALESCE(json_extract(content,'$.title'),'') || char(10) || json_extract(content,'$.body') || char(10) || COALESCE(json_extract(content,'$.summary'),'')),lower(?))>0 ORDER BY seq")?;
        let rows = stmt
            .query_map([text], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut result = Vec::new();
        for raw in rows {
            result.push(self.decode_cached_message(serde_json::from_str(&raw)?)?);
        }
        Ok(result)
    }

    pub async fn who_view(&mut self) -> Result<DirectoryView> {
        self.begin_operation().await?;
        let people = self
            .names()
            .into_iter()
            .map(|(id, name)| PersonView {
                id,
                name,
                devices: self
                    .devices
                    .iter()
                    .filter(|d| d.cert.data.person_id == id)
                    .map(|d| DeviceView {
                        id: d.cert.data.device_id,
                        kind: d.cert.data.kind,
                        last_seen_at: d.last_seen_at,
                        last_seen: d
                            .last_seen_at
                            .map(format_last_seen)
                            .unwrap_or_else(|| "never".into()),
                        revoked: d.revoked_at.is_some(),
                    })
                    .collect(),
            })
            .collect();
        let mut stmt = self.cache.db.prepare("SELECT DISTINCT json_extract(raw,'$.author_person'),json_extract(raw,'$.envelope.handle') FROM messages WHERE created>? ORDER BY 1,2")?;
        let mut handles = Vec::new();
        for row in stmt.query_map([now().saturating_sub(7 * 86400)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })? {
            let (person, handle) = row?;
            handles.push(format!("{}/{handle}", self.person_name(person.parse()?)));
        }
        Ok(DirectoryView { people, handles })
    }
    pub async fn who(&mut self) -> Result<String> {
        Ok(self.who_view().await?.text())
    }
    pub async fn discover_threads(&mut self, destination: Option<&str>) -> Result<Vec<InboxEntry>> {
        let mut threads = self.threads().await?;
        let channel_id = if let Some(to) = destination {
            if let Some(name) = to.strip_prefix('#') {
                Some(
                    self.channels
                        .iter()
                        .find(|c| {
                            matches!(c.channel.kind, ChannelKind::All | ChannelKind::Group)
                                && c.meta.name == name
                        })
                        .ok_or_else(|| user("channel not found"))?
                        .channel
                        .id,
                )
            } else if let Some(person) = to.strip_prefix('@') {
                let person = self.person(person)?;
                let kind = if person == self.profile.person_id {
                    ChannelKind::SelfChannel
                } else {
                    ChannelKind::Dm
                };
                self.channels
                    .iter()
                    .find(|c| c.channel.kind == kind && c.channel.members.contains(&person))
                    .map(|c| c.channel.id)
            } else {
                return Err(user("threads expects #channel or @person"));
            }
        } else {
            None
        };
        if destination.is_some() {
            threads.retain(|t| Some(t.channel_id) == channel_id);
        }
        threads.sort_by_key(|t| std::cmp::Reverse((t.last_activity_seq, t.latest_seq)));
        Ok(threads)
    }
    pub async fn channel_views(&mut self) -> Result<Vec<ChannelView>> {
        let threads = self.threads().await?;
        Ok(self
            .channels
            .iter()
            .map(|c| ChannelView {
                id: c.channel.id,
                name: self.channel_name(c.channel.id),
                kind: c.channel.kind,
                members: c
                    .channel
                    .members
                    .iter()
                    .map(|p| format!("@{}", self.person_name(*p)))
                    .collect(),
                unread_threads: threads
                    .iter()
                    .filter(|t| t.channel_id == c.channel.id && t.unread)
                    .count(),
                unread_messages: threads
                    .iter()
                    .filter(|t| t.channel_id == c.channel.id)
                    .map(|t| t.unread_count)
                    .sum(),
            })
            .collect())
    }
}

fn channel_request(
    cert: &DeviceCertificate,
    keys: &DeviceKeys,
    directory: &VerifiedDirectory,
    kind: ChannelKind,
    meta: &ChannelMeta,
) -> Result<(CreateChannelRequest, ChannelKey)> {
    let id = ChannelId::from_bytes(random_id(&mut entropy)?);
    let key = ChannelKey::generate(cert.data.space_id, id, &mut entropy)?;
    let membership = sign_membership(
        ChannelMembershipData {
            previous: None,
            space_id: cert.data.space_id,
            channel_id: id,
            epoch: 0,
            key_commitment: key.commitment(),
            kind,
            members: meta.members.clone(),
            issuer_device: cert.data.device_id,
        },
        keys,
    )?;
    let verified = directory.verify_membership(&membership, None)?;
    let mut wrapped_keys = Vec::new();
    for device in directory.active_devices() {
        if verified
            .members()
            .contains(&device.certificate().data.person_id)
        {
            wrapped_keys.push(wrap_channel_key(&key, &device, &verified, &mut entropy)?);
        }
    }
    let encrypted = encrypt_channel_metadata(&key, &serde_json::to_vec(meta)?, &mut entropy)?;
    Ok((
        CreateChannelRequest {
            membership,
            id,
            space_id: cert.data.space_id,
            kind,
            meta: encrypted,
            members: meta.members.clone(),
            wrapped_keys,
        },
        key,
    ))
}
fn save_channel_key(store: &dyn KeyStore, key: &ChannelKey) -> Result<()> {
    let account = format!("channel/{}/{}", key.channel_id(), key.epoch());
    let secret = KeyBytes::from_bytes(*key.export_secret());
    if let Some(old) = store.get(&account)? {
        let old: KeyBytes = serde_json::from_slice(&old)?;
        if old != secret {
            return Err(user("server changed an accepted channel epoch key"));
        }
        return Ok(());
    }
    store_json(store, &account, &secret)
}
fn validate_meta(channel: &Channel, meta: &ChannelMeta, person: PersonId) -> Result<()> {
    validate_name(&meta.name)?;
    validate_name(&meta.space_name)?;
    if channel.kind != ChannelKind::All
        && meta.members.iter().copied().collect::<BTreeSet<_>>()
            != channel.members.iter().copied().collect()
    {
        return Err(user(
            "encrypted channel peer context differs from signed roster",
        ));
    }
    if !channel.members.contains(&person)
        || (channel.kind == ChannelKind::All && meta.name != "all")
        || (channel.kind == ChannelKind::SelfChannel && channel.members != vec![person])
        || (channel.kind == ChannelKind::Dm && channel.members.len() != 2)
    {
        return Err(user("channel context does not match expected peers"));
    }
    let mut names = BTreeSet::new();
    for name in meta.people.values() {
        validate_name(name)?;
        if !names.insert(name) {
            return Err(user("duplicate encrypted person name"));
        }
    }
    Ok(())
}
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
    {
        return Err(user(
            "name must use lowercase letters, numbers, -, _ or . (1–255 characters)",
        ));
    }
    Ok(())
}
fn unique_slug(name: &str, people: &BTreeMap<PersonId, String>) -> String {
    let base: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(220)
        .collect();
    let base = if base.is_empty() {
        "person".into()
    } else {
        base
    };
    let mut candidate = base.clone();
    let mut suffix = 2;
    while people.values().any(|n| n == &candidate) {
        candidate = format!("{base}-{suffix}");
        suffix += 1;
    }
    candidate
}
fn mime(name: &str, bytes: &[u8]) -> &'static str {
    match name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "py" | "pyw" | "pyi" => "text/x-python",
        "txt" | "md" | "toml" | "rs" | "ts" | "tsx" | "js" | "jsx" | "yaml" | "yml" | "sh"
        | "css" | "csv" | "log" | "ini" | "cfg" => "text/plain",
        "html" | "htm" => "text/html",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        _ if std::str::from_utf8(bytes).is_ok_and(|text| {
            text.chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        }) =>
        {
            "text/plain"
        }
        _ => "application/octet-stream",
    }
}
async fn run_summarizer(command: &str, input: &str) -> Result<String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    #[cfg(windows)]
    let mut process = {
        let mut p = tokio::process::Command::new("cmd");
        p.arg("/C").arg(command);
        p
    };
    #[cfg(not(windows))]
    let mut process = {
        let mut p = tokio::process::Command::new("sh");
        p.arg("-c").arg(command);
        p
    };
    let mut child = process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| user("summarizer stdin unavailable"))?;
    let writer = async {
        stdin.write_all(input.as_bytes()).await?;
        drop(stdin);
        std::io::Result::Ok(())
    };
    let (written, output) = tokio::join!(writer, child.wait_with_output());
    // Constant commands (explicitly supported by the spec) may successfully close stdin early.
    if let Err(error) = written {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(error.into());
        }
    }
    let output = output?;
    if !output.status.success() {
        return Err(user(format!("summarizer failed: {}", output.status)));
    }
    let summary = String::from_utf8(output.stdout)
        .map_err(|_| user("summarizer output is not UTF-8"))?
        .trim()
        .to_owned();
    if summary.is_empty() {
        return Err(user("summarizer returned an empty summary"));
    }
    Ok(summary)
}

fn validate_key(key: &ChannelKey, epochs: &BTreeMap<Epoch, PublicKey>) -> Result<()> {
    if epochs.get(&key.epoch()) != Some(&key.commitment()) {
        return Err(user(
            "channel key does not match an authenticated epoch commitment",
        ));
    }
    Ok(())
}
