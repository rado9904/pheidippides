use phi_crypto::*;
use phi_proto::*;
use serde_json::{Value, json};

struct TestEntropy {
    seed: u8,
    counter: u64,
}
impl Entropy for TestEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in bytes.chunks_mut(32) {
            let mut input = vec![self.seed];
            input.extend_from_slice(&self.counter.to_le_bytes());
            self.counter += 1;
            let hash = blake3::hash(&input);
            chunk.copy_from_slice(&hash.as_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
struct Fixture {
    entropy: TestEntropy,
    keys: DeviceKeys,
    bundle: TrustBundle,
}
impl Fixture {
    fn new() -> Result<Self, CryptoError> {
        let mut entropy = TestEntropy {
            seed: 42,
            counter: 0,
        };
        let keys = DeviceKeys::generate(&mut entropy)?;
        let device_id = DeviceId::from_bytes([1; 16]);
        let root = certify_device(
            DeviceCertificateData {
                space_id: space_id(&keys.sign_public()),
                person_id: PersonId::from_bytes([1; 16]),
                device_id,
                kind: DeviceKind::Cli,
                sign_pub: keys.sign_public(),
                kex_pub: keys.kex_public(),
                created_at: 10,
                issuer: CertificateIssuer::Device { device_id },
            },
            &keys,
        )?;
        Ok(Self {
            entropy,
            keys,
            bundle: TrustBundle {
                root,
                certificates: vec![],
                grants: vec![],
                revocations: vec![],
            },
        })
    }
    fn space(&self) -> SpaceId {
        self.bundle.root.data.space_id
    }
    fn root(&self) -> DeviceId {
        self.bundle.root.data.device_id
    }
    fn directory(&self) -> Result<VerifiedDirectory, CryptoError> {
        verify_trust_bundle(self.space(), &self.bundle, 100, None)
    }
    fn channel(&mut self) -> Result<ChannelKey, CryptoError> {
        ChannelKey::generate(
            self.space(),
            ChannelId::from_bytes([1; 16]),
            &mut self.entropy,
        )
    }
    fn member(&mut self) -> Result<(DeviceKeys, GrantKeys), CryptoError> {
        let grant = GrantSecret::generate(&mut self.entropy)?.derive()?;
        let record = sign_grant(
            GrantRecordData {
                space_id: self.space(),
                grant_id: grant.id(),
                grant_pub: grant.public(),
                kind: GrantKind::Invite,

                person_id: PersonId::from_bytes([2; 16]),
                created_at: 20,
                expires_at: Some(90),
                issuer_device: self.root(),
            },
            &self.keys,
        )?;
        let keys = DeviceKeys::generate(&mut self.entropy)?;
        let cert = certify_with_grant(
            DeviceCertificateData {
                space_id: self.space(),
                person_id: record.data.person_id,
                device_id: DeviceId::from_bytes([2; 16]),
                kind: DeviceKind::Gui,
                sign_pub: keys.sign_public(),
                kex_pub: keys.kex_public(),
                created_at: 30,
                issuer: CertificateIssuer::Grant {
                    grant_id: grant.id(),
                },
            },
            &grant,
        )?;
        self.bundle.grants.push(record);
        self.bundle.certificates.push(cert);
        Ok((keys, grant))
    }
}
fn content() -> MessageContent {
    MessageContent {
        title: Some("Review API".into()),
        body: "Please review commit abc.".into(),
        summary: Some("Review requested.".into()),
        attachments: vec![],
        display_name: "Vladko".into(),
    }
}
fn metadata() -> Result<MessageMetadata, CryptoError> {
    Ok(MessageMetadata {
        id: MessageId::from_bytes([1; 16]),
        summary_covers_seq: Some(0),
        thread_id: None,
        handle: "main".parse()?,
        mentions: vec![Mention {
            person_id: PersonId::from_bytes([2; 16]),
            handle: Some("reviewer".parse()?),
        }],
    })
}
fn tamper(bytes: &Base64Bytes) -> Base64Bytes {
    let mut bytes = bytes.as_bytes().to_vec();
    bytes[0] ^= 1;
    Base64Bytes::new(bytes)
}

#[test]
fn sealed_boxes_bind_recipient_context_and_all_fields() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let other = DeviceKeys::generate(&mut f.entropy)?;
    for payload in [vec![], vec![7; 8192]] {
        let sealed = seal(
            &f.keys.kex_public(),
            &payload,
            b"channel epoch device",
            &mut f.entropy,
        )?;
        assert_eq!(
            unseal(&f.keys, &sealed, b"channel epoch device")?.as_slice(),
            payload
        );
        assert!(unseal(&other, &sealed, b"channel epoch device").is_err());
        assert!(unseal(&f.keys, &sealed, b"other context").is_err());
        let mut changed = sealed.clone();
        changed.ciphertext = tamper(&changed.ciphertext);
        assert!(unseal(&f.keys, &changed, b"channel epoch device").is_err());
        changed = sealed.clone();
        changed.nonce = Nonce::from_bytes([0; 24]);
        assert!(unseal(&f.keys, &changed, b"channel epoch device").is_err());
        changed = sealed;
        changed.ephemeral_pub = other.kex_public();
        assert!(unseal(&f.keys, &changed, b"channel epoch device").is_err());
    }
    assert!(seal(&PublicKey::from_bytes([0; 32]), b"x", b"", &mut f.entropy).is_err());
    assert!(
        seal(
            &PublicKey::from_bytes({
                let mut p = [0; 32];
                p[0] = 1;
                p
            }),
            b"x",
            b"",
            &mut f.entropy
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn messages_roundtrip_and_authenticate_every_spec_field() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let channel = f.channel()?;
    let author = f.directory()?.device(f.root())?;
    let (envelope, signature) =
        encrypt_message(&channel, &f.keys, metadata()?, &content(), &mut f.entropy)?;
    assert_eq!(
        decrypt_message(&channel, &author, &envelope, &signature)?,
        content()
    );
    let stored = Message {
        id: MessageId::from_bytes([1; 16]),
        envelope: envelope.clone(),
        author_person: PersonId::from_bytes([1; 16]),
        author_device: f.root(),
        signature: signature.clone(),
        seq: 1,
        created_at: 40,
        has_summary: true,
        summary_covers_seq: Some(0),
    };
    f.directory()?.verify_message(&stored)?;
    let mut replay = stored.clone();
    replay.id = MessageId::from_bytes([9; 16]);
    assert!(f.directory()?.verify_message(&replay).is_err());
    replay = stored.clone();
    replay.summary_covers_seq = Some(999);
    assert!(f.directory()?.verify_message(&replay).is_err());
    let mut wrong_author = stored;
    wrong_author.author_person = PersonId::from_bytes([8; 16]);
    assert!(f.directory()?.verify_message(&wrong_author).is_err());
    let golden = MessageEnvelope {
        id: MessageId::from_bytes([0; 16]),
        summary_covers_seq: Some(0),
        space_id: SpaceId::from_bytes([0; 16]),
        channel_id: ChannelId::from_bytes([0; 16]),
        thread_id: None,
        epoch: 0,
        handle: "main".parse()?,
        mentions: vec![],
        nonce: Nonce::from_bytes([0; 24]),
        ciphertext: Base64Bytes::new(vec![0; 16]),
    };
    assert_eq!(message_signing_bytes(&golden)?, br#"["phi message v1",["AAAAAAAAAAAAAAAAAAAAAA",0,"AAAAAAAAAAAAAAAAAAAAAA","AAAAAAAAAAAAAAAAAAAAAA",null,0,"main",[],"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","AAAAAAAAAAAAAAAAAAAAAA"]]"#);
    let mut variations = Vec::new();
    let mut e = envelope.clone();
    e.id = MessageId::from_bytes([9; 16]);
    variations.push(e);
    let mut e = envelope.clone();
    e.summary_covers_seq = Some(999);
    variations.push(e);
    let mut e = envelope.clone();
    e.summary_covers_seq = None;
    variations.push(e);

    let mut e = envelope.clone();
    e.space_id = SpaceId::from_bytes([9; 16]);
    variations.push(e);
    let mut e = envelope.clone();
    e.channel_id = ChannelId::from_bytes([9; 16]);
    variations.push(e);
    let mut e = envelope.clone();
    e.thread_id = Some(MessageId::from_bytes([9; 16]));
    variations.push(e);
    let mut e = envelope.clone();
    e.epoch += 1;
    variations.push(e);
    let mut e = envelope.clone();
    e.handle = "other".parse()?;
    variations.push(e);
    let mut e = envelope.clone();
    e.mentions[0].person_id = PersonId::from_bytes([9; 16]);
    variations.push(e);
    let mut e = envelope.clone();
    e.mentions[0].handle = None;
    variations.push(e);
    let mut e = envelope.clone();
    e.nonce = Nonce::from_bytes([0; 24]);
    variations.push(e);
    let mut e = envelope.clone();
    e.ciphertext = tamper(&e.ciphertext);
    variations.push(e);
    for changed in variations {
        assert!(verify_message_signature(&f.keys.sign_public(), &changed, &signature).is_err());
        assert!(decrypt_message(&channel, &author, &changed, &signature).is_err());
    }
    assert!(
        decrypt_message(
            &channel,
            &author,
            &envelope,
            &Signature::from_bytes([0; 64])
        )
        .is_err()
    );
    let mut reply = content();
    reply.title = None;
    let mut meta = metadata()?;
    meta.thread_id = Some(MessageId::from_bytes([3; 16]));
    let (e, s) = encrypt_message(&channel, &f.keys, meta, &reply, &mut f.entropy)?;
    assert_eq!(decrypt_message(&channel, &author, &e, &s)?, reply);
    Ok(())
}

#[test]
fn attachment_encryption_is_independent_and_detects_corruption() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    for plaintext in [vec![], vec![255; 256 * 1024]] {
        let (key, encrypted) = encrypt_attachment(&plaintext, &mut f.entropy)?;
        assert_eq!(decrypt_attachment(&key, &encrypted)?.as_slice(), plaintext);
        assert!(decrypt_attachment(&KeyBytes::from_bytes([0; 32]), &encrypted).is_err());
        let mut bad = encrypted.clone();
        bad.ciphertext = tamper(&bad.ciphertext);
        assert!(decrypt_attachment(&key, &bad).is_err());
        bad = encrypted;
        bad.nonce = Nonce::from_bytes([0; 24]);
        assert!(decrypt_attachment(&key, &bad).is_err());
    }
    Ok(())
}

#[test]
fn epoch_rotation_keeps_history_and_binds_wrapped_key_routing() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let (member_keys, _) = f.member()?;
    let old = f.channel()?;
    let next = old.rotate(&mut f.entropy)?;
    assert_eq!(next.epoch(), 1);
    assert_ne!(*next.export_secret(), *old.export_secret());
    let member = f.directory()?.device(DeviceId::from_bytes([2; 16]))?;
    let genesis = sign_membership(
        ChannelMembershipData {
            previous: None,
            space_id: f.space(),
            channel_id: next.channel_id(),
            key_commitment: old.commitment(),
            epoch: 0,
            kind: ChannelKind::Group,
            members: vec![
                f.bundle.root.data.person_id,
                member.certificate().data.person_id,
            ],
            issuer_device: f.root(),
        },
        &f.keys,
    )?;
    let membership = sign_membership(
        ChannelMembershipData {
            previous: Some(genesis.signature.clone()),
            space_id: f.space(),
            channel_id: next.channel_id(),
            key_commitment: next.commitment(),
            epoch: next.epoch(),
            kind: ChannelKind::Group,
            members: vec![
                f.bundle.root.data.person_id,
                member.certificate().data.person_id,
            ],
            issuer_device: f.root(),
        },
        &f.keys,
    )?;
    let authorized = f
        .directory()?
        .verify_membership(&membership, Some(&genesis))?;
    let wrapped = wrap_channel_key(&next, &member, &authorized, &mut f.entropy)?;
    let relabeled = ChannelKey::from_bytes(
        f.space(),
        old.channel_id(),
        next.epoch(),
        *old.export_secret(),
    );
    assert!(wrap_channel_key(&relabeled, &member, &authorized, &mut f.entropy).is_err());
    let mut substituted = membership.clone();
    substituted.data.key_commitment = relabeled.commitment();
    assert!(
        f.directory()?
            .verify_membership(&substituted, Some(&genesis))
            .is_err()
    );
    let same_epoch_rebind = sign_membership(
        ChannelMembershipData {
            previous: Some(membership.signature.clone()),
            key_commitment: relabeled.commitment(),
            ..membership.data.clone()
        },
        &f.keys,
    )?;
    assert!(
        f.directory()?
            .verify_membership(&same_epoch_rebind, Some(&membership))
            .is_err()
    );
    let mut forged = membership.clone();
    forged.data.members.pop();
    assert!(f.directory()?.verify_membership(&forged, None).is_err());
    let own_only = sign_membership(
        ChannelMembershipData {
            previous: Some(membership.signature.clone()),
            members: vec![f.bundle.root.data.person_id],
            ..membership.data.clone()
        },
        &f.keys,
    )?;
    let restricted = f
        .directory()?
        .verify_membership(&own_only, Some(&membership))?;
    assert!(
        f.directory()?
            .verify_membership(&membership, Some(&own_only))
            .is_err()
    );
    let channel = Channel {
        membership: own_only.clone(),
        membership_history: vec![genesis.clone(), membership.clone()],
        id: next.channel_id(),
        space_id: f.space(),
        kind: ChannelKind::Group,
        meta: Ciphertext {
            nonce: Nonce::from_bytes([0; 24]),
            ciphertext: Base64Bytes::new(vec![0; 16]),
        },
        members: own_only.data.members.clone(),
        current_epoch: 1,
    };
    f.directory()?.verify_channel(&channel, Some(&membership))?;
    let mut forged_channel = channel.clone();
    forged_channel
        .members
        .push(member.certificate().data.person_id);
    assert!(
        f.directory()?
            .verify_channel(&forged_channel, Some(&membership))
            .is_err()
    );
    forged_channel = channel.clone();
    forged_channel.membership = membership.clone();
    forged_channel.members = membership.data.members.clone();
    forged_channel.membership_history = vec![genesis.clone()];
    assert!(
        f.directory()?
            .verify_channel(&forged_channel, Some(&own_only))
            .is_err()
    );
    let attack = sign_membership(
        ChannelMembershipData {
            previous: Some(own_only.signature.clone()),
            issuer_device: member.certificate().data.device_id,
            members: membership.data.members.clone(),
            ..own_only.data.clone()
        },
        &member_keys,
    )?;
    assert!(
        f.directory()?
            .verify_membership(&attack, Some(&own_only))
            .is_err()
    );

    assert!(wrap_channel_key(&next, &member, &restricted, &mut f.entropy).is_err());
    let received = unwrap_channel_key(
        f.space(),
        member.certificate().data.device_id,
        &member_keys,
        &wrapped,
    )?;
    assert_eq!(*next.export_secret(), *received.export_secret());
    let mut changed = wrapped.clone();
    changed.epoch += 1;
    assert!(
        unwrap_channel_key(
            f.space(),
            member.certificate().data.device_id,
            &member_keys,
            &changed
        )
        .is_err()
    );
    changed = wrapped.clone();
    changed.channel_id = ChannelId::from_bytes([8; 16]);
    assert!(
        unwrap_channel_key(
            f.space(),
            member.certificate().data.device_id,
            &member_keys,
            &changed
        )
        .is_err()
    );
    assert!(unwrap_channel_key(f.space(), f.root(), &f.keys, &wrapped).is_err());
    assert!(
        unwrap_channel_key(
            SpaceId::from_bytes([8; 16]),
            member.certificate().data.device_id,
            &member_keys,
            &wrapped
        )
        .is_err()
    );
    let (old_msg, old_sig) =
        encrypt_message(&old, &f.keys, metadata()?, &content(), &mut f.entropy)?;
    let author = f.directory()?.device(f.root())?;
    assert!(decrypt_message(&next, &author, &old_msg, &old_sig).is_err());
    assert_eq!(
        decrypt_message(&old, &author, &old_msg, &old_sig)?,
        content()
    );
    let max = ChannelKey::from_bytes(f.space(), old.channel_id(), u64::MAX, [1; 32]);
    assert!(max.rotate(&mut f.entropy).is_err());
    Ok(())
}

#[test]
fn grant_derivation_is_stable_and_sealed_keys_bind_context() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let secret = GrantSecret::from_bytes([7; 32]);
    let grant = secret.derive()?;
    assert_eq!(
        grant.id().to_string(),
        "cDl7Lj0R9nkKr4y8Agoj_mxX9VKTltKX990FTH9gmbk"
    );
    assert_eq!(
        serde_json::to_value(grant.public())?,
        json!("yjsuhmpjBkMd2pec4a92SK-8NRX_-JGNkuD0gaqPJ3s")
    );
    let again = GrantSecret::from_bytes([7; 32]).derive()?;
    let other = GrantSecret::from_bytes([8; 32]).derive()?;
    assert_eq!(grant.id(), again.id());
    assert_eq!(grant.public(), again.public());
    assert_ne!(grant.id(), other.id());
    assert_ne!(grant.public(), other.public());
    assert_eq!(
        grant.id().as_bytes(),
        &blake3::derive_key("phi grant id", &[7; 32])
    );
    let channel = f.channel()?;
    let sealed = seal_grant_key(&grant, &channel, &mut f.entropy)?;
    assert_eq!(
        *channel.export_secret(),
        *unseal_grant_key(f.space(), &again, &sealed)?.export_secret()
    );
    assert!(unseal_grant_key(f.space(), &other, &sealed).is_err());
    assert!(unseal_grant_key(SpaceId::from_bytes([7; 16]), &grant, &sealed).is_err());
    let mut bad = sealed.clone();
    bad.epoch += 1;
    assert!(unseal_grant_key(f.space(), &grant, &bad).is_err());
    bad = sealed;
    bad.channel_id = ChannelId::from_bytes([7; 16]);
    assert!(unseal_grant_key(f.space(), &grant, &bad).is_err());
    verify_signature(&grant.public(), b"proof", &again.sign(b"proof"))?;
    assert!(verify_signature(&other.public(), b"proof", &grant.sign(b"proof")).is_err());
    Ok(())
}

#[test]
fn root_anchor_rejects_substitution_and_false_self_signatures() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    assert_eq!(f.directory()?.active_devices().count(), 1);
    assert!(verify_trust_bundle(SpaceId::from_bytes([0; 16]), &f.bundle, 100, None).is_err());
    let attacker = DeviceKeys::generate(&mut f.entropy)?;
    let mut forged = f.bundle.clone();
    forged.root.data.sign_pub = attacker.sign_public();
    forged.root.signature = attacker.sign(&certificate_signing_bytes(&forged.root.data)?);
    assert!(verify_trust_bundle(f.space(), &forged, 100, None).is_err());
    forged = f.bundle.clone();
    forged.root.signature = attacker.sign(&certificate_signing_bytes(&forged.root.data)?);
    assert!(verify_trust_bundle(f.space(), &forged, 100, None).is_err());
    let mut weak = f.keys.sign_public().as_bytes().to_owned();
    weak.fill(0);
    weak[0] = 1;
    assert!(
        verify_signature(
            &PublicKey::from_bytes(weak),
            b"",
            &Signature::from_bytes([0; 64])
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn trust_resolves_out_of_order_recursive_grants_to_the_root() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let (member, _) = f.member()?;
    let enroll = GrantSecret::generate(&mut f.entropy)?.derive()?;
    let record = sign_grant(
        GrantRecordData {
            space_id: f.space(),
            grant_id: enroll.id(),
            grant_pub: enroll.public(),
            kind: GrantKind::Enroll,

            person_id: PersonId::from_bytes([2; 16]),
            created_at: 40,
            expires_at: None,
            issuer_device: DeviceId::from_bytes([2; 16]),
        },
        &member,
    )?;
    let third = DeviceKeys::generate(&mut f.entropy)?;
    let cert = certify_with_grant(
        DeviceCertificateData {
            space_id: f.space(),
            person_id: record.data.person_id,
            device_id: DeviceId::from_bytes([3; 16]),
            kind: DeviceKind::Cli,
            sign_pub: third.sign_public(),
            kex_pub: third.kex_public(),
            created_at: 50,
            issuer: CertificateIssuer::Grant {
                grant_id: enroll.id(),
            },
        },
        &enroll,
    )?;
    f.bundle.grants.insert(0, record);
    f.bundle.certificates.insert(0, cert);
    let directory = verify_trust_bundle(f.space(), &f.bundle, 10000, None)?;
    assert_eq!(directory.active_devices().count(), 3);
    assert_eq!(
        directory
            .device(DeviceId::from_bytes([3; 16]))?
            .certificate()
            .data
            .kex_pub,
        third.kex_public()
    );
    Ok(())
}

#[test]
fn certificate_and_grant_tampering_never_become_verified_keys() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    f.member()?;
    let attacker = DeviceKeys::generate(&mut f.entropy)?;
    let mut impersonation = f.bundle.certificates[0].data.clone();
    impersonation.device_id = DeviceId::from_bytes([9; 16]);
    impersonation.person_id = f.bundle.root.data.person_id;
    impersonation.issuer = CertificateIssuer::Device {
        device_id: f.root(),
    };
    impersonation.sign_pub = attacker.sign_public();
    impersonation.kex_pub = attacker.kex_public();
    assert!(certify_device(impersonation.clone(), &f.keys).is_err());
    let mut hostile = f.bundle.clone();
    hostile.certificates.push(DeviceCertificate {
        signature: f.keys.sign(&certificate_signing_bytes(&impersonation)?),
        data: impersonation,
    });
    assert!(verify_trust_bundle(f.space(), &hostile, 100, None).is_err());
    let mut forged = f.bundle.clone();
    forged.certificates[0].data.kex_pub = attacker.kex_public();
    assert!(verify_trust_bundle(f.space(), &forged, 100, None).is_err());
    forged = f.bundle.clone();
    forged.certificates[0].data.kind = DeviceKind::Cli;
    assert!(verify_trust_bundle(f.space(), &forged, 100, None).is_err());
    forged = f.bundle.clone();
    forged.grants[0].data.grant_pub = attacker.sign_public();
    assert!(verify_trust_bundle(f.space(), &forged, 100, None).is_err());
    forged = f.bundle.clone();
    forged.grants[0].signature = attacker.sign(&grant_signing_bytes(&forged.grants[0].data)?);
    assert!(verify_trust_bundle(f.space(), &forged, 100, None).is_err());
    Ok(())
}

#[test]
fn reused_grants_and_duplicate_device_ids_are_rejected() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let (_, grant) = f.member()?;
    let another = GrantSecret::from_bytes([77; 32]).derive()?;
    let mut record = f.bundle.grants[0].data.clone();
    record.grant_id = another.id();
    record.grant_pub = another.public();
    let mut hostile = f.bundle.clone();
    hostile.grants.push(sign_grant(record, &f.keys)?);
    let mut extra = f.bundle.certificates[0].data.clone();
    extra.device_id = DeviceId::from_bytes([9; 16]);
    extra.issuer = CertificateIssuer::Grant {
        grant_id: another.id(),
    };
    hostile
        .certificates
        .push(certify_with_grant(extra, &another)?);
    assert!(verify_trust_bundle(f.space(), &hostile, 100, None).is_err());
    let mut duplicate = f.bundle.certificates[0].data.clone();
    duplicate.device_id = DeviceId::from_bytes([3; 16]);
    f.bundle
        .certificates
        .push(certify_with_grant(duplicate, &grant)?);
    assert!(f.directory().is_err());
    f.bundle.certificates.pop();
    f.bundle.certificates.push(f.bundle.certificates[0].clone());
    assert!(f.directory().is_err());
    f.bundle.certificates.pop();
    f.bundle.grants.push(f.bundle.grants[0].clone());
    assert!(f.directory().is_err());
    Ok(())
}

#[test]
fn grant_person_time_and_expiry_are_enforced_at_redemption() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let (_, grant) = f.member()?;
    for (person, created) in [
        (PersonId::from_bytes([9; 16]), 30),
        (PersonId::from_bytes([2; 16]), 19),
        (PersonId::from_bytes([2; 16]), 90),
    ] {
        let mut forged = f.bundle.clone();
        forged.certificates[0].data.person_id = person;
        forged.certificates[0].data.created_at = created;
        forged.certificates[0] = certify_with_grant(forged.certificates[0].data.clone(), &grant)?;
        assert!(verify_trust_bundle(f.space(), &forged, 100, None).is_err());
    }
    assert!(verify_trust_bundle(f.space(), &f.bundle, 29, None).is_err());
    assert!(verify_trust_bundle(f.space(), &f.bundle, 100000, None).is_ok());
    let mut other_person_enroll = f.bundle.clone();
    other_person_enroll.grants[0].data.kind = GrantKind::Enroll;
    other_person_enroll.grants[0] =
        sign_grant(other_person_enroll.grants[0].data.clone(), &f.keys)?;
    assert!(verify_trust_bundle(f.space(), &other_person_enroll, 100, None).is_err());
    let enroll_grant = GrantSecret::from_bytes([88; 32]).derive()?;
    let record = GrantRecordData {
        space_id: f.space(),
        grant_id: enroll_grant.id(),
        grant_pub: enroll_grant.public(),
        kind: GrantKind::Enroll,

        person_id: f.bundle.root.data.person_id,
        created_at: 20,
        expires_at: None,
        issuer_device: f.root(),
    };
    let mut with_enrollment = f.bundle.clone();
    with_enrollment.grants.push(sign_grant(record, &f.keys)?);
    assert!(verify_trust_bundle(f.space(), &with_enrollment, 100, None).is_ok());
    let mut cli_label = f.bundle.clone();
    cli_label.certificates[0].data.kind = DeviceKind::Cli;
    cli_label.certificates[0] = certify_with_grant(cli_label.certificates[0].data.clone(), &grant)?;
    assert!(verify_trust_bundle(f.space(), &cli_label, 100, None).is_ok());
    let mut invalid = f.bundle.grants[0].data.clone();
    invalid.expires_at = None;
    assert!(sign_grant(invalid, &f.keys).is_err());
    Ok(())
}

#[test]
fn missing_cyclic_and_cross_space_chains_fail_closed() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let (member, _) = f.member()?;
    let mut broken = f.bundle.clone();
    broken.grants.clear();
    assert!(verify_trust_bundle(f.space(), &broken, 100, None).is_err());
    broken = f.bundle.clone();
    broken.certificates[0].data.issuer = CertificateIssuer::Device {
        device_id: DeviceId::from_bytes([2; 16]),
    };
    broken.certificates[0].signature =
        member.sign(&certificate_signing_bytes(&broken.certificates[0].data)?);
    assert!(verify_trust_bundle(f.space(), &broken, 100, None).is_err());
    broken = f.bundle.clone();
    broken.grants[0].data.space_id = SpaceId::from_bytes([5; 16]);
    broken.grants[0] = sign_grant(broken.grants[0].data.clone(), &f.keys)?;
    assert!(verify_trust_bundle(f.space(), &broken, 100, None).is_err());
    broken = f.bundle.clone();
    broken.certificates.push(broken.root.clone());
    assert!(verify_trust_bundle(f.space(), &broken, 100, None).is_err());
    Ok(())
}

#[test]
fn signed_revocations_exclude_devices_and_persons_and_reject_forgery() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let (member, _) = f.member()?;
    let pinned = f.directory()?.pinned_state();
    let data = RevocationData {
        space_id: f.space(),
        target: RevocationTarget::Device {
            device_id: DeviceId::from_bytes([2; 16]),
        },
        issuer_device: f.root(),
        created_at: 30,
    };
    f.bundle
        .revocations
        .push(sign_revocation(data.clone(), &f.keys)?);
    let verified = verify_trust_bundle(f.space(), &f.bundle, 100, Some(&pinned))?;
    assert!(verified.device(DeviceId::from_bytes([2; 16])).is_err());
    assert_eq!(verified.active_devices().count(), 1);
    assert_eq!(verified.revocations().len(), 1);
    let revoked_pins = verified.pinned_state();
    let mut omitted = f.bundle.clone();
    omitted.revocations.clear();
    assert!(
        verify_trust_bundle(f.space(), &omitted, 100, Some(&revoked_pins))?
            .device(DeviceId::from_bytes([2; 16]))
            .is_err()
    );
    f.bundle.revocations[0] = sign_revocation(data.clone(), &member)?;
    assert!(verify_trust_bundle(f.space(), &f.bundle, 100, Some(&pinned)).is_err());
    let mut person = data.clone();
    person.target = RevocationTarget::Person {
        person_id: PersonId::from_bytes([2; 16]),
    };
    f.bundle.revocations[0] = sign_revocation(person, &f.keys)?;
    assert!(
        verify_trust_bundle(f.space(), &f.bundle, 100, Some(&pinned))?
            .device(DeviceId::from_bytes([2; 16]))
            .is_err()
    );
    let mut future = data;
    future.created_at = 101;
    f.bundle.revocations[0] = sign_revocation(future, &f.keys)?;
    assert!(verify_trust_bundle(f.space(), &f.bundle, 100, Some(&pinned)).is_err());
    Ok(())
}

#[test]
fn pinned_issuance_survives_revocation_but_backdated_successors_fail() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let (_, grant) = f.member()?;
    let pinned = f.directory()?.pinned_state();
    f.bundle.revocations.push(sign_revocation(
        RevocationData {
            space_id: f.space(),
            target: RevocationTarget::Device {
                device_id: f.root(),
            },
            issuer_device: f.root(),
            created_at: 25,
        },
        &f.keys,
    )?);
    assert!(f.directory().is_err());
    let verified = verify_trust_bundle(f.space(), &f.bundle, 100, Some(&pinned))?;
    assert!(verified.device(f.root()).is_err());
    assert!(verified.device(DeviceId::from_bytes([2; 16])).is_ok());
    assert_eq!(
        verified.grant_certificates().get(&grant.id()),
        Some(&f.bundle.certificates[0])
    );
    // A device enrolling later has nothing pinned; it still accepts certificates
    // issued before the revocation's own clock, and so can join the space at all.
    let mut later = f.bundle.clone();
    later.revocations[0] = sign_revocation(
        RevocationData {
            created_at: 50,
            ..later.revocations[0].data.clone()
        },
        &f.keys,
    )?;
    assert!(verify_trust_bundle(f.space(), &later, 100, None).is_ok());
    assert!(verify_trust_bundle(f.space(), &f.bundle, 100, None).is_err());
    let mut equivocation = f.bundle.clone();
    equivocation.certificates[0].data.device_id = DeviceId::from_bytes([9; 16]);
    equivocation.certificates[0] =
        certify_with_grant(equivocation.certificates[0].data.clone(), &grant)?;
    assert!(verify_trust_bundle(f.space(), &equivocation, 100, Some(&pinned)).is_err());
    let mut missing = f.bundle.clone();
    missing.certificates.clear();
    assert!(verify_trust_bundle(f.space(), &missing, 100, Some(&pinned)).is_err());
    let mut missing = f.bundle.clone();
    missing.grants.clear();
    assert!(verify_trust_bundle(f.space(), &missing, 100, Some(&pinned)).is_err());
    let successor_grant = GrantSecret::from_bytes([99; 32]).derive()?;
    let mut record = f.bundle.grants[0].data.clone();
    record.grant_id = successor_grant.id();
    record.grant_pub = successor_grant.public();
    record.kind = GrantKind::Enroll;
    record.person_id = f.bundle.root.data.person_id;
    f.bundle.grants.push(sign_grant(record.clone(), &f.keys)?);
    let mut cert = f.bundle.certificates[0].data.clone();
    cert.device_id = DeviceId::from_bytes([9; 16]);
    cert.person_id = record.person_id;
    cert.issuer = CertificateIssuer::Grant {
        grant_id: successor_grant.id(),
    };
    f.bundle
        .certificates
        .push(certify_with_grant(cert, &successor_grant)?);
    assert!(verify_trust_bundle(f.space(), &f.bundle, 100, Some(&pinned)).is_err());
    Ok(())
}

#[test]
fn reactions_and_settings_authenticate_identity_and_removal() -> Result<(), CryptoError> {
    let f = Fixture::new()?;
    let directory = f.directory()?;
    let reaction = sign_reaction(
        ReactionData {
            space_id: f.space(),
            message_id: MessageId::from_bytes([1; 16]),
            person_id: PersonId::from_bytes([1; 16]),
            device_id: f.root(),
            handle: "reviewer".parse()?,
            kind: ReactionKind::Claim,
            created_at: 40,
            remove: false,
        },
        &f.keys,
    )?;
    directory.verify_reaction(&reaction)?;
    let mut bad = reaction.clone();
    bad.data.remove = true;
    assert!(directory.verify_reaction(&bad).is_err());
    bad = reaction;
    bad.data.person_id = PersonId::from_bytes([8; 16]);
    bad = sign_reaction(bad.data, &f.keys)?;
    assert!(directory.verify_reaction(&bad).is_err());
    let mut settings = sign_settings(
        SettingsChangeData {
            space_id: f.space(),
            issuer_device: f.root(),
            created_at: 40,
            settings: SpaceSettings::default(),
        },
        &f.keys,
    )?;
    directory.verify_settings(&settings)?;
    let mut legacy = serde_json::to_value(&settings)?;
    if let Some(object) = legacy["data"]["settings"].as_object_mut() {
        object.remove("summary_every");
    }
    directory.verify_settings(&serde_json::from_value(legacy)?)?;
    settings.data.settings.summary_every = 5;
    assert!(directory.verify_settings(&settings).is_err());
    settings = sign_settings(settings.data, &f.keys)?;
    directory.verify_settings(&settings)?;
    let mut changed = settings.clone();
    changed.data.settings.summary_every = 3;
    assert!(directory.verify_settings(&changed).is_err());
    changed.data.settings.summary_every = 0;
    assert!(directory.verify_settings(&changed).is_err());
    settings.data.settings.retention_days = 0;
    assert!(directory.verify_settings(&settings).is_err());
    Ok(())
}

#[test]
fn links_roundtrip_tls_ipv6_and_reject_ambiguous_or_leaky_authorities() -> Result<(), CryptoError> {
    let f = Fixture::new()?;
    for (tls, authority) in [
        (false, "localhost:8080"),
        (true, "example.com"),
        (true, "[::1]:8443"),
    ] {
        let link = GrantLink::new(
            tls,
            authority.into(),
            f.space(),
            GrantSecret::from_bytes([7; 32]),
        )?;
        let encoded = link.encode();
        let parsed = GrantLink::parse(&encoded)?;
        assert_eq!(parsed.space_id(), f.space());
        assert_eq!(parsed.secret().expose(), &[7; 32]);
        assert_eq!(*parsed.encode(), *encoded);
        assert!(
            parsed
                .server_url()
                .starts_with(if tls { "https://" } else { "http://" })
        );
        assert!(
            !format!("{parsed:?}")
                .contains(encoded.split_once('#').map(|(_, s)| s).unwrap_or("invalid"))
        );
    }
    for host in [
        "",
        "u@host",
        "host/path",
        "host?x=1",
        "host:0",
        "host:65536",
        "host:+1",
        "::1",
        "[bad]",
        "host:",
        "-a.com",
        "a..com",
        "h ost",
        "host\\path",
    ] {
        assert!(
            GrantLink::new(
                true,
                host.into(),
                f.space(),
                GrantSecret::from_bytes([7; 32])
            )
            .is_err(),
            "{host}"
        );
    }
    for bad in [
        "https://host/id#key",
        "phi://host/id",
        "phi://host/id#key",
        "phi://host/a/b#key",
        "phi://host/#key",
    ] {
        assert!(GrantLink::parse(bad).is_err());
    }
    let link = GrantLink::new(
        true,
        "host".into(),
        f.space(),
        GrantSecret::from_bytes([7; 32]),
    )?
    .encode();
    assert!(GrantLink::parse(&format!("{link}=", link = link.as_str())).is_err());
    Ok(())
}

#[test]
fn wire_validation_is_strict_bounded_and_major_versioned() -> Result<(), CryptoError> {
    let f = Fixture::new()?;
    let id = f.root().to_string();
    assert_eq!(id.len(), 22);
    assert_eq!(id.parse::<DeviceId>()?, f.root());
    for bad in [
        format!("{id}="),
        "a".into(),
        "é".into(),
        "______________________".into(),
    ] {
        assert!(bad.parse::<DeviceId>().is_err());
    }
    for bad in ["", "Main", "-bad", "a/b", "é", "a b"] {
        assert!(bad.parse::<Handle>().is_err());
    }
    assert!("a".repeat(40).parse::<Handle>().is_ok());
    assert!("a".repeat(41).parse::<Handle>().is_err());
    assert!("AA".parse::<PublicKey>().is_err());
    assert!(serde_json::from_value::<MessagesQuery>(json!({"limit":1,"extra":true})).is_err());
    assert!(
        serde_json::from_value::<PutCursorRequest>(json!({"last_read_seq":1,"extra":true}))
            .is_err()
    );
    for length in [15, MAX_CIPHERTEXT_BYTES + 1] {
        assert!(
            Ciphertext {
                nonce: Nonce::from_bytes([0; 24]),
                ciphertext: Base64Bytes::new(vec![0; length])
            }
            .validate()
            .is_err()
        );
    }
    Ciphertext {
        nonce: Nonce::from_bytes([0; 24]),
        ciphertext: Base64Bytes::new(vec![0; MAX_CIPHERTEXT_BYTES]),
    }
    .validate()?;
    let mut cert = serde_json::to_value(&f.bundle.root)?;
    cert["data"]["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<DeviceCertificate>(cert.clone()).is_ok());
    assert!(serde_json::from_value::<RedeemGrantRequest>(json!({"certificate":cert})).is_err());
    let mut nested = serde_json::to_value(&f.bundle.root)?;
    nested["data"]["issuer"]["extra"] = Value::Bool(true);
    assert!(serde_json::from_value::<RedeemGrantRequest>(json!({"certificate":nested})).is_err());
    assert!(
        MessagesQuery {
            limit: Some(0),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        MessagesQuery {
            limit: Some(1001),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        EventsQuery {
            after: 0,
            timeout: Some(901),
            handle: None
        }
        .validate()
        .is_err()
    );
    let mut c = content();
    c.attachments.push(Attachment {
        blob_id: BlobId::from_bytes([1; 16]),
        name: "../secret".into(),
        mime: "text/plain".into(),
        size: 1,
        key: KeyBytes::from_bytes([1; 32]),
        nonce: Nonce::from_bytes([1; 24]),
    });
    assert!(c.validate().is_err());
    for control in [
        "\n", "\r", "\t", "\u{001b}", "\u{202e}", "\u{2066}", "\u{200f}", "\u{2028}",
    ] {
        for field in 0..4 {
            let mut c = content();
            let bad = format!("x{control}forged frame");
            match field {
                0 => c.title = Some(bad),
                1 => {
                    if bad.contains(['\n','\r','\t','\u{2028}']) && !bad.chars().any(|c| matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\0')) { continue; }
                    c.summary = Some(bad);
                }
                2 => c.display_name = bad,
                _ => c.attachments.push(Attachment {
                    blob_id: BlobId::from_bytes([1; 16]),
                    name: bad,
                    mime: "text/plain".into(),
                    size: 0,
                    key: KeyBytes::from_bytes([0; 32]),
                    nonce: Nonce::from_bytes([0; 24]),
                }),
            }
            assert!(c.validate().is_err(), "field {field}");
        }
    }
    let mut markdown = content();
    markdown.body = "line one\nline two\tcode".into();
    markdown.validate()?;
    let settings = SpaceSettings::default();
    assert_eq!(settings.retention_days, 14);
    assert_eq!(settings.summary_every, 3);
    assert_eq!(settings.rate_limits.messages_per_hour, 600);
    check_protocol(PROTOCOL_MAJOR).map_err(|_| CryptoError::Trust("wrong protocol"))?;
    let upgrade = match check_protocol(PROTOCOL_MAJOR + 1) {
        Err(e) => e,
        Ok(()) => return Err(CryptoError::Trust("expected upgrade")),
    };
    assert_eq!(upgrade.status_code(), 426);
    assert_eq!(
        serde_json::to_value(upgrade)?,
        json!({"error":"upgrade","required_major":PROTOCOL_MAJOR})
    );
    let response: Counts = serde_json::from_value(
        json!({"unread_threads":0,"mentions":0,"claimed_by_you":0,"channels":[],"latest_seq":0,"future":true}),
    )?;
    assert_eq!(response.unread_threads, 0);
    Ok(())
}

#[test]
fn secrets_restore_without_logging_and_entropy_failures_propagate() -> Result<(), CryptoError> {
    struct Failing;
    impl Entropy for Failing {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Derivation)
        }
    }
    let f = Fixture::new()?;
    let (sign, kex) = f.keys.export_secrets();
    let restored = DeviceKeys::from_secrets(*sign, *kex);
    assert_eq!(restored.sign_public(), f.keys.sign_public());
    assert_eq!(restored.kex_public(), f.keys.kex_public());
    assert_eq!(format!("{:?}", f.keys), "DeviceKeys([redacted])");
    assert_eq!(
        format!("{:?}", GrantSecret::from_bytes([7; 32])),
        "GrantSecret([redacted])"
    );
    assert!(DeviceKeys::generate(&mut Failing).is_err());
    assert!(GrantSecret::generate(&mut Failing).is_err());
    assert!(ChannelKey::generate(f.space(), ChannelId::from_bytes([1; 16]), &mut Failing).is_err());
    Ok(())
}

#[test]
fn content_limits_and_channel_metadata_are_authenticated() -> Result<(), CryptoError> {
    let mut f = Fixture::new()?;
    let channel = f.channel()?;
    let mut c = content();
    c.body = "x".repeat(MAX_CIPHERTEXT_BYTES);
    assert!(encrypt_message(&channel, &f.keys, metadata()?, &c, &mut f.entropy).is_err());
    c = content();
    c.title = None;
    assert!(encrypt_message(&channel, &f.keys, metadata()?, &c, &mut f.entropy).is_err());
    let encrypted = encrypt_channel_metadata(&channel, b"backend", &mut f.entropy)?;
    assert_eq!(
        decrypt_channel_metadata(&channel, &encrypted)?.as_slice(),
        b"backend"
    );
    let next = channel.rotate(&mut f.entropy)?;
    assert!(decrypt_channel_metadata(&next, &encrypted).is_err());
    let mut wrong = encrypted.clone();
    wrong.ciphertext = tamper(&wrong.ciphertext);
    assert!(decrypt_channel_metadata(&channel, &wrong).is_err());
    let (key, mut encrypted) = encrypt_attachment(b"file", &mut f.entropy)?;
    encrypted.ciphertext = Base64Bytes::new(vec![0; 15]);
    assert!(decrypt_attachment(&key, &encrypted).is_err());
    Ok(())
}
