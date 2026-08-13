use core::fmt;
use std::cell::RefCell;

use client::GexParams;
use log::debug;
use num_bigint::BigUint;
use ssh_encoding::Encode;
use ssh_key::Algorithm;

use super::*;
use crate::helpers::sign_with_hash_alg;
use crate::kex::dh::biguint_to_mpint;
use crate::kex::{KEXES, KexAlgorithm, KexAlgorithmImplementor, KexCause};
use crate::keys::key::PrivateKeyWithHashAlg;
use crate::negotiation::{Names, Select, is_key_compatible_with_algo};
use crate::parsing::ensure_end;
use crate::{msg, negotiation};

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ServerKexState {
    Created,
    WaitingForGexRequest {
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForDhInit {
        // both KexInit and DH init sent
        names: Names,
        kex: KexAlgorithm,
    },
    WaitingForNewKeys {
        newkeys: NewKeys,
    },
}

pub(crate) struct ServerKex {
    exchange: Exchange,
    cause: KexCause,
    state: ServerKexState,
    config: Arc<Config>,
    /// Outbound half already extracted at local-NEWKEYS NeedsReply (S2b).
    outbound_half_taken: bool,
    /// Inbound half extracted at NeedsReply (S3a key-first) or Done.
    inbound_half_taken: bool,
}

impl Debug for ServerKex {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ClientKex");
        s.field("cause", &self.cause);
        match self.state {
            ServerKexState::Created => {
                s.field("state", &"created");
            }
            ServerKexState::WaitingForGexRequest { .. } => {
                s.field("state", &"waiting for GEX request");
            }
            ServerKexState::WaitingForDhInit { .. } => {
                s.field("state", &"waiting for DH reply");
            }
            ServerKexState::WaitingForNewKeys { .. } => {
                s.field("state", &"waiting for NEWKEYS");
            }
        }
        s.finish()
    }
}

/// Outbound half material extracted at local-NEWKEYS boundary (S2b §4.4).
pub(crate) struct OutboundEpochInstall {
    pub cipher: Box<dyn crate::cipher::SealingKey + Send>,
    pub compression: crate::compression::Compression,
    pub reset_seqn: bool,
}

/// Inbound half material extracted at local-NEWKEYS / Done (S3a).
pub(crate) struct InboundEpochInstall {
    pub cipher: Box<dyn crate::cipher::OpeningKey + Send>,
    pub compression: crate::compression::Compression,
    pub reset_seqn: bool,
}

fn inbound_from_newkeys(newkeys: &mut NewKeys, strict_rekey: bool) -> InboundEpochInstall {
    let cipher = std::mem::replace(
        &mut newkeys.cipher.remote_to_local,
        Box::new(crate::cipher::clear::Key {}),
    );
    // Server inbound is client→server = names.client_compression.
    let compression = newkeys.names.client_compression.clone();
    let reset_seqn = newkeys.names.strict_kex() || strict_rekey;
    InboundEpochInstall {
        cipher,
        compression,
        reset_seqn,
    }
}

impl ServerKex {
    pub fn new(
        config: Arc<Config>,
        client_sshid: &[u8],
        server_sshid: &SshId,
        cause: KexCause,
    ) -> Self {
        let exchange = Exchange::new(client_sshid, server_sshid.as_kex_hash_bytes());
        Self {
            config,
            exchange,
            cause,
            state: ServerKexState::Created,
            outbound_half_taken: false,
            inbound_half_taken: false,
        }
    }

    /// True when we have sealed local NEWKEYS and await peer NEWKEYS.
    pub fn is_waiting_for_peer_newkeys(&self) -> bool {
        matches!(self.state, ServerKexState::WaitingForNewKeys { .. })
    }

    /// Take outbound cipher half exactly once after local NEWKEYS was produced.
    /// Leaves a clear-key stub in `NewKeys` so Done can still consume the rest.
    pub fn take_outbound_epoch_install(&mut self) -> Option<OutboundEpochInstall> {
        if self.outbound_half_taken {
            return None;
        }
        let ServerKexState::WaitingForNewKeys { ref mut newkeys } = self.state else {
            return None;
        };
        self.outbound_half_taken = true;
        let cipher = std::mem::replace(
            &mut newkeys.cipher.local_to_remote,
            Box::new(crate::cipher::clear::Key {}),
        );
        // Server outbound is server→client = names.server_compression (not client_compression).
        let compression = newkeys.names.server_compression.clone();
        let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();
        Some(OutboundEpochInstall {
            cipher,
            compression,
            reset_seqn,
        })
    }

    /// Take inbound cipher half exactly once after local NEWKEYS was produced
    /// (S3a key-first). Leaves a clear-key stub so Done can still consume metadata.
    pub fn take_inbound_epoch_install(&mut self) -> Option<InboundEpochInstall> {
        if self.inbound_half_taken {
            return None;
        }
        let ServerKexState::WaitingForNewKeys { ref mut newkeys } = self.state else {
            return None;
        };
        self.inbound_half_taken = true;
        Some(inbound_from_newkeys(newkeys, self.cause.is_strict_rekey()))
    }

    /// Extract inbound half from a `Done` `NewKeys` when it was never taken at
    /// NeedsReply (`none`/skip_exchange / NEWKEYS-first).
    pub fn take_inbound_from_newkeys(
        newkeys: &mut NewKeys,
        strict_rekey: bool,
    ) -> InboundEpochInstall {
        inbound_from_newkeys(newkeys, strict_rekey)
    }

    /// Extract outbound half from a `Done` `NewKeys` when it was never taken at
    /// NeedsReply (`none`/skip_exchange). Same direction rules as
    /// [`take_outbound_epoch_install`].
    pub fn take_outbound_from_newkeys(
        newkeys: &mut NewKeys,
        strict_rekey: bool,
    ) -> OutboundEpochInstall {
        let cipher = std::mem::replace(
            &mut newkeys.cipher.local_to_remote,
            Box::new(crate::cipher::clear::Key {}),
        );
        let compression = newkeys.names.server_compression.clone();
        let reset_seqn = newkeys.names.strict_kex() || strict_rekey;
        OutboundEpochInstall {
            cipher,
            compression,
            reset_seqn,
        }
    }

    pub fn is_rekey(&self) -> bool {
        self.cause.is_rekey()
    }

    pub fn kexinit(
        &mut self,
        output: &mut impl crate::sshbuffer::PacketOut,
    ) -> Result<(), Error> {
        self.exchange.server_kex_init =
            negotiation::write_kex(&self.config.preferred, output, Some(self.config.as_ref()))?;

        Ok(())
    }

    pub async fn step<H: Handler + Send>(
        mut self,
        input: Option<&mut IncomingSshPacket>,
        output: &mut impl crate::sshbuffer::PacketOut,
        handler: &mut H,
    ) -> Result<KexProgress<Self>, H::Error> {
        match self.state {
            ServerKexState::Created => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };
                if input.buffer.first() != Some(&msg::KEXINIT) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                let names = {
                    self.exchange.client_kex_init = input.buffer.clone().into();
                    negotiation::Server::read_kex(
                        &input.buffer,
                        &self.config.preferred,
                        Some(&self.config.keys),
                        &self.cause,
                    )?
                };
                debug!("negotiated: {names:?}");

                // seqno has already been incremented after read()
                if names.strict_kex() && !self.cause.is_rekey() && input.seqn.0 != 1 {
                    return Err(strict_kex_violation(
                        msg::KEXINIT,
                        input.seqn.0 as usize - 1,
                    ))?;
                }

                let kex = KEXES.get(&names.kex).ok_or(Error::UnknownAlgo)?.make();

                if kex.skip_exchange() {
                    let newkeys = compute_keys(
                        Vec::new(),
                        kex,
                        names.clone(),
                        self.exchange.clone(),
                        self.cause.session_id(),
                    )?;

                    output.write_packet(|w| {
                        msg::NEWKEYS.encode(w)?;
                        Ok(())
                    })?;

                    return Ok(KexProgress::Done {
                        newkeys,
                        server_host_key: None,
                    });
                }

                if kex.is_dh_gex() {
                    self.state = ServerKexState::WaitingForGexRequest { names, kex };
                } else {
                    self.state = ServerKexState::WaitingForDhInit { names, kex };
                }

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ServerKexState::WaitingForGexRequest { names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };
                if input.buffer.first() != Some(&msg::KEX_DH_GEX_REQUEST) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];
                let gex_params = GexParams::decode(&mut r)?;
                ensure_end(&r)?;
                debug!("client requests a gex group: {gex_params:?}");

                let Some(dh_group) = handler.lookup_dh_gex_group(&gex_params).await? else {
                    debug!(
                        "server::Handler impl did not find a matching DH group (is lookup_dh_gex_group implemented?)"
                    );
                    return Err(Error::Kex)?;
                };

                let prime = biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.prime));
                let generator = biguint_to_mpint(&BigUint::from_bytes_be(&dh_group.generator));

                self.exchange.gex = Some((gex_params, dh_group.clone()));
                kex.dh_gex_set_group(dh_group)?;

                output.write_packet(|w| {
                    msg::KEX_DH_GEX_GROUP.encode(w)?;
                    prime.encode(w)?;
                    generator.encode(w)?;
                    Ok(())
                })?;

                self.state = ServerKexState::WaitingForDhInit { names, kex };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn: false,
                })
            }
            ServerKexState::WaitingForDhInit { mut names, mut kex } => {
                let Some(input) = input else {
                    return Err(Error::KexInit)?;
                };

                if names.ignore_guessed {
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    debug!("ignoring guessed kex");
                    names.ignore_guessed = false;
                    self.state = ServerKexState::WaitingForDhInit { names, kex };
                    return Ok(KexProgress::NeedsReply {
                        kex: self,
                        reset_seqn: false,
                    });
                }

                if input.buffer.first()
                    != Some(match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_INIT,
                        false => &msg::KEX_ECDH_INIT,
                    })
                {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::KexInit)?;
                }

                #[allow(clippy::indexing_slicing)] // length checked
                let mut r = &input.buffer[1..];

                self.exchange
                    .client_ephemeral
                    .extend_from_slice(&Bytes::decode(&mut r).map_err(Into::into)?);
                ensure_end(&r)?;

                let exchange = &mut self.exchange;
                kex.server_dh(exchange, &input.buffer)?;

                let Some(matching_key_index) = self
                    .config
                    .keys
                    .iter()
                    .position(|key| is_key_compatible_with_algo(key, &names.key))
                else {
                    debug!("we don't have a host key of type {:?}", names.key);
                    return Err(Error::UnknownKey.into());
                };

                // Look up the key we'll be using to sign the exchange hash
                #[allow(clippy::indexing_slicing)] // key index checked
                let key = &self.config.keys[matching_key_index];
                let signature_hash_alg = match &names.key {
                    Algorithm::Rsa { hash } => *hash,
                    _ => None,
                };

                let hash = HASH_BUF.with(|buffer| {
                    let mut buffer = buffer.borrow_mut();
                    buffer.clear();

                    let mut pubkey_vec = Vec::new();
                    key.public_key().to_bytes()?.encode(&mut pubkey_vec)?;

                    let hash = kex.compute_exchange_hash(&pubkey_vec, exchange, &mut buffer)?;

                    Ok::<_, Error>(hash)
                })?;

                // Hash signature
                debug!("signing with key {key:?}");
                let signature = sign_with_hash_alg(
                    &PrivateKeyWithHashAlg::new(Arc::new(key.clone()), signature_hash_alg),
                    &hash,
                )
                .map_err(Into::into)?;

                output.write_packet(|w| {
                    match kex.is_dh_gex() {
                        true => &msg::KEX_DH_GEX_REPLY,
                        false => &msg::KEX_ECDH_REPLY,
                    }
                    .encode(w)?;
                    key.public_key().to_bytes()?.encode(w)?;
                    exchange.server_ephemeral.encode(w)?;
                    signature.encode(w)?;
                    Ok(())
                })?;

                output.write_packet(|w| {
                    msg::NEWKEYS.encode(w)?;
                    Ok(())
                })?;

                let newkeys = compute_keys(
                    hash,
                    kex,
                    names.clone(),
                    self.exchange.clone(),
                    self.cause.session_id(),
                )?;

                let reset_seqn = newkeys.names.strict_kex() || self.cause.is_strict_rekey();

                self.state = ServerKexState::WaitingForNewKeys { newkeys };

                Ok(KexProgress::NeedsReply {
                    kex: self,
                    reset_seqn,
                })
            }
            ServerKexState::WaitingForNewKeys { newkeys } => {
                let Some(input) = input else {
                    return Err(Error::KexInit.into());
                };

                if input.buffer.first() != Some(&msg::NEWKEYS) {
                    error!(
                        "Unexpected kex message at this stage: {:?}",
                        input.buffer.first()
                    );
                    return Err(Error::Kex.into());
                }
                #[allow(clippy::indexing_slicing, reason = "checked")]
                let r = &input.buffer[1..];
                ensure_end(&r)?;

                debug!("new keys received");
                Ok(KexProgress::Done {
                    newkeys,
                    server_host_key: None,
                })
            }
        }
    }
}

fn compute_keys(
    hash: Vec<u8>,
    kex: KexAlgorithm,
    names: Names,
    exchange: Exchange,
    session_id: Option<&CryptoVec>,
) -> Result<NewKeys, Error> {
    let session_id_ref: &[u8] = match session_id {
        Some(sid) => sid,
        None => &hash,
    };
    // Now computing keys.
    let c = kex.compute_keys(
        session_id_ref,
        &hash,
        names.cipher,
        names.client_mac,
        names.server_mac,
        true,
    )?;
    let session_id_cv = match session_id {
        Some(s) => s.clone(),
        None => {
            let mut cv = CryptoVec::new();
            cv.extend(&hash);
            cv
        }
    };
    Ok(NewKeys {
        exchange,
        names,
        kex,
        key: 0,
        cipher: c,
        session_id: session_id_cv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::Compression;
    use crate::kex::{KexCause, NONE as KEX_NONE};
    use crate::tests::raw_no_crypto::{assert_rejected, kexinit_payload, raw_kex_signal, timeout};

    #[tokio::test]
    async fn kexinit_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_kex_signal(|payload| {
            payload.extend_from_slice(&kexinit_payload("none"));
            payload.push(0);
        }))
        .await;

        assert_rejected(result, "server accepted a kexinit with trailing bytes");
    }

    /// Craft asymmetric compression lists in a client KEXINIT and assert server
    /// outbound half uses server→client (`server_compression`), not client→server.
    #[cfg(feature = "flate2")]
    #[test]
    fn server_outbound_half_follows_server_compression_field() {
        use crate::helpers::NameList;
        use crate::negotiation::{Preferred, Select, Server as NegServer};
        use ssh_encoding::Encode;

        // Client KEXINIT: c2s=none, s2c=zlib@openssh.com (asymmetric).
        let mut buf = Vec::new();
        msg::KEXINIT.encode(&mut buf).unwrap();
        buf.extend_from_slice(&[0u8; 16]); // cookie
        NameList(vec!["none".into()]).encode(&mut buf).unwrap(); // kex
        NameList(vec!["ssh-ed25519".into()])
            .encode(&mut buf)
            .unwrap(); // host key
        NameList(vec!["none".into()]).encode(&mut buf).unwrap(); // cipher c2s
        NameList(vec!["none".into()]).encode(&mut buf).unwrap(); // cipher s2c
        NameList(vec!["none".into()]).encode(&mut buf).unwrap(); // mac c2s
        NameList(vec!["none".into()]).encode(&mut buf).unwrap(); // mac s2c
        NameList(vec!["none".into()]).encode(&mut buf).unwrap(); // comp c2s
        NameList(vec!["zlib@openssh.com".into(), "none".into()])
            .encode(&mut buf)
            .unwrap(); // comp s2c
        NameList(vec![]).encode(&mut buf).unwrap(); // lang c2s
        NameList(vec![]).encode(&mut buf).unwrap(); // lang s2c
        0u8.encode(&mut buf).unwrap();
        0u32.encode(&mut buf).unwrap();

        let mut pref = Preferred::DEFAULT;
        pref.kex = std::borrow::Cow::Borrowed(&[KEX_NONE]);
        // Client KEXINIT below offers cipher "none"; match that name.
        pref.cipher = std::borrow::Cow::Borrowed(&[crate::cipher::NONE]);
        pref.mac = std::borrow::Cow::Borrowed(&[crate::mac::NONE]);
        pref.compression = std::borrow::Cow::Borrowed(&[
            crate::compression::ZLIB_LEGACY,
            crate::compression::NONE,
        ]);
        pref.key = std::borrow::Cow::Borrowed(&[Algorithm::Ed25519]);

        let key = ssh_key::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let names = NegServer::read_kex(
            &buf,
            &pref,
            Some(std::slice::from_ref(&key)),
            &KexCause::Initial,
        )
        .expect("asymmetric kexinit must negotiate");

        assert!(
            matches!(names.client_compression, Compression::None),
            "c2s list was none-only → client_compression=None"
        );
        assert!(
            matches!(names.server_compression, Compression::ZlibOpenSSH),
            "s2c listed zlib@openssh.com first in intersection → server_compression=ZlibOpenSSH"
        );

        // Simulate Done-path take: outbound must be server_compression.
        let mut newkeys = NewKeys {
            exchange: Exchange::new(b"SSH-2.0-c", b"SSH-2.0-s"),
            names,
            kex: KEXES.get(&KEX_NONE).unwrap().make(),
            key: 0,
            cipher: crate::cipher::CipherPair {
                local_to_remote: Box::new(crate::cipher::clear::Key {}),
                remote_to_local: Box::new(crate::cipher::clear::Key {}),
            },
            session_id: CryptoVec::new(),
        };
        let half = ServerKex::take_outbound_from_newkeys(&mut newkeys, false);
        assert!(
            matches!(half.compression, Compression::ZlibOpenSSH),
            "server outbound half must follow server_compression, not client_compression"
        );

        // Reverse asymmetry: c2s=zlib, s2c=none.
        let mut buf2 = Vec::new();
        msg::KEXINIT.encode(&mut buf2).unwrap();
        buf2.extend_from_slice(&[0u8; 16]);
        NameList(vec!["none".into()]).encode(&mut buf2).unwrap();
        NameList(vec!["ssh-ed25519".into()])
            .encode(&mut buf2)
            .unwrap();
        NameList(vec!["none".into()]).encode(&mut buf2).unwrap();
        NameList(vec!["none".into()]).encode(&mut buf2).unwrap();
        NameList(vec!["none".into()]).encode(&mut buf2).unwrap();
        NameList(vec!["none".into()]).encode(&mut buf2).unwrap();
        NameList(vec!["zlib@openssh.com".into(), "none".into()])
            .encode(&mut buf2)
            .unwrap(); // c2s
        NameList(vec!["none".into()]).encode(&mut buf2).unwrap(); // s2c
        NameList(vec![]).encode(&mut buf2).unwrap();
        NameList(vec![]).encode(&mut buf2).unwrap();
        0u8.encode(&mut buf2).unwrap();
        0u32.encode(&mut buf2).unwrap();

        let names2 = NegServer::read_kex(
            &buf2,
            &pref,
            Some(std::slice::from_ref(&key)),
            &KexCause::Initial,
        )
        .expect("reverse asymmetric kexinit");
        assert!(matches!(names2.client_compression, Compression::ZlibOpenSSH));
        assert!(matches!(names2.server_compression, Compression::None));
        let mut newkeys2 = NewKeys {
            exchange: Exchange::new(b"SSH-2.0-c", b"SSH-2.0-s"),
            names: names2,
            kex: KEXES.get(&KEX_NONE).unwrap().make(),
            key: 0,
            cipher: crate::cipher::CipherPair {
                local_to_remote: Box::new(crate::cipher::clear::Key {}),
                remote_to_local: Box::new(crate::cipher::clear::Key {}),
            },
            session_id: CryptoVec::new(),
        };
        let half2 = ServerKex::take_outbound_from_newkeys(&mut newkeys2, false);
        assert!(
            matches!(half2.compression, Compression::None),
            "server outbound must be None when s2c negotiated none"
        );
    }
}
