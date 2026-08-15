//! S6c: compression epoch matrix + shared `newkeys` writeback.
//!
//! Requires `--features _test_hooks` (and `flate2` for C1–C5).
//!
//! cargo test -p russh --features _test_hooks --test test_s6c_compression -- --nocapture --test-threads=1

#![cfg(feature = "_test_hooks")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{
    self, Auth, CompressionObserveSlot, DisconnectCauseSlot, KexInstallObserveSlot,
};
use russh::{
    compression, newkeys_rewrites_compression_enums, ChannelId, ChannelMsg, KexCompressionOverride,
    Preferred, SkipNewkeysWriteback, client,
};
use ssh_key::PrivateKey;
use tokio::sync::Mutex;
use tokio::time::sleep;

static SERIAL: Mutex<()> = Mutex::const_new(());

const TAG_NONE: u8 = 0;
const TAG_ZLIB: u8 = 1;
const TAG_ZLIB_OPENSSH: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    StaleCodec,
    EnumNotWritten,
    ContextNotReset,
}

async fn wait_for<F: FnMut() -> bool>(
    what: &str,
    timeout: Duration,
    mut f: F,
) -> Result<(), anyhow::Error> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if f() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("HARD: timeout waiting {what}")
}

fn preferred_with(comp: &'static [compression::Name]) -> Preferred {
    let mut p = Preferred::default();
    p.compression = Cow::Borrowed(comp);
    p
}

struct OkClient;
impl client::Handler for OkClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone)]
struct AcceptAll;
impl server::Handler for AcceptAll {
    type Error = russh::Error;
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        _: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let _ = reply.accept().await;
        Ok(())
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

struct S6cEnv {
    session: client::Handle<OkClient>,
    channel: russh::Channel<client::Msg>,
    observe: Arc<KexInstallObserveSlot>,
    comp: Arc<CompressionObserveSlot>,
    cause: Arc<DisconnectCauseSlot>,
    _override: Option<KexCompressionOverride>,
}

async fn connect_s6c(
    initial: Preferred,
    invert: bool,
) -> Result<S6cEnv, anyhow::Error> {
    let observe = KexInstallObserveSlot::new();
    let comp = CompressionObserveSlot::new();
    let cause = DisconnectCauseSlot::new();
    let mut server_config = server::Config::default();
    server_config.preferred = initial.clone();
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    server_config.inactivity_timeout = None;
    server_config.kex_install_observe = Some(observe.clone());
    server_config.compression_observe = Some(comp.clone());
    server_config.disconnect_cause_slot = Some(cause.clone());
    server_config.invert_keep_old_decompress = invert;
    let server_config = Arc::new(server_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let _ = server::run_stream(server_config, sock, AcceptAll).await;
    });

    let mut client_config = client::Config::default();
    client_config.preferred = initial;
    let mut session = client::connect(Arc::new(client_config), addr, OkClient).await?;
    let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    let ok = session
        .authenticate_publickey("user", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await?
        .success();
    if !ok {
        anyhow::bail!("auth failed");
    }
    let channel = session.channel_open_session().await?;
    Ok(S6cEnv {
        session,
        channel,
        observe,
        comp,
        cause,
        _override: None,
    })
}

async fn rekey_with(
    env: &mut S6cEnv,
    list: &'static [compression::Name],
    expect_client: u8,
    expect_server: u8,
) -> Result<(), anyhow::Error> {
    env._override = Some(KexCompressionOverride::set(list));
    env.session.rekey_soon().await?;
    wait_for("rekey idle + compression enums", Duration::from_secs(8), || {
        env.observe.phase() == 0
            && !env.observe.non_idle()
            && env.comp.client_tag() == expect_client
            && env.comp.server_tag() == expect_server
    })
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "{e} (phase={} non_idle={} c_tag={} s_tag={} expect={}/{} inbound={} outbound={} resets={})",
            env.observe.phase(),
            env.observe.non_idle(),
            env.comp.client_tag(),
            env.comp.server_tag(),
            expect_client,
            expect_server,
            env.comp.inbound_activated(),
            env.comp.outbound_activated(),
            env.comp.zlib_context_resets()
        )
    })
}

async fn expect_echo(
    channel: &mut russh::Channel<client::Msg>,
    want: &[u8],
) -> Result<(), anyhow::Error> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            anyhow::bail!("HARD: timeout waiting echo");
        }
        match tokio::time::timeout(left, channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                anyhow::ensure!(&*data == want, "HARD: echo mismatch");
                return Ok(());
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("HARD: channel closed waiting echo"),
            Err(_) => anyhow::bail!("HARD: timeout waiting echo"),
        }
    }
}

/// C1: none → zlib after auth. Next data still flows.
#[cfg(feature = "flate2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c1_none_to_zlib() -> Result<(), anyhow::Error> {
    let _g = SERIAL.lock().await;
    let _ = env_logger::builder().is_test(false).try_init();
    let mut env = connect_s6c(Preferred::default(), false).await?;
    rekey_with(
        &mut env,
        &[compression::ZLIB, compression::NONE],
        TAG_ZLIB,
        TAG_ZLIB,
    )
    .await?;
    env.channel.data(&b"c1-post-zlib"[..]).await?;
    expect_echo(&mut env.channel, b"c1-post-zlib").await?;
    assert!(env.cause.get().is_none(), "C1 HARD: session must stay up");
    Ok(())
}

/// C1 invert: keep None decompress after zlib install → peer data convicts.
#[cfg(feature = "flate2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invert_c1_stale_none_is_red() -> Result<(), anyhow::Error> {
    let _g = SERIAL.lock().await;
    let _ = env_logger::builder().is_test(false).try_init();
    let mut env = connect_s6c(Preferred::default(), true).await?;
    rekey_with(
        &mut env,
        &[compression::ZLIB, compression::NONE],
        TAG_ZLIB,
        TAG_ZLIB,
    )
    .await?;
    assert!(
        !env.comp.inbound_activated(),
        "invert must skip inbound decompress rebuild"
    );
    let _ = env.channel.data(&b"c1-invert"[..]).await;
    // Stale None decompress does not decode CHANNEL_DATA, so the echo
    // never comes back. Unknown-msg is not a disconnect (debug only).
    let echoed = tokio::time::timeout(Duration::from_millis(800), env.channel.wait()).await;
    match echoed {
        Ok(Some(ChannelMsg::Data { .. })) => {
            anyhow::bail!("invert C1 class {:?}: stale none still decoded zlib data", Class::StaleCodec)
        }
        _ => Ok(()),
    }
}

/// C2: zlib → none.
#[cfg(feature = "flate2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c2_zlib_to_none() -> Result<(), anyhow::Error> {
    let _g = SERIAL.lock().await;
    let _ = env_logger::builder().is_test(false).try_init();
    let pref = preferred_with(&[compression::ZLIB, compression::NONE]);
    let mut env = connect_s6c(pref, false).await?;
    rekey_with(&mut env, &[compression::NONE], TAG_NONE, TAG_NONE).await?;
    env.channel.data(&b"c2-post-none"[..]).await?;
    expect_echo(&mut env.channel, b"c2-post-none").await?;
    assert!(env.cause.get().is_none(), "C2 HARD: session must stay up");
    Ok(())
}

/// C2 invert: keep zlib codec after none install.
#[cfg(feature = "flate2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invert_c2_stale_zlib_is_red() -> Result<(), anyhow::Error> {
    let _g = SERIAL.lock().await;
    let _ = env_logger::builder().is_test(false).try_init();
    let pref = preferred_with(&[compression::ZLIB, compression::NONE]);
    let mut env = connect_s6c(pref, true).await?;
    rekey_with(&mut env, &[compression::NONE], TAG_NONE, TAG_NONE).await?;
    let _ = env.channel.data(&b"c2-invert"[..]).await;
    wait_for("invert C2 disconnect", Duration::from_secs(5), || {
        env.cause.get().is_some()
    })
    .await
    .map_err(|_| anyhow::anyhow!("{:?}", Class::StaleCodec))?;
    Ok(())
}

/// C3: none → zlib@openssh.com post-auth; activate immediately.
#[cfg(feature = "flate2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c3_none_to_zlib_openssh_activates() -> Result<(), anyhow::Error> {
    let _g = SERIAL.lock().await;
    let _ = env_logger::builder().is_test(false).try_init();
    let mut env = connect_s6c(Preferred::default(), false).await?;
    rekey_with(
        &mut env,
        &[compression::ZLIB_LEGACY, compression::NONE],
        TAG_ZLIB_OPENSSH,
        TAG_ZLIB_OPENSSH,
    )
    .await?;
    assert!(
        env.comp.inbound_activated() && env.comp.outbound_activated(),
        "C3 HARD: post-auth rekey must activate zlib@openssh.com immediately \
         (in={} out={})",
        env.comp.inbound_activated(),
        env.comp.outbound_activated()
    );
    env.channel.data(&b"c3-post-legacy"[..]).await?;
    expect_echo(&mut env.channel, b"c3-post-legacy").await?;
    assert!(env.cause.get().is_none(), "C3 HARD: session must stay up");
    Ok(())
}

/// C4: zlib → zlib@openssh.com writes back the new enum and resets flate2.
#[cfg(feature = "flate2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c4_zlib_to_zlib_openssh_resets() -> Result<(), anyhow::Error> {
    let _g = SERIAL.lock().await;
    let _ = env_logger::builder().is_test(false).try_init();
    let pref = preferred_with(&[compression::ZLIB, compression::NONE]);
    let mut env = connect_s6c(pref, false).await?;
    rekey_with(
        &mut env,
        &[compression::ZLIB_LEGACY, compression::NONE],
        TAG_ZLIB_OPENSSH,
        TAG_ZLIB_OPENSSH,
    )
    .await?;
    assert!(
        env.comp.zlib_context_resets() >= 1,
        "C4 HARD: init_* must reset an existing flate2 context (resets={})",
        env.comp.zlib_context_resets()
    );
    env.channel.data(&b"c4-post-legacy"[..]).await?;
    expect_echo(&mut env.channel, b"c4-post-legacy").await?;
    let resets_after_first = env.comp.zlib_context_resets();
    rekey_with(
        &mut env,
        &[compression::ZLIB, compression::NONE],
        TAG_ZLIB,
        TAG_ZLIB,
    )
    .await?;
    assert!(
        env.comp.zlib_context_resets() > resets_after_first,
        "C4 HARD: reverse zlib@openssh→zlib must reset again (before={resets_after_first} after={})",
        env.comp.zlib_context_resets()
    );
    env.channel.data(&b"c4-post-zlib"[..]).await?;
    expect_echo(&mut env.channel, b"c4-post-zlib").await?;
    assert!(env.cause.get().is_none());
    Ok(())
}

/// C4 invert: keep the previous flate2 context instead of reset.
#[cfg(feature = "flate2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invert_c4_skip_reset_is_red() -> Result<(), anyhow::Error> {
    let _g = SERIAL.lock().await;
    let _ = env_logger::builder().is_test(false).try_init();
    let pref = preferred_with(&[compression::ZLIB, compression::NONE]);
    let mut env = connect_s6c(pref, true).await?;
    let resets_before = env.comp.zlib_context_resets();
    rekey_with(
        &mut env,
        &[compression::ZLIB_LEGACY, compression::NONE],
        TAG_ZLIB_OPENSSH,
        TAG_ZLIB_OPENSSH,
    )
    .await?;
    assert_eq!(
        env.comp.zlib_context_resets(),
        resets_before,
        "C4 invert class {:?}",
        Class::ContextNotReset
    );
    Ok(())
}

/// C6: shared `newkeys` writes back the new algorithm enums.
#[cfg(feature = "flate2")]
#[test]
fn c6_newkeys_writes_back_enums() {
    use russh::compression::Compression;
    let (c, s) = newkeys_rewrites_compression_enums(
        Compression::None,
        Compression::None,
        Compression::Zlib,
        Compression::ZlibOpenSSH,
    );
    assert_eq!(c, Compression::Zlib, "C6 HARD: client_compression written back");
    assert_eq!(
        s,
        Compression::ZlibOpenSSH,
        "C6 HARD: server_compression written back"
    );
}

/// C6 invert: skip writeback → enums stay old (P8-2 original bug).
#[cfg(feature = "flate2")]
#[test]
fn invert_c6_skip_writeback_is_red() {
    use russh::compression::Compression;
    let _skip = SkipNewkeysWriteback::arm();
    let (c, s) = newkeys_rewrites_compression_enums(
        Compression::None,
        Compression::None,
        Compression::Zlib,
        Compression::ZlibOpenSSH,
    );
    assert_eq!(c, Compression::None, "C6 invert class {:?}", Class::EnumNotWritten);
    assert_eq!(s, Compression::None, "C6 invert class {:?}", Class::EnumNotWritten);
}
