//! G5 facade skin. Handshake / SessionTask (`facade_cmd_tx == None`) still
//! forward 1:1 into `*_apply`. After the auth barrier the Executor-side proxy
//! (`facade_cmd_tx == Some`) sends a bounded command + waits the oneshot so
//! the method returns only after SessionTask has run the same `*_apply` body
//! (scheme 2). Queue full → `Err` (never park on enqueue). `accept`/`reject`
//! do not enter this queue.

use tokio::sync::oneshot;

use super::executor::{facade_try_send, wait_facade_oneshot, FacadeCmd};
use super::session::{Handle, Session};
use super::Config;
use crate::{ChannelId, Disconnect, Error, Sig};

impl Session {
    fn push_facade(&self, cmd: FacadeCmd) -> Result<(), Error> {
        let tx = self.facade_cmd_tx.as_ref().ok_or(Error::SendError)?;
        facade_try_send(tx, cmd)?;
        self.facade_notify.notify_waiters();
        Ok(())
    }

    fn facade_ok(&self, cmd: FacadeCmd, rx: oneshot::Receiver<Result<(), Error>>) -> Result<(), Error> {
        self.push_facade(cmd)?;
        wait_facade_oneshot(rx)?
    }

    /// Get a handle to this session.
    pub fn handle(&self) -> Handle {
        self.handle_apply()
    }

    pub fn writable_packet_size(&self, channel: &ChannelId) -> u32 {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            if self
                .push_facade(FacadeCmd::WritablePacketSize {
                    channel: *channel,
                    reply: r,
                })
                .is_err()
            {
                return 0;
            }
            return wait_facade_oneshot(rx).unwrap_or(0);
        }
        self.writable_packet_size_apply(channel)
    }

    pub fn window_size(&self, channel: &ChannelId) -> u32 {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            if self.push_facade(

                FacadeCmd::WindowSize {
                    channel: *channel,
                    reply: r,
                },
            )
            .is_err()
            {
                return 0;
            }
            return wait_facade_oneshot(rx).unwrap_or(0);
        }
        self.window_size_apply(channel)
    }

    pub fn max_packet_size(&self, channel: &ChannelId) -> u32 {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            if self.push_facade(

                FacadeCmd::MaxPacketSize {
                    channel: *channel,
                    reply: r,
                },
            )
            .is_err()
            {
                return 0;
            }
            return wait_facade_oneshot(rx).unwrap_or(0);
        }
        self.max_packet_size_apply(channel)
    }

    /// Flush the session: stage plaintext packets then seal via Writer (S2b)
    /// or local PacketWriter (pre-spawn / tests).
    ///
    /// Always retries [`pending_outbound`] first; never lets a newer `enc.write`
    /// bulk leapfrog older parked cmds (incl. compress barrier).
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(FacadeCmd::Flush { reply: r }, rx);
        }
        self.flush_apply()
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> Result<usize, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(FacadeCmd::FlushPending { channel, reply: r })?;
            return wait_facade_oneshot(rx)?;
        }
        self.flush_pending_apply(channel)
    }

    /// Emit head-of-lane fences only (no DATA). Used so EOF/CLOSE/SUCCESS
    /// are not locked by a zero window, without dumping DATA past HWM.
    pub fn flush_pending_fences(&mut self, channel: ChannelId) -> Result<usize, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(FacadeCmd::FlushPendingFences { channel, reply: r })?;
            return wait_facade_oneshot(rx)?;
        }
        self.flush_pending_fences_apply(channel)
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            if self
                .push_facade(FacadeCmd::SenderWindowSize { channel, reply: r })
                .is_err()
            {
                return 0;
            }
            return wait_facade_oneshot(rx).unwrap_or(0);
        }
        self.sender_window_size_apply(channel)
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            if self
                .push_facade(FacadeCmd::HasPendingData { channel, reply: r })
                .is_err()
            {
                return false;
            }
            return wait_facade_oneshot(rx).unwrap_or(false);
        }
        self.has_pending_data_apply(channel)
    }

    /// Retrieves the configuration of this session.
    pub fn config(&self) -> &Config {
        self.config_apply()
    }

    /// Sends a disconnect message.
    pub fn disconnect(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::Disconnect {
                    reason,
                    description: description.to_string(),
                    language_tag: language_tag.to_string(),
                    reply: r,
                },
                rx,
            );
        }
        self.disconnect_apply(reason, description, language_tag)
    }

    /// Sends a debug message to the client.
    ///
    /// Debug messages are intended for debugging purposes and may be
    /// optionally displayed by the client, depending on the
    /// `always_display` flag and client configuration.
    ///
    /// # Parameters
    ///
    /// - `always_display`: If `true`, the client is encouraged to
    ///   display the message regardless of user preferences.
    /// - `message`: The debug message to be sent.
    /// - `language_tag`: The language tag of the message.
    ///
    /// # Notes
    ///
    /// This message is informational and does not affect the SSH session
    /// state. Most clients (e.g., OpenSSH) will only display the message
    /// if verbose mode is enabled.
    pub fn debug(
        &mut self,
        always_display: bool,
        message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::Debug {
                    always_display,
                    message: message.to_string(),
                    language_tag: language_tag.to_string(),
                    reply: r,
                },
                rx,
            );
        }
        self.debug_apply(always_display, message, language_tag)
    }

    /// Send a "success" reply to a /global/ request (requests without
    /// a channel number, such as TCP/IP forwarding or
    /// cancelling). Always call this function if the request was
    /// successful (it checks whether the client expects an answer).
    pub fn request_success(&mut self) {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            let _ = self.facade_ok(FacadeCmd::RequestSuccess { reply: r }, rx);
            return;
        }
        self.request_success_apply()
    }

    /// Send a "failure" reply to a global request.
    pub fn request_failure(&mut self) {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            let _ = self.facade_ok(FacadeCmd::RequestFailure { reply: r }, rx);
            return;
        }
        self.request_failure_apply()
    }

    /// Send a "success" reply to a channel request. Always call this
    /// function if the request was successful (it checks whether the
    /// client expects an answer).
    pub fn channel_success(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(FacadeCmd::ChannelSuccess { channel, reply: r }, rx);
        }
        self.channel_success_apply(channel)
    }

    /// Send a "failure" reply to a channel request.
    pub fn channel_failure(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(FacadeCmd::ChannelFailure { channel, reply: r }, rx);
        }
        self.channel_failure_apply(channel)
    }

    /// Send a "failure" reply to a request to open a channel open.
    pub fn channel_open_failure(
        &mut self,
        channel: ChannelId,
        reason: crate::ChannelOpenFailure,
        description: &str,
        language: &str,
    ) -> Result<(), crate::Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::ChannelOpenFailure {
                    channel,
                    reason,
                    description: description.to_string(),
                    language: language.to_string(),
                    reply: r,
                },
                rx,
            );
        }
        self.channel_open_failure_apply(channel, reason, description, language)
    }

    /// Close a channel.
    pub fn close(&mut self, channel: ChannelId) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(FacadeCmd::Close { channel, reply: r }, rx);
        }
        self.close_apply(channel)
    }

    /// Send EOF to a channel
    pub fn eof(&mut self, channel: ChannelId) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(FacadeCmd::Eof { channel, reply: r }, rx);
        }
        self.eof_apply(channel)
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn data(&mut self, channel: ChannelId, data: impl Into<bytes::Bytes>) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::Data {
                    channel,
                    data: data.into(),
                    reply: r,
                },
                rx,
            );
        }
        self.data_apply(channel, data)
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn extended_data(
        &mut self,
        channel: ChannelId,
        extended: u32,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::ExtendedData {
                    channel,
                    ext: extended,
                    data: data.into(),
                    reply: r,
                },
                rx,
            );
        }
        self.extended_data_apply(channel, extended, data)
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub fn xon_xoff_request(
        &mut self,
        channel: ChannelId,
        client_can_do: bool,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::XonXoff {
                    channel,
                    client_can_do,
                    reply: r,
                },
                rx,
            );
        }
        self.xon_xoff_request_apply(channel, client_can_do)
    }

    /// Ping the client to verify there is still connectivity.
    pub fn keepalive_request(&mut self) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(FacadeCmd::Keepalive { reply: r }, rx);
        }
        self.keepalive_request_apply()
    }

    /// Ping the client with a Keepalive and get a notification when the client responds.
    pub fn send_ping(&mut self, reply_channel: oneshot::Sender<()>) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::SendPing {
                    reply_channel,
                    reply: r,
                },
                rx,
            );
        }
        self.send_ping_apply(reply_channel)
    }

    /// Send the exit status of a program.
    pub fn exit_status_request(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::ExitStatus {
                    channel,
                    exit_status,
                    reply: r,
                },
                rx,
            );
        }
        self.exit_status_request_apply(channel, exit_status)
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub fn exit_signal_request(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        core_dumped: bool,
        error_message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            return self.facade_ok(
                FacadeCmd::ExitSignal {
                    channel,
                    signal,
                    core_dumped,
                    error_message: error_message.to_string(),
                    language_tag: language_tag.to_string(),
                    reply: r,
                },
                rx,
            );
        }
        self.exit_signal_request_apply(channel, signal, core_dumped, error_message, language_tag)
    }

    /// Opens a new session channel on the client.
    pub fn channel_open_session(&mut self) -> Result<ChannelId, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(FacadeCmd::ChannelOpenSession { reply: r })?;
            return wait_facade_oneshot(rx)?;
        }
        self.channel_open_session_apply()
    }

    /// Opens a direct-tcpip channel on the client (non-standard).
    pub fn channel_open_direct_tcpip(
        &mut self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(

                FacadeCmd::ChannelOpenDirectTcpip {
                    host_to_connect: host_to_connect.to_string(),
                    port_to_connect,
                    originator_address: originator_address.to_string(),
                    originator_port,
                    reply: r,
                },
            )?;
            return wait_facade_oneshot(rx)?;
        }
        self.channel_open_direct_tcpip_apply(
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
        )
    }

    /// Opens a direct-streamlocal channel on the client (non-standard).
    pub fn channel_open_direct_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(

                FacadeCmd::ChannelOpenDirectStreamlocal {
                    socket_path: socket_path.to_string(),
                    reply: r,
                },
            )?;
            return wait_facade_oneshot(rx)?;
        }
        self.channel_open_direct_streamlocal_apply(socket_path)
    }

    /// Open a TCP/IP forwarding channel, when a connection comes to a
    /// local port for which forwarding has been requested. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub fn channel_open_forwarded_tcpip(
        &mut self,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(

                FacadeCmd::ChannelOpenForwardedTcpip {
                    connected_address: connected_address.to_string(),
                    connected_port,
                    originator_address: originator_address.to_string(),
                    originator_port,
                    reply: r,
                },
            )?;
            return wait_facade_oneshot(rx)?;
        }
        self.channel_open_forwarded_tcpip_apply(
            connected_address,
            connected_port,
            originator_address,
            originator_port,
        )
    }

    pub fn channel_open_forwarded_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(

                FacadeCmd::ChannelOpenForwardedStreamlocal {
                    socket_path: socket_path.to_string(),
                    reply: r,
                },
            )?;
            return wait_facade_oneshot(rx)?;
        }
        self.channel_open_forwarded_streamlocal_apply(socket_path)
    }

    /// Open a new X11 channel, when a connection comes to a
    /// local port. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.2).
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub fn channel_open_x11(
        &mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(

                FacadeCmd::ChannelOpenX11 {
                    originator_address: originator_address.to_string(),
                    originator_port,
                    reply: r,
                },
            )?;
            return wait_facade_oneshot(rx)?;
        }
        self.channel_open_x11_apply(originator_address, originator_port)
    }

    /// Opens a new agent channel on the client.
    pub fn channel_open_agent(&mut self) -> Result<ChannelId, Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(FacadeCmd::ChannelOpenAgent { reply: r })?;
            return wait_facade_oneshot(rx)?;
        }
        self.channel_open_agent_apply()
    }

    /// Requests that the client forward connections to the given host and port.
    /// See [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The client
    /// will open forwarded_tcpip channels for each connection.
    pub fn tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(

                FacadeCmd::TcpipForward {
                    address: address.to_string(),
                    port,
                    reply_channel,
                    reply: r,
                },
            )?;
            return wait_facade_oneshot(rx)?;
        }
        self.tcpip_forward_apply(address, port, reply_channel)
    }

    /// Cancels a previously tcpip_forward request.
    pub fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<bool>>,
    ) -> Result<(), Error> {
        if self.facade_cmd_tx.is_some() {
            let (r, rx) = oneshot::channel();
            self.push_facade(

                FacadeCmd::CancelTcpipForward {
                    address: address.to_string(),
                    port,
                    reply_channel,
                    reply: r,
                },
            )?;
            return wait_facade_oneshot(rx)?;
        }
        self.cancel_tcpip_forward_apply(address, port, reply_channel)
    }

    /// Returns the SSH ID (Protocol Version + Software Version) the client sent when connecting
    ///
    /// This should contain only ASCII characters for implementations conforming to RFC4253, Section 4.2:
    ///
    /// > Both the 'protoversion' and 'softwareversion' strings MUST consist of
    /// > printable US-ASCII characters, with the exception of whitespace
    /// > characters and the minus sign (-).
    ///
    /// So it usually is fine to convert it to a [`String`] using [`String::from_utf8_lossy`]
    pub fn remote_sshid(&self) -> &[u8] {
        self.remote_sshid_apply()
    }
}
