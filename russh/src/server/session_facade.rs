//! S4a G5 facade skin: public `Session` methods forward 1:1 into `*_apply`.
//!
//! S4b replaces these bodies with command-queue sends. Do not change
//! signatures. Do not move field layout or `*_apply` implementations here.

use tokio::sync::oneshot;

use super::session::{Handle, Session};
use super::Config;
use crate::{ChannelId, Disconnect, Error, Sig};

impl Session {
    /// Get a handle to this session.
    pub fn handle(&self) -> Handle {
        self.handle_apply()
    }

    pub fn writable_packet_size(&self, channel: &ChannelId) -> u32 {
        self.writable_packet_size_apply(channel)
    }

    pub fn window_size(&self, channel: &ChannelId) -> u32 {
        self.window_size_apply(channel)
    }

    pub fn max_packet_size(&self, channel: &ChannelId) -> u32 {
        self.max_packet_size_apply(channel)
    }

    /// Flush the session: stage plaintext packets then seal via Writer (S2b)
    /// or local PacketWriter (pre-spawn / tests).
    ///
    /// Always retries [`pending_outbound`] first; never lets a newer `enc.write`
    /// bulk leapfrog older parked cmds (incl. compress barrier).
    pub fn flush(&mut self) -> Result<(), Error> {
        self.flush_apply()
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> Result<usize, Error> {
        self.flush_pending_apply(channel)
    }

    /// Emit head-of-lane fences only (no DATA). Used so EOF/CLOSE/SUCCESS
    /// are not locked by a zero window, without dumping DATA past HWM.
    pub fn flush_pending_fences(&mut self, channel: ChannelId) -> Result<usize, Error> {
        self.flush_pending_fences_apply(channel)
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        self.sender_window_size_apply(channel)
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
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
        self.debug_apply(always_display, message, language_tag)
    }

    /// Send a "success" reply to a /global/ request (requests without
    /// a channel number, such as TCP/IP forwarding or
    /// cancelling). Always call this function if the request was
    /// successful (it checks whether the client expects an answer).
    pub fn request_success(&mut self) {
        self.request_success_apply()
    }

    /// Send a "failure" reply to a global request.
    pub fn request_failure(&mut self) {
        self.request_failure_apply()
    }

    /// Send a "success" reply to a channel request. Always call this
    /// function if the request was successful (it checks whether the
    /// client expects an answer).
    pub fn channel_success(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        self.channel_success_apply(channel)
    }

    /// Send a "failure" reply to a channel request.
    pub fn channel_failure(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
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
        self.channel_open_failure_apply(channel, reason, description, language)
    }

    /// Close a channel.
    pub fn close(&mut self, channel: ChannelId) -> Result<(), Error> {
        self.close_apply(channel)
    }

    /// Send EOF to a channel
    pub fn eof(&mut self, channel: ChannelId) -> Result<(), Error> {
        self.eof_apply(channel)
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn data(&mut self, channel: ChannelId, data: impl Into<bytes::Bytes>) -> Result<(), Error> {
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
        self.xon_xoff_request_apply(channel, client_can_do)
    }

    /// Ping the client to verify there is still connectivity.
    pub fn keepalive_request(&mut self) -> Result<(), Error> {
        self.keepalive_request_apply()
    }

    /// Ping the client with a Keepalive and get a notification when the client responds.
    pub fn send_ping(&mut self, reply_channel: oneshot::Sender<()>) -> Result<(), Error> {
        self.send_ping_apply(reply_channel)
    }

    /// Send the exit status of a program.
    pub fn exit_status_request(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
    ) -> Result<(), Error> {
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
        self.exit_signal_request_apply(channel, signal, core_dumped, error_message, language_tag)
    }

    /// Opens a new session channel on the client.
    pub fn channel_open_session(&mut self) -> Result<ChannelId, Error> {
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
        self.channel_open_x11_apply(originator_address, originator_port)
    }

    /// Opens a new agent channel on the client.
    pub fn channel_open_agent(&mut self) -> Result<ChannelId, Error> {
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
        self.tcpip_forward_apply(address, port, reply_channel)
    }

    /// Cancels a previously tcpip_forward request.
    pub fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<bool>>,
    ) -> Result<(), Error> {
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
