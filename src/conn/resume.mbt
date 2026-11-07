// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What a client must keep for the next connection (RFC 9000 §7.4.1). A ticket is TLS's, but the
// limits 0-RTT data may spend are QUIC's: the flow-control credit, the largest datagram frame and
// the path count the server declared on the connection the ticket came from. §7.4.1 forbids
// guessing them and forbids using more than was remembered, so the two have to be kept together —
// a ticket without its parameters is a ticket a client cannot safely send under.

///|
/// A ticket and the transport parameters the server declared when it issued it: what a client keeps
/// from one connection to resume the next with early data.
pub(all) struct Remembered {
  /// The TLS session, which is the ticket and the secret that unseals its early data.
  session : @tls.Session
  /// The server's transport parameters, exactly as they arrived in EncryptedExtensions.
  params : Bytes
}

///|
/// What early data may spend before the handshake's own parameters arrive: the connection-wide
/// credit, the credit on each bidirectional and unidirectional stream, and the largest datagram
/// frame, all as the connection the ticket came from declared them (RFC 9000 §7.4.1).
fn early_credit(
  cfg : Config,
  resumption : Remembered?,
) -> (UInt64, UInt64, UInt64, UInt64) {
  let peer = match resumption {
    Some(r) =>
      match decode_opt(r.params[:]) {
        Some(params) => Limits::read(params[:])
        None => limits
      }
    None => limits
  }
  // The two Config fields overrule what was remembered rather than add to it: a caller that knows
  // better than the last connection says so here, and zero means "use what the ticket
  // remembered". §7.4.1 puts the remembered values as the ceiling, so an override above them
  // earns a flow-control error from the server rather than a wider window.
  let data = if cfg.zero_rtt_data > 0UL { cfg.zero_rtt_data } else { peer.data }
  let bidi = if cfg.zero_rtt_stream_data > 0UL {
    cfg.zero_rtt_stream_data
  } else {
    peer.stream_data_bidi_remote
  }
  let uni = if cfg.zero_rtt_stream_data > 0UL {
    cfg.zero_rtt_stream_data
  } else {
    peer.stream_data_uni
  }
  (data, bidi, uni, peer.datagram_frame)
}

///|
/// The ticket this connection received and the parameters it was issued under, for the next
/// connection to resume from. `None` before the handshake is done, when the server issued no
/// ticket, or when the client was configured without a session store to keep one in.
pub fn Client::remembered(self : Client) -> Remembered? {
  guard self.tls.is_connected() && self.peer_params.length() > 0 else {
    return None
  }
  let store = match self.sessions {
    Some(store) => store
    None => return None
  }
  match store.get(host=self.host, version=Tls13, now=self.wall) {
    Some(session) => Some({ session, params: self.peer_params, })
    None => None
  }
}

///|
/// Put a remembered ticket where the handshake will offer it, so a client built from
/// `Client::remembered` of an earlier connection resumes without the caller moving bytes about.
fn Client::adopt_ticket(self : Client, resumption : Remembered) -> Unit {
  guard self.sessions is Some(store) else { return }
  match store.find(ticket=resumption.session.ticket[:]) {
    Some(_) => ()
    None => store.put(resumption.session)
  }
}
