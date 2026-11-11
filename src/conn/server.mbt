// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A QUIC server connection's Initial-flight processing (RFC 9000 §7, RFC 9001 §5): it
// ties the Initial packet protection, the per-level CRYPTO reassembly, and the TLS 1.3
// handshake runner together. Receiving an Initial packet unprotects it with the keys
// derived from the client's connection id, records the packet number for acknowledgement,
// reassembles the CRYPTO stream, and drives the handshake with the contiguous handshake
// bytes. This is the pure connection core the async UDP transport wraps; feeding it a
// client's Initial packet advances the server handshake to RECVD_CH.

///|
/// A QUIC server connection mid-handshake: the Initial keys, the packet-number/CRYPTO
/// bookkeeping, and the TLS handshake it is driving.
pub struct Server {
  /// The id the Initial keys derive from, kept so a version change can re-derive them.
  dcid : Bytes
  /// The version this endpoint's Initial packets are protected under (RFC 9369 §3.3).
  mut version : UInt32
  initial_keys : @crypto.Keys
  mut reply_keys : @crypto.Keys
  handshake : @hs.Handshake
  conn : Conn
}

///|
/// A server connection for a client whose Destination Connection ID is `dcid` (the
/// Initial secret and keys derive from it, RFC 9001 §5.2).
pub fn Server::new(
  dcid : Bytes,
  version~ : UInt32 = @packet.version1,
) -> Server {
  let constants = @crypto.Version::of(version).unwrap()
  let (client, server) = @crypto.initial(dcid[:], version=constants)
  {
    dcid,
    version,
    initial_keys: client,
    reply_keys: server,
    handshake: @hs.Handshake::new(),
    conn: Conn::new(true),
  }
}

///|
/// Answer under `version` from now on: the reply keys are re-derived from the same connection id
/// under that version's salt (RFC 9369 §3.3), which is what a version negotiated compatibly does
/// to a server's own Initial packets (RFC 9368 §4.1). The keys the client's packets arrive under
/// are left alone, since it may still be sending the version it started with.
pub fn Server::reply_as(self : Server, version : UInt32) -> Unit {
  guard self.version != version else { return }
  let constants = match @crypto.Version::of(version) {
    Some(constants) => constants
    None => return
  }
  let (_, reply) = @crypto.initial(self.dcid[:], version=constants)
  self.reply_keys = reply
  self.version = version
}

///|
/// The current TLS handshake state.
pub fn Server::handshake_state(self : Server) -> @hs.Server {
  self.handshake.state()
}

///|
/// The transcript hash over the handshake messages processed so far.
pub fn Server::transcript_hash(self : Server) -> Bytes {
  self.handshake.transcript()
}

///|
/// The raw ClientHello the connection received (empty before one arrives): the source a
/// server runs the ECDHE key_share from to derive its handshake secrets.
pub fn Server::client_hello(self : Server) -> Bytes {
  self.handshake.hello()
}

///|
/// Negotiate the ClientHello this connection received (RFC 8446 §4.1.1): the group and key
/// share to run the ECDHE with, and the signature scheme to sign the CertificateVerify under,
/// read off what the client offered. Raises the §6 alert for a ClientHello this build cannot
/// serve, and returns `Retry` when the answer is a HelloRetryRequest.
pub fn Server::negotiate(self : Server) -> @hs.Choice raise @alert.Alert {
  self.handshake.negotiate()
}

///|
/// Whether an ACK is owed in the Initial space.
pub fn Server::initial_ack_pending(self : Server) -> Bool {
  self.conn.space(Level::Initial).ack_pending()
}

///|
/// Build the server's ServerHello response: encode it, fold it into the transcript, and
/// protect it into an Initial packet addressed to `out_dcid` (the client's source
/// connection id) from `out_scid`, at Initial packet number `pn` (RFC 9001 §5.3). The
/// state stays at RECVD_CH — the server flight is not complete until the Handshake-space
/// messages (EncryptedExtensions, Certificate, CertificateVerify, Finished) are sent by
/// `send_handshake_flight`, which advances it to WAIT_FINISHED.
pub fn Server::send_server_hello(
  self : Server,
  server_hello : @msg.Server,
  out_dcid : Bytes,
  out_scid : Bytes,
  pn : Int64,
) -> Bytes {
  let sh_msg = @msg.server_hello(server_hello)
  self.handshake.sent(sh_msg[:])
  send_long(
    Initial,
    self.version,
    out_dcid,
    out_scid,
    pn,
    4,
    [@frame.Crypto(offset=0, data=sh_msg)],
    self.reply_keys,
  )
}

///|
/// Send the server's Handshake-space flight (RFC 8446 §4, RFC 9001 §5): encode
/// EncryptedExtensions, Certificate, and CertificateVerify, fold them into the transcript
/// in order, compute the server Finished as `HMAC(finished_key, transcript hash through
/// CertificateVerify)` over `server_hs_secret`, fold the Finished too, and advance the
/// state past the whole flight (RECVD_CH → WAIT_FINISHED). The four messages form one
/// contiguous CRYPTO stream, protected into a Handshake packet with the handshake-space
/// keys `@crypto.Keys::of(server_hs_secret[:])`, addressed to `out_dcid` from `out_scid` at
/// Handshake packet number `pn`. `server_hs_secret` is the server handshake traffic secret
/// the key schedule derives once ECDHE completes.
pub fn Server::send_handshake_flight(
  self : Server,
  server_hs_secret : Bytes,
  encrypted_extensions : Bytes,
  certificate : Bytes,
  verify : (Bytes) -> Bytes,
  out_dcid : Bytes,
  out_scid : Bytes,
  pn : Int64,
) -> Bytes raise {
  let ee = @msg.frame(EncryptedExtensions, encrypted_extensions[:])
  let cert = @msg.frame(Certificate, certificate[:])
  self.handshake.sent(ee[:])
  self.handshake.sent(cert[:])
  // The body is built here rather than passed in, because §4.4.3 signs the transcript
  // as it stands at exactly this point: Certificate folded in, Finished not yet.
  let cv = @msg.frame(CertificateVerify, verify(self.handshake.transcript())[:])
  self.handshake.sent(cv[:])
  let verify_data = @keys.finished(
    server_hs_secret[:],
    self.handshake.transcript()[:],
  )
  let fin = @msg.frame(Finished, verify_data[:])
  self.handshake.sent(fin[:])
  self.handshake.sent_flight(client_cert=false)
  let crypto = join(join(join(ee, cert), cv), fin)
  send_long(
    Handshake,
    self.version,
    out_dcid,
    out_scid,
    pn,
    4,
    [@frame.Crypto(offset=0, data=crypto)],
    @crypto.Keys::of(
      server_hs_secret[:],
      version=@crypto.Version::of(self.version).unwrap(),
    ),
  )
}

///|
/// Drive an already-unprotected packet's `frames` at `level`, numbered `pn`: record the
/// packet for acknowledgement and feed its CRYPTO frames into that level's reassembler,
/// driving the handshake with whatever handshake bytes become contiguous. Returns the
/// handshake message types processed. A driver that unprotected the packet itself — because
/// it also wants the ACK and CONNECTION_CLOSE frames beside the CRYPTO — enters here rather
/// than through `receive_initial`.
pub fn Server::on_frames(
  self : Server,
  level : Level,
  frames : Array[@frame.Frame],
  pn : Int64,
) -> Array[@msg.Kind] raise {
  self.conn.on_packet_received(level, pn, @packet.payload_elicits_ack(frames))
  let processed : Array[@msg.Kind] = []
  for frame in frames {
    match frame {
      Crypto(offset~, data~) => {
        let contiguous = self.conn.on_crypto_frame(level, offset, data)
        if contiguous.length() > 0 {
          for msg_type in self.handshake.feed(contiguous) {
            processed.push(msg_type)
          }
        }
      }
      _ => ()
    }
  }
  processed
}

///|
/// Receive a client Initial packet: unprotect it, record its number for acknowledgement,
/// reassemble its CRYPTO frames, and drive the handshake with the contiguous handshake
/// bytes. Returns the handshake message types processed. Raises if the packet fails to
/// authenticate.
pub fn Server::receive_initial(
  self : Server,
  packet : Bytes,
) -> Array[@msg.Kind] raise {
  let (frames, pn) = match recv_long(packet, self.initial_keys) {
    Some(v) => v
    None => raise @packet.Malformed("Initial packet failed to authenticate")
  }
  self.on_frames(Level::Initial, frames, pn)
}

///|
/// Receive the client's Handshake-space flight — in this no-client-authentication path,
/// the client Finished (RFC 8446 §4.4.4): unprotect the Handshake packet with the client
/// handshake keys, reassemble its CRYPTO stream, verify the Finished `verify_data` against
/// `client_hs_secret` over the transcript through the server Finished, then fold it in to
/// advance the handshake to CONNECTED. Returns whether the handshake is now connected with
/// a Finished that authenticated. Raises if the packet fails to authenticate.
pub fn Server::receive_handshake(
  self : Server,
  packet : Bytes,
  client_hs_keys : @crypto.Keys,
  client_hs_secret : Bytes,
) -> Bool raise {
  let (frames, pn) = match recv_long(packet, client_hs_keys) {
    Some(v) => v
    None => raise @packet.Malformed("Handshake packet failed to authenticate")
  }
  self.on_handshake_frames(frames, pn, client_hs_secret)
}

///|
/// Drive the client's Handshake-space `frames`, numbered `pn`, already unprotected: record
/// the packet, reassemble its CRYPTO stream, verify any Finished in it against
/// `client_hs_secret` over the transcript as it stands, then fold the messages in. Returns
/// whether the handshake is now connected with a Finished that authenticated — the frame-level
/// half of `receive_handshake`, for a driver holding the decrypted packet.
pub fn Server::on_handshake_frames(
  self : Server,
  frames : Array[@frame.Frame],
  pn : Int64,
  client_hs_secret : Bytes,
) -> Bool raise {
  self.conn.on_packet_received(
    Level::Handshake,
    pn,
    @packet.payload_elicits_ack(frames),
  )
  let mut finished_ok = false
  for frame in frames {
    match frame {
      Crypto(offset~, data~) => {
        let contiguous = self.conn.on_crypto_frame(
          Level::Handshake,
          offset,
          data,
        )
        if contiguous.length() > 0 {
          // The Finished MACs the transcript as it stands now (through the server Finished),
          // so verify against the current hash before folding the client Finished in.
          let th = self.handshake.transcript()
          let view = contiguous[:]
          let mut off = 0
          for ;; {
            match @msg.unframe(view[off:]) {
              Some((t, body)) => {
                if t == @msg.Kind::Finished {
                  finished_ok = @keys.finished_ok(
                    client_hs_secret[:],
                    th[:],
                    body[:],
                  )
                }
                off = off + 4 + body.length()
              }
              None => break
            }
          }
          let _ = self.handshake.feed(contiguous)
        }
      }
      _ => ()
    }
  }
  self.handshake.is_connected() && finished_ok
}
