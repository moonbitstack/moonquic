// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What RFC 9000 says a peer may send, one case at a time: the QUIC half of the conformance
// suite, driven through the same checks the connection runs. Each test names the section it
// comes from, because a failure should say which rule broke rather than that a byte changed.

///|
/// A connection's standing for a frame check, with a packet-number space that has issued 100
/// packets, so an acknowledgement of anything below that is an acknowledgement of something.
fn standing_of(streams~ : @stream.Streams) -> Standing {
  {
    server: true,
    streams,
    sched: @stream.Scheduler::new(@stream.Budget::new(0UL, 0UL)),
    sent: 100L,
  }
}

///|
fn fresh_streams() -> @stream.Streams {
  @stream.Streams::new(
    0UL,
    0UL,
    server=true,
    bidi=@stream.Quota::new(3UL),
    uni=@stream.Quota::new(3UL),
  )
}

///|
/// The error code a set of frames draws, or 0 when they are all allowed.
fn code_of(
  level : Level,
  frames : Array[@frame.Frame],
  standing : Standing,
) -> UInt64 {
  match frames_fault(level, frames, standing) {
    Some(fault) => fault.code
    None => 0UL
  }
}

///|
test "a stream past the advertised limit is STREAM_LIMIT_ERROR, not flow control (§4.6)" {
  // A client's fourth bidirectional stream, with three allowed.
  let code = code_of(
    Level::Application,
    [Stream(id=12UL, offset=0UL, fin=false, data=b"x")],
    standing_of(streams=fresh_streams()),
  )
  assert_eq(code, stream_limit_error)
}

///|
test "a stream at the limit is fine" {
  let code = code_of(
    Level::Application,
    [Stream(id=8UL, offset=0UL, fin=false, data=b"x")],
    standing_of(streams=fresh_streams()),
  )
  assert_eq(code, 0UL)
}

///|
test "a STREAM frame on a unidirectional stream this end opened is STREAM_STATE_ERROR (§19.8)" {
  let code = code_of(
    Level::Application,
    [Stream(id=3UL, offset=0UL, fin=false, data=b"x")],
    standing_of(streams=fresh_streams()),
  )
  assert_eq(code, stream_state_error)
}

///|
test "a RESET_STREAM on a send-only stream is STREAM_STATE_ERROR (§19.4)" {
  let code = code_of(
    Level::Application,
    [ResetStream(id=3UL, error_code=0UL, final_size=0UL)],
    standing_of(streams=fresh_streams()),
  )
  assert_eq(code, stream_state_error)
}

///|
test "STOP_SENDING or MAX_STREAM_DATA for a stream that does not exist is STREAM_STATE_ERROR" {
  let standing = standing_of(streams=fresh_streams())
  assert_eq(
    code_of(
      Level::Application,
      [StopSending(id=101UL, error_code=0UL)],
      standing,
    ),
    stream_state_error,
  )
  assert_eq(
    code_of(
      Level::Application,
      [MaxStreamData(id=101UL, max=1_000_000UL)],
      standing,
    ),
    stream_state_error,
  )
}

///|
test "MAX_STREAM_DATA for a receive-only stream is STREAM_STATE_ERROR (§19.10)" {
  // Stream 2 is the client's first unidirectional stream: this server only receives on it.
  let code = code_of(
    Level::Application,
    [MaxStreamData(id=2UL, max=1_000_000UL)],
    standing_of(streams=fresh_streams()),
  )
  assert_eq(code, stream_state_error)
}

///|
test "NEW_TOKEN and HANDSHAKE_DONE from a client are PROTOCOL_VIOLATION (§19.7, §19.20)" {
  let standing = standing_of(streams=fresh_streams())
  assert_eq(
    code_of(Level::Application, [NewToken(token=b"t")], standing),
    protocol_violation,
  )
  assert_eq(
    code_of(Level::Application, [HandshakeDone], standing),
    protocol_violation,
  )
}

///|
test "an ACK range below packet zero is FRAME_ENCODING_ERROR (§19.3.1)" {
  let code = code_of(
    Level::Application,
    [Ack(largest=5UL, delay=0UL, first_range=0UL, ranges=[(10UL, 0UL)])],
    standing_of(streams=fresh_streams()),
  )
  assert_eq(code, frame_encoding_error)
}

///|
test "an ACK for a packet never sent is PROTOCOL_VIOLATION (§13.1)" {
  let code = code_of(
    Level::Application,
    [Ack(largest=1_000_000UL, delay=0UL, first_range=0UL, ranges=[])],
    standing_of(streams=fresh_streams()),
  )
  assert_eq(code, protocol_violation)
}

///|
test "MAX_STREAMS and STREAMS_BLOCKED past 2^60 say what §19.11 and §19.14 say" {
  let standing = standing_of(streams=fresh_streams())
  assert_eq(
    code_of(
      Level::Application,
      [MaxStreams(bidi=true, max=max_streams + 1UL)],
      standing,
    ),
    frame_encoding_error,
  )
  let blocked = code_of(
    Level::Application,
    [StreamsBlocked(bidi=true, max=max_streams + 1UL)],
    standing,
  )
  assert_eq(blocked, stream_limit_error)
}

///|
test "a NEW_CONNECTION_ID with no id, or a retire_prior_to past its sequence, is FRAME_ENCODING_ERROR" {
  let standing = standing_of(streams=fresh_streams())
  assert_eq(
    code_of(
      Level::Application,
      [
        NewConnectionId(
          seq=1UL,
          retire_prior_to=0UL,
          conn_id=b"",
          reset_token=Bytes::make(16, 0),
        ),
      ],
      standing,
    ),
    frame_encoding_error,
  )
  assert_eq(
    code_of(
      Level::Application,
      [
        NewConnectionId(
          seq=1UL,
          retire_prior_to=10UL,
          conn_id=b"abcd",
          reset_token=Bytes::make(16, 0),
        ),
      ],
      standing,
    ),
    frame_encoding_error,
  )
}

///|
test "a frame outside its encryption level is PROTOCOL_VIOLATION (§12.4)" {
  let standing = standing_of(streams=fresh_streams())
  assert_eq(
    code_of(Level::Handshake, [PathChallenge(b"01234567")], standing),
    protocol_violation,
  )
  assert_eq(
    code_of(Level::Handshake, [StreamDataBlocked(id=0UL, max=0UL)], standing),
    protocol_violation,
  )
  assert_eq(
    code_of(Level::Handshake, [DataBlocked(0UL)], standing),
    protocol_violation,
  )
  assert_eq(
    code_of(Level::Initial, [NewToken(token=b"t")], standing),
    protocol_violation,
  )
}

///|
test "a packet with no frames is PROTOCOL_VIOLATION (§12.4)" {
  assert_eq(
    code_of(Level::Application, [], standing_of(streams=fresh_streams())),
    protocol_violation,
  )
}

///|
test "a parameter a client may not declare is TRANSPORT_PARAMETER_ERROR (§18.2)" {
  let cases : Array[Array[Param]] = [
    [{ kind: OriginalDcid, value: b"abcd", }],
    [{ kind: PreferredAddress, value: Bytes::make(41, 0), }],
    [{ kind: RetryScid, value: b"abcd", }],
    [{ kind: StatelessResetToken, value: Bytes::make(16, 0), }],
  ]
  for params in cases {
    match params_fault(params[:], server=true) {
      Some(fault) => assert_eq(fault.code, transport_parameter_error)
      None => fail("a server's parameter went through")
    }
  }
}

///|
test "a parameter whose value is malformed is TRANSPORT_PARAMETER_ERROR (§18.1)" {
  let params : Array[Param] = [{ kind: MaxData, value: b"", }]
  match params_fault(params[:], server=true) {
    Some(fault) => assert_eq(fault.code, transport_parameter_error)
    None => fail("an empty varint went through")
  }
}

///|
test "the value bounds of §18.2 are held" {
  let over : Array[Array[Param]] = [
    [Param::int(MaxUdpPayload, 1199UL)],
    [Param::int(AckDelayExponent, 21UL)],
    [Param::int(MaxAckDelay, 1UL << 14)],
    [Param::int(MaxStreamsBidi, max_streams + 1UL)],
    [Param::int(MaxStreamsUni, max_streams + 1UL)],
    [Param::int(ActiveConnectionIdLimit, 1UL)],
  ]
  for params in over {
    match params_fault(params[:], server=true) {
      Some(fault) => assert_eq(fault.code, transport_parameter_error)
      None => fail("a value out of bounds went through")
    }
  }
  // The same values at their limits are fine.
  let at : Array[Param] = [
    Param::int(MaxUdpPayload, 1200UL),
    Param::int(AckDelayExponent, 20UL),
    Param::int(MaxAckDelay, (1UL << 14) - 1UL),
    Param::int(MaxStreamsBidi, max_streams),
  ]
  assert_true(params_fault(at[:], server=true) is None)
}

///|
test "a parameter declared twice is TRANSPORT_PARAMETER_ERROR (§7.4)" {
  let params : Array[Param] = [
    Param::int(MaxData, 1UL),
    Param::int(MaxData, 2UL),
  ]
  match params_fault(params[:], server=true) {
    Some(fault) => assert_eq(fault.code, transport_parameter_error)
    None => fail("a duplicate went through")
  }
}

///|
/// A 1-RTT packet from the connected `client`, numbered past everything it has sent, carrying
/// `frames` — the way a conformance tool injects a case into a live handshake.
fn inject(
  server : Endpoint[String],
  client : Client,
  frames : Array[@frame.Frame],
  pn : Int64,
  now : Int64,
) -> Session[String] raise {
  let packet = send_short(
    client.dcid,
    pn,
    4,
    frames,
    client.app_tx.unwrap(),
    key_phase=client.key_phase,
  )
  server.recv(packet, from, now, wall=WALL)
  only_conn(server)
}

///|
/// The code a connection's CONNECTION_CLOSE names, or 0 when it is not closing.
fn closed_with(conn : Session[String]) -> UInt64 {
  match conn.close_frame {
    Some(ConnectionClose(error_code~, ..)) =>
      if conn.phase() is Closing {
        error_code
      } else {
        0UL
      }
    _ => 0UL
  }
}

///|
test "a live server closes on HANDSHAKE_DONE from its client with PROTOCOL_VIOLATION" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = plain_server()
  exchange(client, server, WALL, 1000L)
  let conn = inject(server, client, [HandshakeDone], 500L, 2000L)
  assert_eq(closed_with(conn), protocol_violation)
}

///|
test "a live server closes on an acknowledgement of a packet it never sent" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = plain_server()
  exchange(client, server, WALL, 1000L)
  let conn = inject(
    server,
    client,
    [Ack(largest=1_000_000UL, delay=0UL, first_range=0UL, ranges=[])],
    500L,
    2000L,
  )
  assert_eq(closed_with(conn), protocol_violation)
}

///|
test "a live server closes on a packet with no frames" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = plain_server()
  exchange(client, server, WALL, 1000L)
  let conn = inject(server, client, [], 500L, 2000L)
  assert_eq(closed_with(conn), protocol_violation)
}

///|
test "a live server closes on a STREAM frame for a stream past its limit" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = plain_server()
  exchange(client, server, WALL, 1000L)
  let conn = inject(
    server,
    client,
    [Stream(id=1_000_000_000UL, offset=0UL, fin=false, data=b"GET /")],
    500L,
    2000L,
  )
  assert_eq(closed_with(conn), stream_limit_error)
}

///|
test "a live server closes on a STREAM frame for a local stream it never opened" {
  let client = resuming_client(@tls.Sessions::new(), WALL)
  let server = plain_server()
  exchange(client, server, WALL, 1000L)
  // Stream 1 is the server's own bidirectional stream, and it has not opened it.
  let conn = inject(
    server,
    client,
    [Stream(id=1UL, offset=0UL, fin=false, data=b"")],
    500L,
    2000L,
  )
  assert_eq(closed_with(conn), stream_state_error)
}
