/*
 * A QUIC server that speaks a raw bidirectional stream, built directly on
 * ngtcp2_conn_server_new (ngtcp2 v1.16.0, OpenSSL backend).
 *
 * ngtcp2's shipped examples are HTTP/3 servers: they answer an h3 request with
 * nghttp3 frames, so a client that writes plain bytes on a stream gets nothing
 * back. The one example that reads a raw stream (h09server) is not a CMake
 * target and hard-codes the h3 ALPN, which makes it send alert 120 to a client
 * offering anything else. This peer is the missing direction of the interop
 * matrix: it accepts whatever ALPN the client offers, echoes every byte it
 * receives on the first bidirectional stream, and finishes that stream.
 *
 *     ./peer <port> <key.pem> <cert.pem> <1|2> [prefer <1|2>]
 *
 * It prints `version=0x...`, `alpn=...`, `handshake completed` and
 * `echoed <n> bytes` on stdout, one line each, flushed as they happen, so a
 * driver script can assert on facts rather than on prose. It serves exactly one
 * connection and exits once the echo has been acknowledged.
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#define MAX_PKT 1500
#define SCIDLEN 8
#define ECHO_CAP 65536

static void say(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  putchar('\n');
  fflush(stdout);
}

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

struct peer {
  ngtcp2_conn *conn;
  SSL *ssl;
  ngtcp2_crypto_ossl_ctx *ossl_ctx;
  ngtcp2_crypto_conn_ref conn_ref;

  struct sockaddr_storage local;
  socklen_t local_len;
  struct sockaddr_storage remote;
  socklen_t remote_len;

  uint8_t echo[ECHO_CAP];
  size_t echo_len;
  size_t echo_sent;
  size_t echo_acked;
  int have_stream;
  int64_t stream_id;
  int fin_sent;
  int acked_reported;
  int handshake_done;
  uint64_t finished_at;
};

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
  return ((struct peer *)ref->user_data)->conn;
}

static int alpn_select(SSL *ssl, const unsigned char **out,
                       unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;
  /* Accept the client's first offer. A raw-stream peer has no application
   * protocol of its own, and echoing the ALPN back keeps TLS happy. */
  if (inlen < 2 || in[0] == 0 || in[0] > inlen - 1) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  *out = in + 1;
  *outlen = in[0];
  say("alpn=%.*s", (int)in[0], (const char *)in + 1);
  return SSL_TLSEXT_ERR_OK;
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data) {
  struct peer *p = user_data;
  p->handshake_done = 1;
  say("handshake completed");
  say("negotiated version=0x%08x",
      (unsigned)ngtcp2_conn_get_negotiated_version(conn));
  return 0;
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
  (void)flags;
  (void)offset;
  (void)stream_user_data;
  struct peer *p = user_data;
  if (!p->have_stream) {
    p->have_stream = 1;
    p->stream_id = stream_id;
  }
  if (p->stream_id != stream_id ||
      p->echo_len + datalen > sizeof(p->echo)) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  memcpy(p->echo + p->echo_len, data, datalen);
  p->echo_len += datalen;
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
  ngtcp2_conn_extend_max_offset(conn, datalen);
  return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data,
                                       void *stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)offset;
  (void)stream_user_data;
  struct peer *p = user_data;
  if (p->echo_acked + datalen > p->echo_len) {
    p->echo_acked = p->echo_len;
  } else {
    p->echo_acked += datalen;
  }
  if (p->fin_sent && p->echo_acked >= p->echo_len && !p->acked_reported) {
    p->acked_reported = 1;
    say("echo acknowledged");
  }
  return 0;
}

static int cb_stream_open(ngtcp2_conn *conn, int64_t stream_id,
                          void *user_data) {
  (void)conn;
  (void)stream_id;
  (void)user_data;
  return 0;
}

static int cb_stream_close(ngtcp2_conn *conn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void *user_data, void *stream_user_data) {
  (void)conn;
  (void)flags;
  (void)stream_id;
  (void)app_error_code;
  (void)user_data;
  (void)stream_user_data;
  return 0;
}

static void cb_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  if (RAND_bytes(dest, (int)destlen) != 1) {
    say("error: RAND_bytes failed");
    exit(2);
  }
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;
  if (RAND_bytes(cid->data, (int)cidlen) != 1 ||
      RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  return 0;
}

static int cb_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                      const ngtcp2_crypto_cipher_ctx *hp_ctx,
                      const uint8_t *sample) {
  return ngtcp2_crypto_hp_mask_cb(dest, hp, hp_ctx, sample);
}

static void log_error(const char *what, int rv) {
  say("error: %s: %s", what, ngtcp2_strerror(rv));
}

static int create_connection(struct peer *p, const ngtcp2_pkt_hd *hd,
                             SSL_CTX *ssl_ctx, uint32_t prefer, uint64_t now) {
  ngtcp2_callbacks cb = {0};
  cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cb.handshake_completed = cb_handshake_completed;
  cb.encrypt = ngtcp2_crypto_encrypt_cb;
  cb.decrypt = ngtcp2_crypto_decrypt_cb;
  cb.hp_mask = cb_hp_mask;
  cb.recv_stream_data = cb_recv_stream_data;
  cb.acked_stream_data_offset = cb_acked_stream_data_offset;
  cb.stream_open = cb_stream_open;
  cb.stream_close = cb_stream_close;
  cb.rand = cb_rand;
  cb.get_new_connection_id = cb_get_new_connection_id;
  cb.update_key = ngtcp2_crypto_update_key_cb;
  cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  /* Required when a client's version_information lets this server convert its
   * first flight into a preferred version: the Initial keys are re-derived. */
  cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

  ngtcp2_cid scid = {0};
  scid.datalen = SCIDLEN;
  if (RAND_bytes(scid.data, SCIDLEN) != 1) {
    return -1;
  }

  static uint32_t preferred[1];
  static uint32_t available[1];
  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  /* ngtcp2 asserts that every timestamp it sees is non-decreasing. Using the
   * same instant for the connection's initial_ts and its first read_pkt keeps
   * that true even though the connection is created inside the read path. */
  settings.initial_ts = now;
  settings.handshake_timeout = 30 * NGTCP2_SECONDS;
  /* RFC 9368 §3: a server's Available Versions are the Fully Deployed ones. This peer only
   * fully deploys the version it was asked to speak, which is also what a client that
   * restarted after a Version Negotiation packet checks its choice against. */
  available[0] = hd->version;
  settings.available_versions = available;
  settings.available_versionslen = 1;
  if (prefer) {
    preferred[0] = prefer;
    settings.preferred_versions = preferred;
    settings.preferred_versionslen = 1;
  }

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_data = 1 << 20;
  params.initial_max_stream_data_bidi_local = 1 << 20;
  params.initial_max_stream_data_bidi_remote = 1 << 20;
  params.initial_max_stream_data_uni = 1 << 20;
  params.initial_max_streams_bidi = 10;
  params.initial_max_streams_uni = 3;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 3;
  params.original_dcid = hd->dcid;
  params.original_dcid_present = 1;
  /* ngtcp2 fills initial_scid from the SCID passed to conn_server_new and asserts
   * that an application did not set the field itself. */

  ngtcp2_path path = {
      {(struct sockaddr *)&p->local, p->local_len},
      {(struct sockaddr *)&p->remote, p->remote_len},
      NULL,
  };
  int rv = ngtcp2_conn_server_new(&p->conn, &hd->scid, &scid, &path,
                                  hd->version, &cb, &settings, &params, NULL,
                                  p);
  if (rv != 0) {
    log_error("ngtcp2_conn_server_new", rv);
    return -1;
  }

  if (ngtcp2_crypto_ossl_ctx_new(&p->ossl_ctx, NULL) != 0) {
    say("error: ngtcp2_crypto_ossl_ctx_new failed");
    return -1;
  }
  p->ssl = SSL_new(ssl_ctx);
  if (!p->ssl) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  ngtcp2_crypto_ossl_ctx_set_ssl(p->ossl_ctx, p->ssl);
  if (ngtcp2_crypto_ossl_configure_server_session(p->ssl) != 0) {
    say("error: ngtcp2_crypto_ossl_configure_server_session failed");
    return -1;
  }
  SSL_set_app_data(p->ssl, &p->conn_ref);
  SSL_set_accept_state(p->ssl);
  /* For the OpenSSL backend the native handle is the per-connection ossl ctx,
   * not the SSL object. */
  ngtcp2_conn_set_tls_native_handle(p->conn, p->ossl_ctx);
  return 0;
}

static void answer_with_vn(int fd, const ngtcp2_version_cid *vc,
                           uint32_t wanted, const struct sockaddr *to,
                           socklen_t to_len) {
  uint8_t buf[MAX_PKT];
  uint32_t versions[2] = {0x0a0a0a0aU, wanted};
  uint8_t random_byte = 0;
  RAND_bytes(&random_byte, 1);
  ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(
      buf, sizeof(buf), random_byte, vc->scid, vc->scidlen, vc->dcid,
      vc->dcidlen, versions, 2);
  if (n <= 0) {
    log_error("ngtcp2_pkt_write_version_negotiation", (int)n);
    return;
  }
  say("version negotiation offered=0x%08x", (unsigned)wanted);
  if (sendto(fd, buf, (size_t)n, 0, to, to_len) < 0) {
    perror("sendto");
  }
}

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: %s <port> <key.pem> <cert.pem> <1|2>\n", argv[0]);
    return 2;
  }
  int port = atoi(argv[1]);
  const char *key_file = argv[2];
  const char *cert_file = argv[3];
  uint32_t wanted = strcmp(argv[4], "2") == 0 ? NGTCP2_PROTO_VER_V2
                                              : NGTCP2_PROTO_VER_V1;
  uint32_t prefer = argc > 5 && strcmp(argv[5], "2") == 0
                        ? NGTCP2_PROTO_VER_V2
                        : (argc > 5 && strcmp(argv[5], "1") == 0
                               ? NGTCP2_PROTO_VER_V1
                               : 0);

  if (ngtcp2_crypto_ossl_init() != 0) {
    say("error: ngtcp2_crypto_ossl_init failed");
    return 2;
  }

  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
  if (!ssl_ctx ||
      SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1 ||
      SSL_CTX_check_private_key(ssl_ctx) != 1) {
    ERR_print_errors_fp(stderr);
    say("error: TLS context failed");
    return 2;
  }
  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select, NULL);
  SSL_CTX_set_default_verify_paths(ssl_ctx);

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    return 2;
  }
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("bind");
    return 2;
  }
  socklen_t local_len = sizeof(addr);
  getsockname(fd, (struct sockaddr *)&addr, &local_len);
  say("port %d", ntohs(addr.sin_port));

  struct peer p = {0};
  p.local_len = sizeof(p.local);
  getsockname(fd, (struct sockaddr *)&p.local, &p.local_len);
  p.conn_ref.get_conn = get_conn;
  p.conn_ref.user_data = &p;

  uint8_t buf[MAX_PKT];
  uint8_t out[MAX_PKT];

  for (;;) {
    struct pollfd pfd = {fd, POLLIN, 0};
    uint64_t now = now_ns();
    int timeout = 1000;
    if (p.conn) {
      uint64_t expiry = ngtcp2_conn_get_expiry(p.conn);
      uint64_t delta = expiry > now ? (expiry - now) / NGTCP2_MILLISECONDS : 0;
      timeout = delta > 1000 ? 1000 : (int)delta;
      if (p.finished_at && timeout > 100) {
        timeout = 100;
      }
    }
    if (p.finished_at && now - p.finished_at > 300 * NGTCP2_MILLISECONDS) {
      say("done");
      break;
    }
    int ready = poll(&pfd, 1, timeout);
    if (ready < 0 && errno != EINTR) {
      perror("poll");
      return 2;
    }
    now = now_ns();

    if (ready > 0 && (pfd.revents & POLLIN)) {
      struct sockaddr_storage from;
      socklen_t from_len = sizeof(from);
      ssize_t nread = recvfrom(fd, buf, sizeof(buf), 0,
                               (struct sockaddr *)&from, &from_len);
      if (nread < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          perror("recvfrom");
          return 2;
        }
      } else if (nread >= 21) {
        if (!p.conn) {
          ngtcp2_version_cid vc;
          int vr = ngtcp2_pkt_decode_version_cid(
              &vc, buf, (size_t)nread, SCIDLEN);
          if (vr == NGTCP2_ERR_VERSION_NEGOTIATION || vc.version != wanted) {
            /* An incompatible negotiation: offer the one version this peer was
             * asked to speak, and wait for the client's restarted first flight. */
            answer_with_vn(fd, &vc, wanted, (struct sockaddr *)&from, from_len);
            continue;
          }
          if (vr != 0) {
            log_error("ngtcp2_pkt_decode_version_cid", vr);
            return 2;
          }
          ngtcp2_pkt_hd hd;
          int ar = ngtcp2_accept(&hd, buf, (size_t)nread);
          if (ar != 0) {
            log_error("ngtcp2_accept", ar);
            return 2;
          }
          p.remote = from;
          p.remote_len = from_len;
          say("version=0x%08x", (unsigned)hd.version);
          if (create_connection(&p, &hd, ssl_ctx, prefer, now) != 0) {
            return 2;
          }
        }
        ngtcp2_path path = {
            {(struct sockaddr *)&p.local, p.local_len},
            {(struct sockaddr *)&p.remote, p.remote_len},
            NULL,
        };
        ngtcp2_pkt_info rx_pi = {0};
        int rr = ngtcp2_conn_read_pkt(p.conn, &path, &rx_pi, buf,
                                      (size_t)nread, now);
        if (rr != 0) {
          log_error("ngtcp2_conn_read_pkt", rr);
          if (rr != NGTCP2_ERR_DRAINING) {
            return 2;
          }
        }
      }
    }

    if (p.conn) {
      int hr = ngtcp2_conn_handle_expiry(p.conn, now);
      if (hr != 0) {
        log_error("ngtcp2_conn_handle_expiry", hr);
        return 2;
      }
      /* Write until ngtcp2 has nothing more to say. A single call produces one
       * datagram; handshake flights and the echo each need their own. */
      for (int guard = 0; guard < 32; ++guard) {
        ngtcp2_path path = {
            {(struct sockaddr *)&p.local, p.local_len},
            {(struct sockaddr *)&p.remote, p.remote_len},
            NULL,
        };
        ngtcp2_pkt_info tx_pi = {0};
        ngtcp2_ssize ndatalen = -1;
        ngtcp2_vec vec = {NULL, 0};
        int64_t stream_id = -1;
        size_t vcnt = 0;
        uint32_t flags = 0;
        if (p.have_stream && p.echo_sent < p.echo_len) {
          stream_id = p.stream_id;
          vec.base = p.echo + p.echo_sent;
          vec.len = p.echo_len - p.echo_sent;
          vcnt = 1;
          flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            p.conn, &path, &tx_pi, out, sizeof(out), &ndatalen, flags,
            stream_id, &vec, vcnt, now);
        if (nwrite == 0) {
          break;
        }
        if (nwrite < 0) {
          /* Flow control or a finished stream is not a failure: the next expiry
           * or the next ACK will make room for the rest. */
          if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
              nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
            break;
          }
          log_error("ngtcp2_conn_writev_stream", (int)nwrite);
          return 2;
        }
        if (ndatalen > 0 && vcnt) {
          p.echo_sent += (size_t)ndatalen;
          if (p.echo_sent >= p.echo_len && !p.fin_sent) {
            p.fin_sent = 1;
            /* The client may close the socket as soon as the stream is complete
             * without sending a final ACK, so the fact that all bytes left this
             * peer is the report; an ACK, if it comes, is a separate line. */
            say("echoed %zu bytes", p.echo_len);
            p.finished_at = now;
          }
        }
        if (sendto(fd, out, (size_t)nwrite, 0,
                   (struct sockaddr *)&p.remote, p.remote_len) < 0) {
          perror("sendto");
          return 2;
        }
      }
    }
  }

  if (p.conn) {
    ngtcp2_conn_del(p.conn);
  }
  if (p.ossl_ctx) {
    ngtcp2_crypto_ossl_ctx_del(p.ossl_ctx);
  }
  SSL_CTX_free(ssl_ctx);
  close(fd);
  return p.fin_sent && p.echo_len > 0 ? 0 : 1;
}
