// A QUIC peer built on quic-go, for the interop scripts: a server that echoes a stream and a
// client that sends one and reads it back.
//
//	quic-go-peer -mode server -addr 127.0.0.1:12000 -certs DIR [-version 1|2]
//	quic-go-peer -mode client -addr 127.0.0.1:12000 -ca FILE [-version 1|2] [-payload TEXT]
//
// The server writes `port N` first, then one line per connection naming the version it settled
// on, so a script reads facts rather than prose.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
)

func writeChain(dir string) tls.Certificate {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "moonquic interop ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "cert.pem"), leafPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o644)
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return pair
}

func versions(name string) []quic.Version {
	if name == "2" {
		return []quic.Version{quic.Version2}
	}
	return []quic.Version{quic.Version1}
}

func serve(addr, certDir, version string) {
	pair := writeChain(certDir)
	config := &quic.Config{Versions: versions(version)}
	ln, err := quic.ListenAddr(addr, &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{"h3"},
	}, config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("port %d\n", ln.Addr().(*net.UDPAddr).Port)
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		go func(conn *quic.Conn) {
			state := conn.ConnectionState()
			fmt.Printf("connection version %s group %q\n", state.Version,
				tls.CurveID(state.TLS.CurveID).String())
			for {
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func(s *quic.Stream) {
					data, err := io.ReadAll(s)
					if err != nil {
						return
					}
					fmt.Printf("read %d bytes\n", len(data))
					s.Write(data)
					s.Close()
				}(stream)
			}
		}(conn)
	}
}

func dial(addr, caPath, version, payload string) int {
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatal(err)
	}
	pool.AppendCertsFromPEM(pem)
	conn, err := quic.DialAddr(context.Background(), addr, &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"h3"},
		ServerName: "localhost",
	}, &quic.Config{
		Versions:            versions(version),
		HandshakeIdleTimeout: 10 * time.Second,
	})
	if err != nil {
		fmt.Printf("error %v\n", err)
		return 1
	}
	fmt.Printf("connected %s\n", conn.ConnectionState().Version)
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		fmt.Printf("error %v\n", err)
		return 1
	}
	stream.Write([]byte(payload))
	stream.Close()
	answer, err := io.ReadAll(stream)
	if err != nil {
		fmt.Printf("error %v\n", err)
		return 1
	}
	fmt.Printf("echo %s\n", string(answer))
	conn.CloseWithError(0, "")
	if string(answer) != payload {
		return 1
	}
	return 0
}

func main() {
	mode := flag.String("mode", "server", "server or client")
	addr := flag.String("addr", "127.0.0.1:12000", "address to bind or dial")
	certs := flag.String("certs", "", "directory the server writes its chain to")
	ca := flag.String("ca", "", "root certificate the client trusts")
	version := flag.String("version", "1", "QUIC version to speak: 1 or 2")
	payload := flag.String("payload", "moonquic interop", "what the client sends")
	flag.Parse()
	switch *mode {
	case "server":
		if *certs == "" {
			log.Fatal("-certs names the directory to write the chain to")
		}
		serve(*addr, *certs, *version)
	case "client":
		os.Exit(dial(*addr, *ca, *version, *payload))
	default:
		log.Fatalf("no such mode: %s", *mode)
	}
}
