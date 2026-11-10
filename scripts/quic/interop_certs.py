#!/usr/bin/env python3
"""A root and a server certificate under it, for the interop scripts to hand to both ends.

The certificate names `localhost` and `127.0.0.1`, so a peer dialled by address verifies it
against a root the script writes next to it. Nothing here is committed: the files live in the
temporary directory the calling script makes.

    from interop_certs import write
    write(pathlib.Path(tmp) / "certs")   # ca.pem, cert.pem, key.pem
"""

import datetime as dt
import ipaddress
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

START = dt.datetime(2010, 1, 1, tzinfo=dt.timezone.utc)
END = dt.datetime(2060, 1, 1, tzinfo=dt.timezone.utc)


def name(common):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def write(directory):
    """Write `ca.pem`, `cert.pem` and `key.pem` into `directory`; return the directory."""
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = name("moonquic interop root")
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(START)
        .not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("localhost"))
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(START)
        .not_valid_after(END)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )
    (directory / "ca.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (directory / "cert.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return directory
