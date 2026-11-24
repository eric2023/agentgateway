#!/usr/bin/env python3
"""AgentGateway CA certificate generator.

Generates a root CA that agentgatewayd uses to dynamically sign
certificates for intercepted TLS connections. In a real deployment
this CA is installed into the OS trust store (/etc/ssl/certs/) by the
OS vendor. For testing we use HTTPS_PROXY so the CA only needs to be
trusted by the gateway's own TLS stack.
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")

def generate_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentGateway Trusted Runtime"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AgentGateway Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    key_path = os.path.join(CERT_DIR, "ca-key.pem")
    cert_path = os.path.join(CERT_DIR, "ca-cert.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(key_path, 0o600)
    print(f"[CA] Root CA generated:")
    print(f"     cert: {cert_path}")
    print(f"     key:  {key_path}")
    return key, cert

if __name__ == "__main__":
    os.makedirs(CERT_DIR, exist_ok=True)
    generate_ca()
