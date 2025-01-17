from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, SubjectAlternativeName, DNSName
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
import hashlib


def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _generate_private_key(save_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )

    save_path = os.path.join(save_path, "private_key.pem")
    with open(save_path, "wb") as file:
        file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return private_key

def _create_self_signed_certificate(private_key, save_path):
    subject = issuer = Name([
        NameAttribute(NameOID.COMMON_NAME, u"localhost")
    ])
    cert = CertificateBuilder().subject_name(subject).issuer_name(issuer)\
        .public_key(private_key.public_key()).serial_number(1000)\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .add_extension(SubjectAlternativeName([DNSName(u"localhost")]), critical=False)\
        .sign(private_key, hashes.SHA256())

    save_path = os.path.join(save_path, "certificate.pem")
    with open(save_path, "wb") as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))


def gen_key_cert(save_path="code/assets"):
    os.makedirs(save_path, exist_ok=True)
    private_key = _generate_private_key(save_path)
    _create_self_signed_certificate(private_key, save_path)
    print("Certificate and private key generated!")