from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, SubjectAlternativeName, DNSName
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
import json
import hashlib
import logging


def calculate_md5(file_path: str):
    """Calculate the MD5 checksum of a file. This function was used mainly for
    debugging.
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _generate_private_key(save_path: str) -> rsa.RSAPrivateKey:
    """ This function generates a 2048-bit RSA private key, serializes it to
    PEM format, and writes it to a file in the specified directory.
    """
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


def _create_self_signed_certificate(private_key: rsa.RSAPrivateKey, save_path: str):
    """ This function generates a self-signed certificate with a validity of
    one year and saves it in PEM format to the specified directory.
    """
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
    logging.info("Certificate and private key generated!")


def save_file(file_name: str, file_data: bytes, is_client: bool = True):
    try:
        if is_client:
            save_path = os.path.join("code/assets/client_directory", file_name)
        else:
            save_path = os.path.join("code/assets/server_directory", file_name)

        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        with open(save_path, "wb") as file:
            file.write(file_data)

        logging.info(f"File saved as '{save_path}'")
    except Exception as e:
        logging.error(f"Error saving file '{file_name}': {e}")


def parse_metadata(data: bytes):
    try:
        metadata, remaining_data = data.split(b"\n", 1)
        return json.loads(metadata.decode()), remaining_data

    except Exception as e:
        logging.error(f"Error parsing metadata: {e}")
        return None, data