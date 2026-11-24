"""Certificate management for PS5 Jailbreak Helper."""
import ssl
import datetime
from pathlib import Path
from typing import Tuple, Optional


CERT_VALIDITY_DAYS = 365  # Reduced from 10 years to 1 year for security
CERT_KEY_SIZE = 2048
CERT_PUBLIC_EXPONENT = 65537

# Subject Alternative Names for PS5 guide domains
SAN_DOMAINS = [
    "manuals.playstation.net",
    "manual.playstation.net",
    "doc.dl.playstation.net",
]


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> bool:
    """Generate a self-signed certificate for manuals.playstation.net with SANs."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        return False

    try:
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=CERT_PUBLIC_EXPONENT,
            key_size=CERT_KEY_SIZE,
        )

        # Subject and issuer (self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "manuals.playstation.net"),
        ])

        # Subject Alternative Names
        san = x509.SubjectAlternativeName([
            x509.DNSName(domain) for domain in SAN_DOMAINS
        ])

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=CERT_VALIDITY_DAYS))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Write certificate
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        # Write private key
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

        return True
    except Exception:
        return False


def verify_cert(cert_path: Path, key_path: Path) -> bool:
    """Verify that certificate and key are valid and match."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return True
    except Exception:
        return False


def get_cert_info(cert_path: Path) -> Optional[dict]:
    """Get certificate information for display."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None

    try:
        cert_data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "serial": str(cert.serial_number),
            "san": [ext.value for ext in cert.extensions if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
        }
    except Exception:
        return None


def ensure_cert(assets_dir: Path) -> bool:
    """Ensure TLS certificate exists, generate if missing or invalid."""
    assets_dir.mkdir(parents=True, exist_ok=True)
    crt_path = assets_dir / "manuals.crt"
    key_path = assets_dir / "manuals.key"

    if crt_path.is_file() and key_path.is_file():
        if verify_cert(crt_path, key_path):
            return True

    # Generate new certificate
    return generate_self_signed_cert(crt_path, key_path)


def get_cert_paths(assets_dir: Path) -> Tuple[Path, Path]:
    """Get certificate and key paths."""
    return assets_dir / "manuals.crt", assets_dir / "manuals.key"