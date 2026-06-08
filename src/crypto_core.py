"""
Lógica criptográfica del sistema: generación de pares de claves RSA,
una Autoridad de Certificación (CA) simulada que emite certificados
estilo X.509 simplificados, generación de claves de sesión AES y
cifrado/descifrado híbrido (RSA + AES-GCM).

Basado en los conceptos del informe del grupo:
"Sistemas de Generación y Distribución de Claves Criptográficas"
(criptografía simétrica/asimétrica, PKI, certificados X.509, no repudio).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 2048
AES_KEY_SIZE_BITS = 256
CERTIFICATE_VALIDITY_DAYS = 365


# ---------------------------------------------------------------------------
# Pares de claves RSA (asimétricas)
# ---------------------------------------------------------------------------

def generate_rsa_keypair() -> rsa.RSAPrivateKey:
    """Genera un nuevo par de claves RSA-2048 (privada + pública)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)


def public_key_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Exporta la clave pública asociada en formato PEM (texto)."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fingerprint(public_pem: bytes) -> str:
    """Huella SHA-256 de una clave pública, para identificarla de forma corta."""
    return hashlib.sha256(public_pem).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Certificado digital simplificado (estilo X.509) y Autoridad de Certificación
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Certificate:
    """Versión simplificada de un certificado X.509: vincula una identidad
    (subject) con su clave pública, firmada digitalmente por una CA."""

    subject: str
    issuer: str
    serial_number: int
    public_key_pem: bytes
    not_before: datetime
    not_after: datetime
    signature: bytes

    def _signed_payload(self) -> bytes:
        """Construye los bytes que la CA firma (y que se vuelven a calcular
        para verificar la firma). Debe ser determinista."""
        return b"|".join([
            self.subject.encode("utf-8"),
            self.issuer.encode("utf-8"),
            str(self.serial_number).encode("ascii"),
            self.public_key_pem,
            self.not_before.isoformat().encode("ascii"),
            self.not_after.isoformat().encode("ascii"),
        ])

    def is_within_validity(self, when: datetime | None = None) -> bool:
        when = when or datetime.now(timezone.utc)
        return self.not_before <= when <= self.not_after

    def load_public_key(self) -> rsa.RSAPublicKey:
        return serialization.load_pem_public_key(self.public_key_pem)

    def summary(self) -> str:
        return (
            f"Sujeto: {self.subject}\n"
            f"Emisor (CA): {self.issuer}\n"
            f"Número de serie: {self.serial_number}\n"
            f"Válido desde: {self.not_before.date()}  hasta: {self.not_after.date()}\n"
            f"Huella de la clave pública: {fingerprint(self.public_key_pem)}\n"
            f"Firma de la CA (resumen): {self.signature.hex()[:48]}..."
        )


class CertificateAuthority:
    """Autoridad de Certificación (CA) simulada.

    Tiene su propio par de claves RSA y firma certificados que vinculan
    el nombre de un usuario con su clave pública — el mecanismo central
    de una PKI para evitar la suplantación de identidad (descrito en el
    informe como "No Repudio" y "Autoridad de Certificación").
    """

    def __init__(self, name: str = "CA-Curso-Seguridad-TI"):
        self.name = name
        self._private_key = generate_rsa_keypair()
        self._next_serial = 1000

    @property
    def public_key_pem(self) -> bytes:
        return public_key_pem(self._private_key)

    def issue_certificate(self, subject_name: str, subject_private_key: rsa.RSAPrivateKey) -> Certificate:
        """Emite (firma) un certificado para un usuario, vinculando su nombre
        con su clave pública. Equivale a lo que en el informe se describe
        como el rol de la CA dentro de una PKI."""
        now = datetime.now(timezone.utc)
        serial = self._next_serial
        self._next_serial += 1

        cert_without_signature = Certificate(
            subject=subject_name,
            issuer=self.name,
            serial_number=serial,
            public_key_pem=public_key_pem(subject_private_key),
            not_before=now,
            not_after=now + timedelta(days=CERTIFICATE_VALIDITY_DAYS),
            signature=b"",
        )
        signature = self._private_key.sign(
            cert_without_signature._signed_payload(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return Certificate(
            subject=cert_without_signature.subject,
            issuer=cert_without_signature.issuer,
            serial_number=cert_without_signature.serial_number,
            public_key_pem=cert_without_signature.public_key_pem,
            not_before=cert_without_signature.not_before,
            not_after=cert_without_signature.not_after,
            signature=signature,
        )

    def verify_certificate(self, certificate: Certificate) -> bool:
        """Comprueba que el certificado fue realmente firmado por esta CA
        y que sus datos no han sido alterados."""
        ca_public_key = self._private_key.public_key()
        try:
            ca_public_key.verify(
                certificate.signature,
                certificate._signed_payload(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return certificate.issuer == self.name and certificate.is_within_validity()
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Claves de sesión simétricas (AES-GCM) y cifrado híbrido
# ---------------------------------------------------------------------------

def generate_session_key() -> bytes:
    """Genera una clave de sesión simétrica AES-256 aleatoria (32 bytes)."""
    return AESGCM.generate_key(bit_length=AES_KEY_SIZE_BITS)


def wrap_session_key(session_key: bytes, recipient_certificate: Certificate) -> bytes:
    """Cifra ('envuelve') una clave de sesión con la clave pública RSA del
    destinatario, tomada de su certificado verificado. Solo su clave privada
    podrá recuperarla — esto es la 'distribución segura' descrita en el informe."""
    recipient_public_key = recipient_certificate.load_public_key()
    return recipient_public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def unwrap_session_key(wrapped_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Descifra una clave de sesión recibida usando la clave privada propia."""
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def encrypt_message(session_key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """Cifra un mensaje con la clave de sesión (AES-GCM). Devuelve (iv, texto_cifrado)."""
    iv = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return iv, ciphertext


def decrypt_message(session_key: bytes, iv: bytes, ciphertext: bytes) -> str:
    """Descifra un mensaje cifrado con AES-GCM usando la clave de sesión."""
    plaintext = AESGCM(session_key).decrypt(iv, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")
