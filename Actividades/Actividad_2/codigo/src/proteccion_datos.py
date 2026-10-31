"""Controles de protección para el caso académico NortiShop.

El módulo demuestra cifrado autenticado, índices ciegos, hashing de
contraseñas, tokenización y sellos de integridad HMAC. No registra secretos
ni datos en texto claro.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import json
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ConfigurationError(RuntimeError):
    """Indica que falta material criptográfico o tiene formato incorrecto."""


def _read_32_byte_key(variable: str) -> bytes:
    encoded = os.environ.get(variable)
    if not encoded:
        raise ConfigurationError(f"Falta la variable de entorno {variable}")
    try:
        key = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ConfigurationError(f"{variable} no contiene Base64 válido") from exc
    if len(key) != 32:
        raise ConfigurationError(f"{variable} debe decodificar exactamente 32 bytes")
    return key


@dataclass(frozen=True)
class SecretKeys:
    data_key: bytes
    index_key: bytes

    @classmethod
    def from_environment(cls) -> "SecretKeys":
        return cls(
            data_key=_read_32_byte_key("NORTISHOP_DATA_KEY_B64"),
            index_key=_read_32_byte_key("NORTISHOP_INDEX_KEY_B64"),
        )


class FieldProtector:
    """Cifra campos con AES-256-GCM e indexa valores con HMAC-SHA-256."""

    VERSION = "v1"

    def __init__(self, keys: SecretKeys) -> None:
        self._keys = keys
        self._aesgcm = AESGCM(keys.data_key)

    def encrypt(self, plaintext: str, *, context: str) -> str:
        nonce = secrets.token_bytes(12)
        aad = context.encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        packed = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
        return f"{self.VERSION}:{packed}"

    def decrypt(self, protected: str, *, context: str) -> str:
        version, encoded = protected.split(":", 1)
        if version != self.VERSION:
            raise ValueError("Versión de cifrado no soportada")
        packed = base64.urlsafe_b64decode(encoded.encode("ascii"))
        nonce, ciphertext = packed[:12], packed[12:]
        plaintext = self._aesgcm.decrypt(
            nonce, ciphertext, context.encode("utf-8")
        )
        return plaintext.decode("utf-8")

    def blind_index(self, value: str, *, context: str) -> str:
        normalized = value.strip().casefold().encode("utf-8")
        digest = hmac.new(
            self._keys.index_key,
            context.encode("utf-8") + b"\x00" + normalized,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class PasswordProtector:
    """Deriva hashes de contraseña con scrypt y sal aleatoria.

    Parámetros mínimos recomendados por OWASP para scrypt: N=2^17, r=8, p=1.
    Con esos valores scrypt usa unos 128 MiB, por eso se amplía ``maxmem``.
    """

    N = 2**17
    R = 8
    P = 1
    DKLEN = 32
    MAXMEM = 256 * 1024 * 1024

    @classmethod
    def hash_password(cls, password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=cls.N,
            r=cls.R,
            p=cls.P,
            dklen=cls.DKLEN,
            maxmem=cls.MAXMEM,
        )
        return "$".join(
            [
                "scrypt",
                str(cls.N),
                str(cls.R),
                str(cls.P),
                base64.urlsafe_b64encode(salt).decode("ascii"),
                base64.urlsafe_b64encode(digest).decode("ascii"),
            ]
        )

    @classmethod
    def verify_password(cls, password: str, encoded: str) -> bool:
        try:
            algorithm, n, r, p, salt_b64, digest_b64 = encoded.split("$")
            if algorithm != "scrypt":
                return False
            salt = base64.urlsafe_b64decode(salt_b64)
            expected = base64.urlsafe_b64decode(digest_b64)
            candidate = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=int(n),
                r=int(r),
                p=int(p),
                dklen=len(expected),
                maxmem=cls.MAXMEM,
            )
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(candidate, expected)


class IntegrityProtector:
    """Sella registros con HMAC-SHA-256 para detectar alteraciones.

    Se usa donde predomina la integridad y no la confidencialidad: eventos de
    consentimiento y movimientos de NortiPuntos. Cada sello incluye el sello
    anterior, de modo que borrar, reordenar o modificar un evento rompe la
    cadena completa.
    """

    GENESIS = "0" * 64

    def __init__(self, keys: SecretKeys) -> None:
        # Llave derivada de la llave de índice con separación de dominio.
        self._key = hmac.new(keys.index_key, b"nortishop:integrity:v1", hashlib.sha256).digest()

    def seal(self, record: dict, *, previous: str) -> str:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hmac.new(
            self._key, (previous + "|" + canonical).encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def append(self, chain: list[dict], record: dict) -> dict:
        previous = chain[-1]["mac"] if chain else self.GENESIS
        entry = {"record": dict(record), "mac": self.seal(record, previous=previous)}
        chain.append(entry)
        return entry

    def verify_chain(self, chain: list[dict]) -> bool:
        previous = self.GENESIS
        for entry in chain:
            expected = self.seal(entry["record"], previous=previous)
            if not hmac.compare_digest(expected, entry["mac"]):
                return False
            previous = entry["mac"]
        return True


class LoyaltyLedger:
    """Libro de NortiPuntos: el saldo se deriva de movimientos sellados."""

    def __init__(self, integrity: IntegrityProtector) -> None:
        self._integrity = integrity
        self.entries: list[dict] = []

    def add(self, customer_ref: str, points: int, reason: str) -> None:
        if not isinstance(points, int) or points == 0:
            raise ValueError("Movimiento inválido")
        if self.balance(customer_ref) + points < 0:
            raise ValueError("El saldo no puede quedar negativo")
        self._integrity.append(
            self.entries,
            {"customer": customer_ref, "points": points, "reason": reason, "seq": len(self.entries)},
        )

    def balance(self, customer_ref: str) -> int:
        if not self._integrity.verify_chain(self.entries):
            raise ValueError("Libro de NortiPuntos alterado")
        return sum(e["record"]["points"] for e in self.entries if e["record"]["customer"] == customer_ref)


@dataclass(frozen=True)
class PaymentReference:
    token: str
    brand: str
    last4: str

    def merchant_record(self, protector: "FieldProtector") -> dict:
        """Registro que persiste NortiShop: el token va cifrado en reposo."""
        return {
            "payment_token_enc": protector.encrypt(self.token, context="payment:token"),
            "brand": self.brand,
            "last4": self.last4,
        }


class PaymentTokenizer:
    """Bóveda didáctica: el comercio conserva solo token, marca y últimos 4."""

    def __init__(self, protector: FieldProtector) -> None:
        self._protector = protector
        self._vault: dict[str, str] = {}

    def tokenize(self, pan: str, *, brand: str) -> PaymentReference:
        digits = "".join(ch for ch in pan if ch.isdigit())
        if not 12 <= len(digits) <= 19:
            raise ValueError("PAN inválido para la demostración")
        token = "tok_" + secrets.token_urlsafe(18)
        self._vault[token] = self._protector.encrypt(
            digits, context=f"payment-vault:{token}"
        )
        return PaymentReference(token=token, brand=brand, last4=digits[-4:])

    def detokenize_for_authorized_processor(self, token: str) -> str:
        protected = self._vault[token]
        return self._protector.decrypt(
            protected, context=f"payment-vault:{token}"
        )

