"""Primitivas criptográficas del sistema NortiShop.

Evoluciona el módulo de la Actividad 2:
- ``Keyring``: llaves de datos versionadas para permitir rotación.
- ``FieldProtector``: AES-256-GCM por campo con contexto (AAD) e índice ciego.
- ``PasswordHasher``: scrypt con sal aleatoria (parámetros OWASP).
- ``Pseudonymizer``: seudónimos HMAC estables por finalidad.
- ``chain_mac``: sello HMAC encadenado para auditoría y consentimiento.

Ninguna función registra llaves ni textos claros.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ConfigurationError(RuntimeError):
    """Falta material criptográfico o tiene un formato incorrecto."""


def _decode_key(name: str, encoded: str) -> bytes:
    try:
        key = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ConfigurationError(f"{name} no contiene Base64 válido") from exc
    if len(key) != 32:
        raise ConfigurationError(f"{name} debe decodificar exactamente 32 bytes")
    return key


def new_key_b64() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


@dataclass
class Keyring:
    """Llaves del sistema. La última versión de ``data_keys`` es la activa."""

    data_keys: dict[str, bytes]
    index_key: bytes
    audit_key: bytes
    pseudo_key: bytes
    active_version: str = field(default="")

    def __post_init__(self) -> None:
        if not self.data_keys:
            raise ConfigurationError("Se requiere al menos una llave de datos")
        if not self.active_version:
            self.active_version = list(self.data_keys)[-1]

    @classmethod
    def from_environment(cls, env: dict[str, str] | None = None) -> "Keyring":
        env = dict(os.environ if env is None else env)
        raw = env.get("NORTISHOP_DATA_KEYS", "")
        if not raw:
            raise ConfigurationError("Falta la variable de entorno NORTISHOP_DATA_KEYS")
        data_keys: dict[str, bytes] = {}
        for item in raw.split(","):
            version, _, encoded = item.strip().partition(":")
            if not version or not encoded:
                raise ConfigurationError("NORTISHOP_DATA_KEYS debe tener formato v1:<base64>,v2:<base64>")
            data_keys[version] = _decode_key(f"NORTISHOP_DATA_KEYS[{version}]", encoded)

        def need(name: str) -> bytes:
            value = env.get(name)
            if not value:
                raise ConfigurationError(f"Falta la variable de entorno {name}")
            return _decode_key(name, value)

        return cls(
            data_keys=data_keys,
            index_key=need("NORTISHOP_INDEX_KEY_B64"),
            audit_key=need("NORTISHOP_AUDIT_KEY_B64"),
            pseudo_key=need("NORTISHOP_PSEUDO_KEY_B64"),
        )

    @classmethod
    def ephemeral(cls) -> "Keyring":
        """Llaves aleatorias en memoria, solo para pruebas y demostraciones."""
        return cls(
            data_keys={"v1": secrets.token_bytes(32)},
            index_key=secrets.token_bytes(32),
            audit_key=secrets.token_bytes(32),
            pseudo_key=secrets.token_bytes(32),
        )

    def add_version(self, version: str, key: bytes) -> None:
        if version in self.data_keys:
            raise ConfigurationError("La versión de llave ya existe")
        self.data_keys[version] = key
        self.active_version = version

    def __repr__(self) -> str:  # nunca exponer material de llaves
        return f"Keyring(versions={list(self.data_keys)}, active={self.active_version!r})"


class FieldProtector:
    """AES-256-GCM por campo. Formato: ``<versión>:<base64url(nonce||ct||tag)>``."""

    def __init__(self, keyring: Keyring) -> None:
        self._keyring = keyring

    def encrypt(self, plaintext: str | None, *, context: str) -> str | None:
        if plaintext is None:
            return None
        version = self._keyring.active_version
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._keyring.data_keys[version]).encrypt(
            nonce, plaintext.encode("utf-8"), context.encode("utf-8")
        )
        return f"{version}:" + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

    def decrypt(self, protected: str | None, *, context: str) -> str | None:
        if protected is None:
            return None
        version, _, encoded = protected.partition(":")
        key = self._keyring.data_keys.get(version)
        if key is None:
            raise ValueError("Versión de llave no disponible")
        packed = base64.urlsafe_b64decode(encoded.encode("ascii"))
        return AESGCM(key).decrypt(packed[:12], packed[12:], context.encode("utf-8")).decode("utf-8")

    def needs_rotation(self, protected: str | None) -> bool:
        return protected is not None and not protected.startswith(self._keyring.active_version + ":")

    def rotate(self, protected: str | None, *, context: str) -> str | None:
        return self.encrypt(self.decrypt(protected, context=context), context=context)

    def blind_index(self, value: str, *, context: str) -> str:
        normalized = value.strip().casefold().encode("utf-8")
        digest = hmac.new(
            self._keyring.index_key, context.encode("utf-8") + b"\x00" + normalized, hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


class PasswordHasher:
    """scrypt N=2^17, r=8, p=1 (mínimo recomendado por OWASP)."""

    N, R, P, DKLEN = 2**17, 8, 1, 32
    MAXMEM = 256 * 1024 * 1024

    def __init__(self, n: int | None = None) -> None:
        # Las pruebas pueden bajar N para acelerar; producción usa el valor por defecto.
        self.n = n or self.N

    def hash(self, password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=self.n, r=self.R,
                                p=self.P, dklen=self.DKLEN, maxmem=self.MAXMEM)
        b64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii")  # noqa: E731
        return f"scrypt${self.n}${self.R}${self.P}${b64(salt)}${b64(digest)}"

    def verify(self, password: str, encoded: str | None) -> bool:
        if not encoded:
            # Igual se deriva para no revelar por tiempo si la cuenta existe.
            hashlib.scrypt(b"x", salt=b"0" * 16, n=self.n, r=self.R, p=self.P, maxmem=self.MAXMEM)
            return False
        try:
            alg, n, r, p, salt_b64, digest_b64 = encoded.split("$")
            if alg != "scrypt":
                return False
            expected = base64.urlsafe_b64decode(digest_b64)
            candidate = hashlib.scrypt(password.encode("utf-8"), salt=base64.urlsafe_b64decode(salt_b64),
                                       n=int(n), r=int(r), p=int(p), dklen=len(expected),
                                       maxmem=self.MAXMEM)
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(candidate, expected)


class Pseudonymizer:
    """Seudónimos estables por dominio: ``HMAC(pseudo_key, dominio||id)``.

    Sin la llave y sin la tabla ``pseudonym_vault`` no se puede volver al
    identificador real. Dominios distintos producen seudónimos no enlazables.
    """

    def __init__(self, keyring: Keyring) -> None:
        self._key = keyring.pseudo_key

    def pseudonym(self, internal_id: int | str, *, domain: str) -> str:
        msg = f"{domain}\x00{internal_id}".encode("utf-8")
        return "ps_" + hmac.new(self._key, msg, hashlib.sha256).hexdigest()[:20]


def canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def chain_mac(key: bytes, previous: str, record: dict) -> str:
    return hmac.new(key, (previous + "|" + canonical(record)).encode("utf-8"), hashlib.sha256).hexdigest()


GENESIS = "0" * 64


def token_hash(token: str) -> str:
    """Hash de tokens de sesión y códigos: la base nunca guarda el valor."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
