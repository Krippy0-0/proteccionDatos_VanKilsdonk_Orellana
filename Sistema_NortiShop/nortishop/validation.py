"""Validaciones de minimización (Hito 2, parte 4).

Cada operación declara una lista blanca de campos. Todo campo que no esté en
la lista se rechaza (por ejemplo ``fecha_nacimiento``, ``genero``, ``cvv`` o
``pan``), de modo que el sistema no puede almacenar datos que no necesita.
Los textos libres se revisan para impedir que el usuario ingrese números de
tarjeta u otros identificadores donde no corresponde.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

REGIONES = (
    "Arica y Parinacota", "Tarapacá", "Antofagasta", "Atacama", "Coquimbo", "Valparaíso",
    "Metropolitana", "O'Higgins", "Maule", "Ñuble", "Biobío", "La Araucanía", "Los Ríos",
    "Los Lagos", "Aysén", "Magallanes",
)

# Campos que el rediseño eliminó: si llegan, se rechazan con un mensaje explícito.
FORBIDDEN_FIELDS = {
    "fecha_nacimiento": "NortiShop no necesita la fecha de nacimiento: basta la declaración de mayoría de edad.",
    "genero": "El género no es necesario para vender ni despachar.",
    "telefono_secundario": "Se admite un solo teléfono de contacto, opcional.",
    "pan": "El número de tarjeta se ingresa solo en el formulario de la pasarela de pago.",
    "numero_tarjeta": "El número de tarjeta se ingresa solo en el formulario de la pasarela de pago.",
    "cvv": "El código de seguridad nunca se almacena.",
    "vencimiento_tarjeta": "El vencimiento de la tarjeta lo gestiona la pasarela.",
    "latitud": "No se almacena geolocalización precisa del domicilio.",
    "longitud": "No se almacena geolocalización precisa del domicilio.",
    "rut": "El RUT solo se solicita para factura, dentro de 'factura'.",
}


class ValidationError(ValueError):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("Datos inválidos")
        self.errors = errors


@dataclass(frozen=True)
class Field:
    required: bool = True
    check: Callable[[Any], Any] | None = None   # devuelve el valor normalizado o lanza ValueError


def _str(min_len: int = 1, max_len: int = 120) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("debe ser texto")
        value = " ".join(value.split())
        if not (min_len <= len(value) <= max_len):
            raise ValueError(f"largo permitido {min_len}-{max_len}")
        return value
    return check


EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?56?9\d{8}$")
PAN_RE = re.compile(r"(?:\d[ -]?){13,19}")
RUT_TEXT_RE = re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b")
EMAIL_TEXT_RE = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")


def email(value: Any) -> str:
    value = _str(5, 254)(value).lower()
    if not EMAIL_RE.match(value):
        raise ValueError("correo inválido")
    return value


def phone(value: Any) -> str:
    digits = re.sub(r"[\s().-]", "", _str(8, 20)(value))
    if not PHONE_RE.match(digits):
        raise ValueError("teléfono móvil chileno inválido (+569XXXXXXXX)")
    return "+569" + digits[-8:]


def rut(value: Any) -> str:
    raw = re.sub(r"[.\s]", "", _str(3, 12)(value)).upper()
    if "-" not in raw:
        raise ValueError("RUT debe incluir guion y dígito verificador")
    body, dv = raw.split("-", 1)
    if not body.isdigit() or len(dv) != 1:
        raise ValueError("RUT inválido")
    total, factor = 0, 2
    for d in reversed(body):
        total += int(d) * factor
        factor = 2 if factor == 7 else factor + 1
    expected = 11 - total % 11
    expected_dv = {11: "0", 10: "K"}.get(expected, str(expected))
    if dv != expected_dv:
        raise ValueError("dígito verificador incorrecto")
    return f"{int(body):,}".replace(",", ".") + "-" + dv


def region(value: Any) -> str:
    value = _str(3, 40)(value)
    if value not in REGIONES:
        raise ValueError("región desconocida")
    return value


def password(value: Any) -> str:
    if not isinstance(value, str) or not (12 <= len(value) <= 128):
        raise ValueError("la contraseña debe tener entre 12 y 128 caracteres")
    return value


def true_only(value: Any) -> bool:
    if value is not True:
        raise ValueError("NortiShop no admite cuentas de menores de edad")
    return True


def luhn(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def free_text(max_len: int = 2000) -> Callable[[Any], str]:
    """Texto libre que no puede contener números de tarjeta (PAN válidos por Luhn)."""
    base = _str(1, max_len)

    def check(value: Any) -> str:
        value = base(value)
        for m in PAN_RE.finditer(value):
            digits = re.sub(r"\D", "", m.group())
            if 13 <= len(digits) <= 19 and luhn(digits):
                raise ValueError("no ingrese números de tarjeta en este campo")
        return value
    return check


def public_text(max_len: int = 1000) -> Callable[[Any], str]:
    """Texto que se publicará (reseñas): sin correo, RUT ni tarjeta."""
    inner = free_text(max_len)

    def check(value: Any) -> str:
        value = inner(value)
        if EMAIL_TEXT_RE.search(value) or RUT_TEXT_RE.search(value):
            raise ValueError("no publique correos ni RUT en una reseña")
        return value
    return check


def last4(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}", value):
        raise ValueError("deben ser exactamente 4 dígitos")
    return value


def int_range(lo: int, hi: int) -> Callable[[Any], int]:
    def check(value: Any) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not (lo <= value <= hi):
            raise ValueError(f"entero entre {lo} y {hi}")
        return value
    return check


def one_of(*options: str) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if value not in options:
            raise ValueError("valor no permitido: " + ", ".join(options))
        return value
    return check


def validate(payload: Any, spec: dict[str, Field]) -> dict[str, Any]:
    """Valida contra una lista blanca. Campos desconocidos o prohibidos => error."""
    if not isinstance(payload, dict):
        raise ValidationError({"_": "se esperaba un objeto JSON"})
    errors: dict[str, str] = {}
    clean: dict[str, Any] = {}
    for key in payload:
        if key in spec:
            continue
        if key in FORBIDDEN_FIELDS:
            errors[key] = "campo no permitido por minimización: " + FORBIDDEN_FIELDS[key]
        elif key not in spec:
            errors[key] = "campo no permitido por minimización"
    for name, field in spec.items():
        if name not in payload or payload[name] in (None, ""):
            if field.required:
                errors.setdefault(name, "campo obligatorio")
            continue
        try:
            clean[name] = field.check(payload[name]) if field.check else payload[name]
        except ValueError as exc:
            errors[name] = str(exc)
    if errors:
        raise ValidationError(errors)
    return clean


# ---- Especificaciones de cada operación ----
REGISTER = {
    "nombre_completo": Field(check=_str(3, 120)),
    "email": Field(check=email),
    "password": Field(check=password),
    "telefono": Field(required=False, check=phone),
    "declaro_mayor_de_edad": Field(check=true_only),
}

LOGIN = {"email": Field(check=email), "password": Field(check=_str(1, 128))}
STAFF_LOGIN = {"username": Field(check=_str(3, 40)), "password": Field(check=_str(1, 128))}

ADDRESS = {
    "calle": Field(check=_str(3, 120)),
    "comuna": Field(check=_str(2, 60)),
    "region": Field(check=region),
}

FACTURA = {
    "rut": Field(check=rut),
    "razon_social": Field(check=_str(2, 120)),
    "direccion_facturacion": Field(check=_str(5, 160)),
}

ITEM = {"sku": Field(check=_str(2, 40)), "cantidad": Field(check=int_range(1, 20))}

CHECKOUT = {
    "destinatario": Field(check=_str(3, 120)),
    "telefono_contacto": Field(check=phone),
    "direccion": Field(),
    "items": Field(),
    "pago": Field(),                 # respuesta de la pasarela: token, marca, últimos 4, autorización
    "factura": Field(required=False),
    "guardar_medio_pago": Field(required=False, check=lambda v: bool(v is True)),
}

GATEWAY_RESULT = {
    "token": Field(check=_str(8, 80)),
    "marca": Field(check=one_of("VISA", "MASTERCARD", "AMEX", "REDCOMPRA")),
    "ultimos4": Field(check=lambda v: last4(v)),
    "codigo_autorizacion": Field(check=_str(4, 20)),
}

TICKET = {"asunto": Field(check=_str(3, 120)), "mensaje": Field(check=free_text())}
REVIEW = {"sku": Field(check=_str(2, 40)), "alias": Field(check=_str(2, 30)),
          "calificacion": Field(check=int_range(1, 5)), "texto": Field(check=public_text())}

RECTIFICATION = {
    "nombre_completo": Field(required=False, check=_str(3, 120)),
    "telefono": Field(required=False, check=phone),
    "email": Field(required=False, check=email),
    "direccion_id": Field(required=False, check=int_range(1, 10**9)),
    "calle": Field(required=False, check=_str(3, 120)),
    "comuna": Field(required=False, check=_str(2, 60)),
    "region": Field(required=False, check=region),
}

RIGHTS_REQUEST = {
    "tipo": Field(check=one_of("acceso", "portabilidad", "rectificacion", "supresion", "oposicion")),
    "cambios": Field(required=False),
    "motivo": Field(required=False, check=free_text(500)),
}
