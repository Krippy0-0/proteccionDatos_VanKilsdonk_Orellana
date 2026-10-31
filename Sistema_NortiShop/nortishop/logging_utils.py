"""Registros técnicos sin datos personales.

El filtro ``RedactingFilter`` se aplica a todos los handlers: enmascara
correos, RUT, teléfonos, números de tarjeta y tokens Bearer aunque un
desarrollador los incluya por error en un mensaje. Las excepciones se
registran con un identificador de solicitud; el cliente nunca recibe la traza.
"""

from __future__ import annotations

import logging
import re

PATTERNS = [
    (re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [token]"),
    (re.compile(r"[^@\s\"']+@[^@\s\"']+\.[A-Za-z]{2,}"), "[correo]"),
    (re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b"), "[rut]"),
    (re.compile(r"(?:\d[ -]?){13,19}"), "[numero]"),
    (re.compile(r"\+?56\s?9\s?\d{4}\s?\d{4}"), "[telefono]"),
]


def redact(text: str) -> str:
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        record.msg = redact(message)
        record.args = ()
        if record.exc_info:
            # Se conserva el tipo de excepción, no el texto (puede contener valores).
            exc_type = record.exc_info[0].__name__ if record.exc_info[0] else "Exception"
            record.msg += f" [excepción: {exc_type}]"
            record.exc_info = None
            record.exc_text = None
        return True


def configure_logging(app) -> None:  # noqa: ANN001
    logger = logging.getLogger("nortishop")
    # Los filtros de logger no se heredan: se instalan en cada logger del paquete.
    for name in ("nortishop", "nortishop.api", "nortishop.security"):
        lg = logging.getLogger(name)
        if not any(isinstance(f, RedactingFilter) for f in lg.filters):
            lg.addFilter(RedactingFilter())
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    app.logger.addFilter(RedactingFilter())
