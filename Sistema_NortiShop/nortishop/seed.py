"""Datos sintéticos para desarrollo, pruebas y evidencias.

Nunca se copian datos de producción a estos ambientes: los nombres, correos,
teléfonos y RUT se generan al azar y los RUT tienen dígito verificador válido
pero no corresponden a personas reales conocidas.
"""

from __future__ import annotations

import random
import secrets
import uuid

from .db import now_iso

NOMBRES = ["Camila", "Matías", "Valentina", "Benjamín", "Antonia", "Joaquín", "Florencia", "Tomás", "Isidora",
           "Vicente", "Martina", "Agustín", "Josefa", "Diego", "Catalina", "Lucas"]
APELLIDOS = ["Rojas", "González", "Muñoz", "Díaz", "Pérez", "Soto", "Contreras", "Silva", "Morales", "Araya",
             "Castillo", "Fuentes", "Torres", "Espinoza", "Valenzuela", "Tapia"]
COMUNAS = [("Antofagasta", "Antofagasta"), ("Calama", "Antofagasta"), ("Iquique", "Tarapacá"),
           ("Arica", "Arica y Parinacota"), ("La Serena", "Coquimbo"), ("Santiago", "Metropolitana")]

STAFF = [("soporte1", "soporte"), ("logistica1", "logistica"), ("marketing1", "marketing"), ("finanzas1", "finanzas"),
         ("admin1", "administrador"), ("dpo1", "dpo"), ("seguridad1", "oficial_seguridad"), ("auditor1", "auditor")]


def rut_dv(body: int) -> str:
    total, factor = 0, 2
    for d in reversed(str(body)):
        total += int(d) * factor
        factor = 2 if factor == 7 else factor + 1
    return {11: "0", 10: "K"}.get(11 - total % 11, str(11 - total % 11))


def synthetic_person(rng: random.Random) -> dict:
    name = f"{rng.choice(NOMBRES)} {rng.choice(APELLIDOS)} {rng.choice(APELLIDOS)}"
    user = name.split()[0].lower().translate(str.maketrans("áéíóúñ", "aeioun")) + str(rng.randint(10, 9999))
    body = rng.randint(10_000_000, 25_999_999)
    return {"nombre": name, "email": f"{user}@correo-sintetico.test", "telefono": f"+569{rng.randint(10**7, 10**8 - 1)}",
            "rut": f"{body:,}".replace(",", ".") + "-" + rut_dv(body)}


def seed_staff(services, password: str | None = None) -> dict[str, str]:  # noqa: ANN001
    """Crea una cuenta por rol del personal. Devuelve usuario → contraseña (solo en memoria)."""
    creds = {}
    for username, role in STAFF:
        if services.system.execute("SELECT 1 FROM staff_users WHERE username=?", (username,)).fetchone():
            continue
        pw = password or secrets.token_urlsafe(12)
        services.system.execute(
            "INSERT INTO staff_users (public_id, username, role, password_hash, created_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), username, role, services.hasher.hash(pw), now_iso()))
        creds[username] = pw
    return creds
