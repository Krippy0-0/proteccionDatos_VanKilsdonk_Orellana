"""Utilidades comunes de prueba: app aislada con base temporal y llaves efímeras."""

from __future__ import annotations

import random
import shutil
import tempfile
import unittest
from pathlib import Path

from nortishop import create_app
from nortishop.crypto import Keyring
from nortishop.seed import seed_staff, synthetic_person

STAFF_PASSWORD = "Personal-Demo-2026!"
CUSTOMER_PASSWORD = "Cliente-Demo-2026!"
PAYMENT = {"token": "tok_demo_8f2a91c4", "marca": "VISA", "ultimos4": "1111", "codigo_autorizacion": "AUTH839201"}


class AppTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="nortishop_test_"))
        self.keyring = Keyring.ephemeral()
        # N reducido solo en pruebas para que la suite sea rápida; producción usa 2^17.
        self.app = create_app(db_path=str(self.tmp / "test.db"), keyring=self.keyring,
                              evidence_dir=self.tmp / "evidencia", scrypt_n=2**12, testing=True)
        self.client = self.app.test_client()
        self.s = self.app.extensions["nortishop"]
        seed_staff(self.s, STAFF_PASSWORD)
        self.rng = random.Random(7)

    def tearDown(self) -> None:
        self.s.system.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers HTTP ----
    def auth(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def register(self, person: dict | None = None, password: str = CUSTOMER_PASSWORD) -> tuple[dict, str]:
        person = person or synthetic_person(self.rng)
        r = self.client.post("/api/auth/registro", json={"nombre_completo": person["nombre"], "email": person["email"],
                                                          "password": password, "telefono": person["telefono"],
                                                          "declaro_mayor_de_edad": True})
        self.assertEqual(r.status_code, 201, r.get_json())
        person["public_id"] = r.get_json()["cliente"]
        token = self.login(person["email"], password)
        return person, token

    def login(self, email: str, password: str = CUSTOMER_PASSWORD) -> str:
        r = self.client.post("/api/auth/login", json={"email": email, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["token"]

    def staff(self, username: str) -> str:
        r = self.client.post("/api/personal/login", json={"username": username, "password": STAFF_PASSWORD})
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["token"]

    def order(self, token: str, region: str = "Antofagasta", factura: bool = False, **extra) -> dict:
        payload = {"destinatario": "Destinatario Sintético", "telefono_contacto": "+56987654321",
                   "direccion": {"calle": "Calle Falsa 123", "comuna": "Antofagasta", "region": region},
                   "items": [{"sku": "MOUSE-ERGO", "cantidad": 1}], "pago": dict(PAYMENT), **extra}
        if factura:
            payload["factura"] = {"rut": "76.086.428-5", "razon_social": "Empresa Sintética SpA",
                                  "direccion_facturacion": "Av. Grecia 1000, Antofagasta"}
        r = self.client.post("/api/pedidos", json=payload, headers=self.auth(token))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def audit_actions(self) -> list[str]:
        return [r["action"] for r in self.s.system.execute("SELECT action FROM audit_log ORDER BY id")]
