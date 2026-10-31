"""Hito 2: minimización, protección de campos, seudonimización/anonimización y RBAC."""

from __future__ import annotations

import logging
import sqlite3

from helpers import CUSTOMER_PASSWORD, PAYMENT, AppTestCase

from nortishop.crypto import FieldProtector
from nortishop.db import connect_for_role
from nortishop.seed import synthetic_person


class MinimizationTests(AppTestCase):
    def test_registration_rejects_fields_removed_by_redesign(self) -> None:
        p = synthetic_person(self.rng)
        r = self.client.post("/api/auth/registro", json={
            "nombre_completo": p["nombre"], "email": p["email"], "password": CUSTOMER_PASSWORD,
            "declaro_mayor_de_edad": True, "fecha_nacimiento": "1999-01-01", "genero": "F",
            "telefono_secundario": "+56911111111"})
        self.assertEqual(r.status_code, 400)
        campos = r.get_json()["campos"]
        for field in ("fecha_nacimiento", "genero", "telefono_secundario"):
            self.assertIn("minimización", campos[field])
        self.assertEqual(self.s.system.execute("SELECT COUNT(*) FROM customers").fetchone()[0], 0)

    def test_phone_is_optional_and_minor_accounts_are_rejected(self) -> None:
        p = synthetic_person(self.rng)
        ok = self.client.post("/api/auth/registro", json={"nombre_completo": p["nombre"], "email": p["email"],
                                                           "password": CUSTOMER_PASSWORD, "declaro_mayor_de_edad": True})
        self.assertEqual(ok.status_code, 201)
        q = synthetic_person(self.rng)
        minor = self.client.post("/api/auth/registro", json={"nombre_completo": q["nombre"], "email": q["email"],
                                                              "password": CUSTOMER_PASSWORD,
                                                              "declaro_mayor_de_edad": False})
        self.assertEqual(minor.status_code, 400)
        self.assertIn("menores", minor.get_json()["campos"]["declaro_mayor_de_edad"])

    def test_checkout_rejects_card_data_and_free_text_with_pan(self) -> None:
        _, token = self.register()
        bad = {"destinatario": "Ana Pérez", "telefono_contacto": "+56987654321",
               "direccion": {"calle": "Calle 1", "comuna": "Calama", "region": "Antofagasta", "latitud": -22.4},
               "items": [{"sku": "MOUSE-ERGO", "cantidad": 1}], "pago": dict(PAYMENT),
               "cvv": "123", "pan": "4111111111111111"}
        r = self.client.post("/api/pedidos", json=bad, headers=self.auth(token))
        self.assertEqual(r.status_code, 400)
        self.assertIn("cvv", r.get_json()["campos"])
        self.assertIn("pan", r.get_json()["campos"])
        t = self.client.post("/api/tickets", json={"asunto": "Cobro", "mensaje": "mi tarjeta es 4111 1111 1111 1111"},
                             headers=self.auth(token))
        self.assertEqual(t.status_code, 400)
        rv = self.client.post("/api/resenas", json={"sku": "MOUSE-ERGO", "alias": "Ana", "calificacion": 5,
                                                    "texto": "Excelente, escríbanme a ana@correo.cl"},
                              headers=self.auth(token))
        self.assertEqual(rv.status_code, 400)

    def test_rut_only_collected_for_invoices(self) -> None:
        _, token = self.register()
        self.order(token)
        self.assertEqual(self.s.system.execute("SELECT COUNT(*) FROM billing_profiles").fetchone()[0], 0)
        self.order(token, factura=True)
        self.assertEqual(self.s.system.execute("SELECT COUNT(*) FROM billing_profiles").fetchone()[0], 1)

    def test_personal_data_is_never_stored_in_plaintext(self) -> None:
        person, token = self.register()
        self.order(token, factura=True, guardar_direccion=True)
        dump = "\n".join(self.s.system.iterdump())
        for secret in (person["nombre"], person["email"], person["telefono"], "Calle Falsa 123", "76.086.428-5",
                       CUSTOMER_PASSWORD, PAYMENT["token"], PAYMENT["codigo_autorizacion"]):
            self.assertNotIn(secret, dump, secret)
        pw = self.s.system.execute("SELECT password_hash FROM credentials").fetchone()[0]
        self.assertTrue(pw.startswith("scrypt$"))
        tokens = self.s.system.execute("SELECT token_hash FROM sessions").fetchall()
        self.assertTrue(all(len(t[0]) == 64 for t in tokens))  # SHA-256, no el token

    def test_key_rotation_reencrypts_without_losing_data(self) -> None:
        person, _ = self.register()
        row = self.s.system.execute("SELECT id, email_enc FROM customers").fetchone()
        self.assertTrue(row["email_enc"].startswith("v1:"))
        self.keyring.add_version("v2", b"\x07" * 32)
        f = FieldProtector(self.keyring)
        self.assertTrue(f.needs_rotation(row["email_enc"]))
        rotated = f.rotate(row["email_enc"], context="customer:email")
        self.assertTrue(rotated.startswith("v2:"))
        self.assertEqual(f.decrypt(rotated, context="customer:email"), person["email"])


class RBACTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.person, self.cust = self.register()
        self.order(self.cust)
        self.tokens = {u: self.staff(u) for u in ("soporte1", "logistica1", "marketing1", "finanzas1", "admin1",
                                                    "dpo1", "seguridad1", "auditor1")}
        self.tokens["cliente"] = self.cust

    def test_permission_matrix_is_enforced_by_server(self) -> None:
        matrix = {  # endpoint → roles con acceso
            "/api/personal/clientes": {"soporte1", "admin1", "dpo1"},
            "/api/logistica/despachos": {"logistica1"},
            "/api/marketing/audiencia": {"marketing1"},
            "/api/finanzas/pagos": {"finanzas1"},
            "/api/reportes/ventas": {"finanzas1"},
            "/api/dpo/solicitudes": {"dpo1"},
            "/api/auditoria": {"auditor1", "dpo1", "seguridad1"},
            "/api/seguridad/alertas": {"seguridad1"},
            "/api/me": {"cliente"},
        }
        for path, allowed in matrix.items():
            self.assertEqual(self.client.get(path).status_code, 401, path)
            for who, token in self.tokens.items():
                code = self.client.get(path, headers=self.auth(token)).status_code
                self.assertEqual(code, 200 if who in allowed else 403, f"{who} → {path}: {code}")

    def test_forged_or_revoked_tokens_are_rejected(self) -> None:
        self.assertEqual(self.client.get("/api/me", headers=self.auth("token-inventado")).status_code, 401)
        self.client.post("/api/auth/logout", headers=self.auth(self.cust))
        self.assertEqual(self.client.get("/api/me", headers=self.auth(self.cust)).status_code, 401)

    def test_support_sees_only_masked_data(self) -> None:
        body = self.client.get("/api/personal/clientes", headers=self.auth(self.tokens["soporte1"])).get_data(True)
        self.assertNotIn(self.person["email"], body)
        self.assertNotIn(self.person["telefono"], body)
        self.assertNotIn(self.person["nombre"], body)
        self.assertIn("***@", body)

    def test_logistics_window_closes_after_delivery(self) -> None:
        lg = self.auth(self.tokens["logistica1"])
        ship = self.client.get("/api/logistica/despachos", headers=lg).get_json()["despachos"]
        self.assertEqual(len(ship), 1)
        self.client.post(f"/api/logistica/despachos/{ship[0]['despacho']}/estado", json={"estado": "entregado"}, headers=lg)
        self.assertEqual(self.client.get("/api/logistica/despachos", headers=lg).get_json()["despachos"], [])

    def test_admin_cannot_escalate_privileges(self) -> None:
        h = self.auth(self.tokens["admin1"])
        admin_id = self.s.system.execute("SELECT public_id FROM staff_users WHERE username='admin1'").fetchone()[0]
        support_id = self.s.system.execute("SELECT public_id FROM staff_users WHERE username='soporte1'").fetchone()[0]
        self.assertEqual(self.client.post(f"/api/admin/personal/{admin_id}/rol", json={"rol": "dpo"}, headers=h).status_code, 403)
        self.assertEqual(self.client.post(f"/api/admin/personal/{support_id}/rol", json={"rol": "auditor"}, headers=h).status_code, 403)
        ok = self.client.post(f"/api/admin/personal/{support_id}/rol", json={"rol": "finanzas"}, headers=h)
        self.assertEqual(ok.status_code, 200)
        # el cambio de rol revoca las sesiones del afectado
        self.assertEqual(self.client.get("/api/personal/clientes", headers=self.auth(self.tokens["soporte1"])).status_code, 401)

    def test_database_layer_blocks_unauthorized_tables(self) -> None:
        path = self.s.db_path
        cases = [("soporte", "SELECT password_hash FROM credentials"),
                 ("soporte", "SELECT * FROM pseudonym_vault"),
                 ("soporte", "SELECT * FROM audit_log"),
                 ("marketing", "SELECT full_name_enc FROM customers"),
                 ("marketing", "SELECT * FROM orders"),
                 ("logistica", "SELECT email_enc FROM customers"),
                 ("finanzas", "SELECT gateway_token_enc FROM saved_payment_methods"),
                 ("administrador", "SELECT * FROM audit_log"),
                 ("cliente", "INSERT INTO audit_log (event_id) VALUES ('x')"),
                 ("cliente", "UPDATE consent_events SET action='otorgado'"),
                 ("auditor", "DELETE FROM audit_log"),
                 ("dpo", "UPDATE audit_log SET result='ok'")]
        for role, sql in cases:
            conn = connect_for_role(path, role)
            with self.assertRaises(sqlite3.DatabaseError, msg=f"{role}: {sql}"):
                conn.execute(sql).fetchall()
            conn.close()
        allowed = connect_for_role(path, "marketing")
        self.assertIsNotNone(allowed.execute("SELECT id, status FROM customers").fetchall())
        allowed.close()

    def test_audit_table_is_immutable_even_for_system_connection(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self.s.system.execute("UPDATE audit_log SET result='ok'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.s.system.execute("DELETE FROM audit_log")


class PseudonymizationTests(AppTestCase):
    def test_analytics_and_marketing_use_pseudonyms(self) -> None:
        person, token = self.register()
        h = self.auth(token)
        self.assertFalse(self.client.post("/api/analitica/eventos", json={"evento": "vista_producto", "sku": "SSD-1TB"},
                                          headers=h).get_json()["registrado"])
        self.client.post("/api/me/consentimientos/analitica/otorgar", json={"version_texto": "2026-10"}, headers=h)
        self.client.post("/api/me/consentimientos/marketing_email/otorgar", json={"version_texto": "2026-10"}, headers=h)
        self.assertTrue(self.client.post("/api/analitica/eventos", json={"evento": "vista_producto", "sku": "SSD-1TB"},
                                         headers=h).get_json()["registrado"])
        ref = self.s.system.execute("SELECT customer_ref FROM analytics_events").fetchone()[0]
        self.assertTrue(ref.startswith("ps_"))
        audience = self.client.get("/api/marketing/audiencia", headers=self.auth(self.staff("marketing1"))).get_json()
        self.assertEqual(audience["total"], 1)
        self.assertNotIn(person["email"], str(audience))
        self.assertNotIn(person["public_id"], str(audience))
        mk_ref = audience["destinatarios"][0]
        self.assertNotEqual(mk_ref, ref)  # dominios distintos: seudónimos no enlazables
        # Solo el DPO revierte, con motivo, y queda auditado.
        payload = {"seudonimo": mk_ref, "motivo": "Reclamo del titular por correo recibido"}
        self.assertEqual(self.client.post("/api/dpo/seudonimos/revertir", json=payload,
                                          headers=self.auth(self.staff("marketing1"))).status_code, 403)
        r = self.client.post("/api/dpo/seudonimos/revertir", json=payload, headers=self.auth(self.staff("dpo1")))
        self.assertEqual(r.get_json()["cliente"], person["public_id"])
        self.assertIn("seudonimo.reversion", self.audit_actions())

    def test_sales_report_is_k_anonymous(self) -> None:
        for _ in range(5):
            _, t = self.register()
            self.order(t, region="Antofagasta")
        for _ in range(2):
            _, t = self.register()
            self.order(t, region="Atacama")
        report = self.client.get("/api/reportes/ventas", headers=self.auth(self.staff("finanzas1"))).get_json()
        regions = [c["region"] for c in report["celdas_publicadas"]]
        self.assertEqual(regions, ["Antofagasta"])
        self.assertEqual(report["celdas_suprimidas"], 1)  # Atacama (2 clientes) no se publica

    def test_dev_dataset_contains_no_identifiers(self) -> None:
        person, t = self.register()
        self.order(t, factura=True)
        rows = self.client.get("/api/reportes/dataset-desarrollo", headers=self.auth(self.staff("finanzas1"))).get_json()["filas"]
        text = str(rows)
        for value in (person["nombre"], person["email"], person["public_id"], "Calle Falsa", "76.086.428-5"):
            self.assertNotIn(value, text)
        self.assertEqual(set(rows[0]), {"cliente_dev", "region", "mes", "tramo_monto", "estado"})


class SecureErrorsAndLogsTests(AppTestCase):
    def test_internal_errors_do_not_leak_details_and_logs_are_redacted(self) -> None:
        person = synthetic_person(self.rng)

        @self.app.get("/api/_falla")
        def _boom():  # endpoint de prueba que falla con un dato personal en el mensaje
            raise RuntimeError(f"fallo procesando {person['email']} tarjeta 4111111111111111")

        person, token = self.register(person)

        with self.assertLogs("nortishop", level=logging.ERROR) as captured:
            r = self.client.get("/api/_falla", headers=self.auth(token))
        self.assertEqual(r.status_code, 500)
        self.assertEqual(set(r.get_json()), {"error", "request_id"})
        joined = "\n".join(captured.output)
        self.assertNotIn(person["email"], joined)
        self.assertNotIn("4111111111111111", joined)

    def test_login_lockout_and_no_user_enumeration(self) -> None:
        person, _ = self.register()
        unknown = self.client.post("/api/auth/login", json={"email": "nadie@correo-sintetico.test", "password": "x"})
        wrong = self.client.post("/api/auth/login", json={"email": person["email"], "password": "x"})
        self.assertEqual(unknown.get_json()["error"], wrong.get_json()["error"])
        for _ in range(5):
            self.client.post("/api/auth/login", json={"email": person["email"], "password": "incorrecta"})
        locked = self.client.post("/api/auth/login", json={"email": person["email"], "password": CUSTOMER_PASSWORD})
        self.assertEqual(locked.status_code, 401)
        self.assertIn("auth.bloqueo", self.audit_actions())
        rules = [r[0] for r in self.s.system.execute("SELECT rule FROM security_alerts")]
        self.assertIn("fuerza_bruta_login", rules)
