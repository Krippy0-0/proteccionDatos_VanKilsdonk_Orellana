"""Hito 3: registro de auditoría, detección, contención, recuperación y notificación."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from helpers import CUSTOMER_PASSWORD, AppTestCase

from nortishop.audit import sanitize
from nortishop.maintenance import reapply_erasures, rotate_keys
from nortishop.crypto import GENESIS, chain_mac
from nortishop.security import notification_assessment


class AuditTests(AppTestCase):
    def test_events_have_required_attributes_and_no_personal_data(self) -> None:
        person, token = self.register()
        self.order(token, factura=True)
        self.client.post("/api/me/consentimientos/marketing_email/otorgar", json={"version_texto": "2026-10"},
                         headers=self.auth(token))
        self.client.post("/api/auth/login", json={"email": person["email"], "password": "incorrecta"})
        rows = [dict(r) for r in self.s.system.execute("SELECT * FROM audit_log")]
        self.assertGreaterEqual(len(rows), 5)
        for r in rows:
            for attr in ("event_id", "occurred_at", "actor_ref", "action", "resource_type", "result"):
                self.assertTrue(r[attr], attr)
        dump = json.dumps(rows, ensure_ascii=False)
        for value in (person["email"], person["nombre"], person["telefono"], CUSTOMER_PASSWORD, "incorrecta",
                      "76.086.428-5", token):
            self.assertNotIn(value, dump)
        self.assertTrue(all(r["ip_prefix"] in (None, "127.0.0.0/24") for r in rows))

    def test_sanitize_drops_secrets_and_masks_values(self) -> None:
        clean = sanitize({"password": "x", "token": "y", "codigo": "123456", "api_key": "k",
                          "nota": "contactar a ana@correo.cl o +56 9 1234 5678, RUT 12.345.678-5",
                          "campana": "verano"})
        self.assertEqual(clean["password"], "[omitido]")
        self.assertEqual(clean["token"], "[omitido]")
        self.assertEqual(clean["codigo"], "[omitido]")
        self.assertEqual(clean["api_key"], "[omitido]")
        self.assertEqual(clean["campana"], "verano")
        self.assertNotIn("ana@correo.cl", clean["nota"])
        self.assertNotIn("12.345.678-5", clean["nota"])
        self.assertNotIn("1234 5678", clean["nota"])

    def test_chain_detects_tampering_and_opens_incident(self) -> None:
        self.register()
        auditor = self.auth(self.staff("auditor1"))
        self.assertTrue(self.client.get("/api/auditoria/verificar", headers=auditor).get_json()["valida"])
        # Atacante con acceso directo al archivo: elimina el trigger y altera un evento.
        self.s.system.execute("DROP TRIGGER audit_no_update")
        self.s.system.execute("UPDATE audit_log SET result='ok' WHERE action='auth.login' AND id=2")
        self.s.system.execute("UPDATE audit_log SET actor_ref='otro' WHERE id=1")
        status = self.client.get("/api/auditoria/verificar", headers=auditor).get_json()
        self.assertFalse(status["valida"])
        self.assertEqual(status["falla_en_id"], 1)
        inc = self.s.system.execute("SELECT severity, phase FROM incidents").fetchone()
        self.assertEqual(tuple(inc), ("critica", "analisis"))

    def test_retention_purge_keeps_chain_verifiable(self) -> None:
        key = self.keyring.audit_key
        old = {"event_id": "antiguo-1", "occurred_at": "2024-01-01T00:00:00", "actor_type": "sistema",
               "actor_ref": "sistema", "actor_role": "sistema", "action": "auth.login", "resource_type": "x",
               "resource_ref": None, "result": "ok", "request_id": None, "ip_prefix": None, "details": "{}",
               "prev_hash": GENESIS}
        old["hash"] = chain_mac(key, GENESIS, {k: v for k, v in old.items() if k != "hash"})
        self.s.system.execute(f"INSERT INTO audit_log ({', '.join(old)}) VALUES ({', '.join('?' * len(old))})",
                              list(old.values()))
        self.register()  # eventos recientes encadenados al antiguo
        self.assertTrue(self.s.audit.verify()["valida"])
        with self.assertRaises(sqlite3.DatabaseError):  # lo reciente no se puede borrar
            self.s.system.execute("DELETE FROM audit_log WHERE event_id <> 'antiguo-1'")
        self.assertEqual(self.s.audit.purge_expired(), 1)
        self.assertTrue(self.s.audit.verify()["valida"])
        self.assertEqual(self.s.system.execute("SELECT COUNT(*) FROM audit_anchor").fetchone()[0], 1)

    def test_only_authorized_roles_read_audit_and_reads_are_audited(self) -> None:
        _, token = self.register()
        for user in ("soporte1", "admin1", "marketing1"):
            self.assertEqual(self.client.get("/api/auditoria", headers=self.auth(self.staff(user))).status_code, 403)
        self.assertEqual(self.client.get("/api/auditoria", headers=self.auth(token)).status_code, 403)
        r = self.client.get("/api/auditoria?accion=auth.registro", headers=self.auth(self.staff("auditor1")))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["eventos"]), 1)
        self.assertIn("auditoria.consulta", self.audit_actions())


class DetectionAndIncidentTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.person, self.token = self.register()
        self.sec = self.auth(self.staff("seguridad1"))

    def test_repeated_denied_access_raises_suspicious_event(self) -> None:
        for _ in range(5):
            self.client.get("/api/auditoria", headers=self.auth(self.token))
        alerts = self.client.get("/api/seguridad/alertas", headers=self.sec).get_json()["alertas"]
        self.assertEqual([(a["rule"], a["level"]) for a in alerts], [("accesos_denegados_reiterados", "sospechoso")])

    def test_anomalous_exports_raise_alert(self) -> None:
        for _ in range(3):
            rid = self.client.post("/api/derechos/solicitudes", json={"tipo": "acceso"}, headers=self.auth(self.token)).get_json()["solicitud"]
            code = [m for m in self.s.mail if m["solicitud"] == rid][-1]["codigo"]
            self.client.post(f"/api/derechos/solicitudes/{rid}/verificar", json={"password": CUSTOMER_PASSWORD, "codigo": code},
                             headers=self.auth(self.token))
            self.client.get(f"/api/derechos/solicitudes/{rid}/exportacion", headers=self.auth(self.token))
            self.s.system.execute("UPDATE rights_requests SET status='cerrada' WHERE public_id=?", (rid,))
        rules = [r[0] for r in self.s.system.execute("SELECT rule FROM security_alerts")]
        self.assertIn("exportacion_anomala", rules)

    def test_full_incident_lifecycle(self) -> None:
        # Detección: fuerza bruta contra la cuenta.
        for _ in range(5):
            self.client.post("/api/auth/login", json={"email": self.person["email"], "password": "x"})
        alert = self.client.get("/api/seguridad/alertas", headers=self.sec).get_json()["alertas"][0]
        r = self.client.post("/api/seguridad/incidentes", headers=self.sec, json={
            "alertas": [alert["id"]], "resumen": "Intentos de acceso por fuerza bruta a una cuenta de cliente"})
        self.assertEqual(r.status_code, 201)
        inc = r.get_json()["incidente"]
        self.assertEqual(r.get_json()["severidad"], "media")

        # Contención 1: revocar sesiones del titular afectado (preserva evidencia antes).
        c = self.client.post(f"/api/seguridad/incidentes/{inc}/contencion", headers=self.sec,
                             json={"accion": "revocar_sesiones", "objetivo": self.person["public_id"]})
        self.assertEqual(c.status_code, 200)
        self.assertEqual(self.client.get("/api/me", headers=self.auth(self.token)).status_code, 401)
        detail = self.client.get(f"/api/seguridad/incidentes/{inc}", headers=self.sec).get_json()
        evidence = [a for a in detail["acciones"] if a["action"] == "preservar_evidencia"][0]
        files = list(self.s.evidence_dir.glob(f"{inc}_*.json"))
        self.assertEqual(len(files), 1)
        self.assertEqual(hashlib.sha256(files[0].read_bytes()).hexdigest(), evidence["evidence_sha256"])

        # Contención 2: congelar exportaciones y modo solo lectura.
        self.client.post(f"/api/seguridad/incidentes/{inc}/contencion", headers=self.sec, json={"accion": "congelar_exportaciones"})
        self.client.post(f"/api/seguridad/incidentes/{inc}/contencion", headers=self.sec, json={"accion": "modo_solo_lectura"})
        blocked = self.client.post("/api/auth/login", json={"email": self.person["email"], "password": CUSTOMER_PASSWORD})
        self.assertEqual(blocked.status_code, 503)
        self.assertEqual(self.client.get("/api/consentimientos/textos").status_code, 200)  # lectura sigue

        # No se puede cerrar con contención activa ni sin evaluación de notificación.
        close_body = {"causas": "Contraseña reutilizada filtrada en otro sitio",
                      "medidas_correctivas": "Bloqueo progresivo y aviso al titular",
                      "mejoras": "Agregar segundo factor opcional para clientes"}
        self.assertEqual(self.client.post(f"/api/seguridad/incidentes/{inc}/cierre", headers=self.sec, json=close_body).status_code, 409)

        # Recuperación: verifica integridad antes de restablecer.
        for action in ("salir_modo_solo_lectura", "descongelar_exportaciones"):
            rr = self.client.post(f"/api/seguridad/incidentes/{inc}/recuperacion", headers=self.sec,
                                  json={"accion": action, "causa_erradicada": "Se forzó cambio de contraseña del titular"})
            self.assertEqual(rr.status_code, 200)
            self.assertTrue(rr.get_json()["auditoria"]["valida"])

        # Notificación: no hubo acceso a datos → sin riesgo razonable.
        n = self.client.post(f"/api/seguridad/incidentes/{inc}/evaluacion-notificacion", headers=self.sec,
                             json={"categorias_datos": [], "riesgo_razonable": False, "titulares_estimados": 1}).get_json()
        self.assertFalse(n["reportar_agencia"])
        cl = self.client.post(f"/api/seguridad/incidentes/{inc}/cierre", headers=self.sec, json=close_body)
        self.assertEqual(cl.get_json()["fase"], "cerrado")
        for action in ("incidente.apertura", "incidente.evidencia", "incidente.contencion", "incidente.recuperacion",
                       "incidente.cierre"):
            self.assertIn(action, self.audit_actions())

    def test_disable_compromised_staff_account(self) -> None:
        support = self.staff("soporte1")
        inc = self.client.post("/api/seguridad/incidentes", headers=self.sec,
                               json={"resumen": "Credencial de soporte expuesta en repositorio público",
                                     "severidad": "critica"}).get_json()["incidente"]
        sid = self.s.system.execute("SELECT public_id FROM staff_users WHERE username='soporte1'").fetchone()[0]
        self.client.post(f"/api/seguridad/incidentes/{inc}/contencion", headers=self.sec,
                         json={"accion": "deshabilitar_cuenta", "objetivo": sid})
        self.assertEqual(self.client.get("/api/personal/clientes", headers=self.auth(support)).status_code, 401)
        relog = self.client.post("/api/personal/login", json={"username": "soporte1", "password": "Personal-Demo-2026!"})
        self.assertEqual(relog.status_code, 401)

    def test_only_security_officer_can_contain(self) -> None:
        inc = self.client.post("/api/seguridad/incidentes", headers=self.sec,
                               json={"resumen": "Prueba de permisos de contención"}).get_json()["incidente"]
        for user in ("admin1", "dpo1", "auditor1"):
            r = self.client.post(f"/api/seguridad/incidentes/{inc}/contencion", headers=self.auth(self.staff(user)),
                                 json={"accion": "modo_solo_lectura"})
            self.assertEqual(r.status_code, 403)

    def test_notification_criteria_follow_art_14_sexies(self) -> None:
        self.assertEqual(notification_assessment(["contacto"], True)["comunicar_titulares"], False)
        self.assertEqual(notification_assessment(["contacto"], True)["reportar_agencia"], True)
        self.assertTrue(notification_assessment(["financieros_comerciales"], True)["comunicar_titulares"])
        self.assertTrue(notification_assessment(["sensibles"], True)["comunicar_titulares"])
        self.assertFalse(notification_assessment(["financieros_comerciales"], False)["reportar_agencia"])


class RecoveryProceduresTests(AppTestCase):
    def test_key_rotation_reencrypts_whole_database(self) -> None:
        person, token = self.register()
        order = self.order(token, factura=True, guardar_direccion=True)
        self.keyring.add_version("v2", b"\x05" * 32)
        counts = rotate_keys(self.s.system, self.s.fields)
        self.assertEqual(counts["customers"], 1)
        self.assertEqual(counts["orders"], 1)
        for table, col in (("customers", "email_enc"), ("orders", "shipping_street_enc"), ("billing_profiles", "rut_enc"),
                           ("payments", "auth_code_enc"), ("addresses", "street_enc")):
            value = self.s.system.execute(f"SELECT {col} FROM {table}").fetchone()[0]
            self.assertTrue(value.startswith("v2:"), table)
        # Tras retirar la llave v1, el sistema sigue leyendo todo.
        del self.keyring.data_keys["v1"]
        me = self.client.get("/api/me", headers=self.auth(token)).get_json()
        self.assertEqual(me["email"], person["email"])
        lg = self.client.get("/api/logistica/despachos", headers=self.auth(self.staff("logistica1"))).get_json()
        self.assertEqual(lg["despachos"][0]["pedido"], order["pedido"])

    def test_restored_backup_does_not_resurrect_erased_customer(self) -> None:
        import shutil
        person, token = self.register()
        backup = self.tmp / "respaldo.db"
        self.s.system.execute(f"VACUUM INTO '{backup}'")  # respaldo previo a la supresión
        rid = self.client.post("/api/derechos/solicitudes", json={"tipo": "supresion"}, headers=self.auth(token)).get_json()["solicitud"]
        code = [m for m in self.s.mail if m["solicitud"] == rid][-1]["codigo"]
        self.client.post(f"/api/derechos/solicitudes/{rid}/verificar", json={"password": CUSTOMER_PASSWORD, "codigo": code},
                         headers=self.auth(token))
        tombstones = [dict(r) for r in self.s.system.execute("SELECT * FROM erasure_tombstones")]
        # Restauración: se vuelve al respaldo y se conservan las lápidas (se guardan fuera del respaldo).
        self.s.system.close()
        shutil.copy(backup, self.s.db_path)
        for suffix in ("-wal", "-shm"):
            (self.tmp / ("test.db" + suffix)).unlink(missing_ok=True)
        from nortishop.db import connect_system
        from nortishop.consent import ConsentService
        conn = connect_system(self.s.db_path)
        self.assertEqual(conn.execute("SELECT status FROM customers").fetchone()[0], "active")  # "resucitado"
        for t in tombstones:
            conn.execute("INSERT OR IGNORE INTO erasure_tombstones VALUES (?,?)", (t["customer_public_id"], t["erased_at"]))
        consent = ConsentService(conn, self.keyring.index_key, self.s.pseudo)
        self.assertEqual(reapply_erasures(conn, consent, self.s.pseudo), [person["public_id"]])
        self.assertEqual(conn.execute("SELECT status FROM customers").fetchone()[0], "erased")
        self.s.system = conn
