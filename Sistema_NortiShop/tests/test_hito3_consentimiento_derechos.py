"""Hito 3: consentimiento por finalidad y ejercicio de derechos."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from helpers import CUSTOMER_PASSWORD, PAYMENT, AppTestCase


class ConsentTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.person, self.token = self.register()
        self.h = self.auth(self.token)
        self.cid = self.s.system.execute("SELECT id FROM customers").fetchone()[0]

    def grant(self, purpose: str, version: str = "2026-10"):
        return self.client.post(f"/api/me/consentimientos/{purpose}/otorgar", json={"version_texto": version}, headers=self.h)

    def test_nothing_is_granted_by_default(self) -> None:
        state = self.client.get("/api/me/consentimientos", headers=self.h).get_json()["consentimientos"]
        self.assertEqual({v["estado"] for v in state.values()}, {"no_otorgado"})

    def test_each_purpose_is_independent(self) -> None:
        self.assertEqual(self.grant("marketing_email").status_code, 201)
        state = self.client.get("/api/me/consentimientos", headers=self.h).get_json()["consentimientos"]
        self.assertEqual(state["marketing_email"]["estado"], "otorgado")
        for other in ("personalizacion", "analitica", "guardar_medio_pago"):
            self.assertEqual(state[other]["estado"], "no_otorgado")
            self.assertFalse(self.s.consent.has_consent(self.cid, other))
        # Las funciones que dependen de otras finalidades siguen deshabilitadas.
        self.assertEqual(self.client.get("/api/recomendaciones", headers=self.h).get_json()["tipo"], "genericas")
        r = self.order(self.token, guardar_medio_pago=True)
        self.assertIn("requiere consentimiento", r["notas"][0])

    def test_outdated_text_version_is_rejected(self) -> None:
        r = self.grant("analitica", version="2025-01")
        self.assertEqual(r.status_code, 409)
        self.assertIn("versión", r.get_json()["error"])

    def test_record_contains_date_purpose_version_and_state(self) -> None:
        self.grant("analitica")
        row = self.s.system.execute("SELECT * FROM consent_events").fetchone()
        self.assertEqual((row["purpose_code"], row["text_version"], row["action"], row["channel"]),
                         ("analitica", "2026-10", "otorgado", "web"))
        datetime.fromisoformat(row["occurred_at"])
        self.assertTrue(row["subject_ref"].startswith("ps_"))  # seudónimo, no correo
        self.assertNotIn("ip", row.keys())

    def test_revocation_is_recorded_and_propagated(self) -> None:
        self.grant("marketing_email")
        self.grant("analitica")
        self.client.post("/api/analitica/eventos", json={"evento": "busqueda"}, headers=self.h)
        mk = self.auth(self.staff("marketing1"))
        self.assertEqual(self.client.get("/api/marketing/audiencia", headers=mk).get_json()["total"], 1)

        r = self.client.post("/api/me/consentimientos/marketing_email/revocar", json={}, headers=self.h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/api/marketing/audiencia", headers=mk).get_json()["total"], 0)
        actions = [a[0] for a in self.s.system.execute("SELECT action FROM marketing_outbox ORDER BY id")]
        self.assertEqual(actions, ["subscribe", "suppress"])

        r = self.client.post("/api/me/consentimientos/analitica/revocar", json={}, headers=self.h)
        self.assertIn("eliminan 1", r.get_json()["efectos"][0])
        self.assertEqual(self.s.system.execute("SELECT COUNT(*) FROM analytics_events").fetchone()[0], 0)
        self.assertFalse(self.client.post("/api/analitica/eventos", json={"evento": "busqueda"},
                                          headers=self.h).get_json()["registrado"])

        hist = self.client.get("/api/me/consentimientos/historial", headers=self.h).get_json()["historial"]
        self.assertEqual([(h["finalidad"], h["accion"]) for h in hist],
                         [("marketing_email", "otorgado"), ("analitica", "otorgado"),
                          ("marketing_email", "revocado"), ("analitica", "revocado")])
        self.assertTrue(all(h["fecha_hora_utc"] for h in hist))
        # revocar algo no otorgado no crea eventos falsos
        self.assertEqual(self.client.post("/api/me/consentimientos/personalizacion/revocar", json={},
                                          headers=self.h).status_code, 409)

    def test_revoking_saved_payment_deletes_token(self) -> None:
        self.grant("guardar_medio_pago")
        self.order(self.token, guardar_medio_pago=True)
        self.assertEqual(self.s.system.execute("SELECT COUNT(*) FROM saved_payment_methods").fetchone()[0], 1)
        self.client.post("/api/me/consentimientos/guardar_medio_pago/revocar", json={}, headers=self.h)
        self.assertEqual(self.s.system.execute("SELECT COUNT(*) FROM saved_payment_methods").fetchone()[0], 0)

    def test_history_is_append_only_and_tamper_evident(self) -> None:
        self.grant("marketing_email")
        self.client.post("/api/me/consentimientos/marketing_email/revocar", json={}, headers=self.h)
        for sql in ("UPDATE consent_events SET action='otorgado'", "DELETE FROM consent_events"):
            with self.assertRaises(sqlite3.DatabaseError):
                self.s.system.execute(sql)
        self.assertTrue(self.s.consent.verify_chain())
        # Un atacante con acceso al archivo elimina el trigger y oculta la revocación:
        self.s.system.execute("DROP TRIGGER consent_events_no_update")
        self.s.system.execute("UPDATE consent_events SET action='otorgado' WHERE action='revocado'")
        self.assertFalse(self.s.consent.verify_chain())

    def test_staff_cannot_manage_customer_consent(self) -> None:
        sup = self.auth(self.staff("soporte1"))
        self.assertEqual(self.client.post("/api/me/consentimientos/marketing_email/otorgar",
                                          json={"version_texto": "2026-10"}, headers=sup).status_code, 403)


class RightsTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.person, self.token = self.register()
        self.h = self.auth(self.token)
        self.other, self.other_token = self.register()

    def request(self, payload: dict, headers: dict | None = None):
        return self.client.post("/api/derechos/solicitudes", json=payload, headers=headers or self.h)

    def code_for(self, request_id: str) -> str:
        return [m for m in self.s.mail if m["solicitud"] == request_id][-1]["codigo"]

    def verify(self, request_id: str, code: str | None = None, password: str = CUSTOMER_PASSWORD, headers=None):
        body = {"password": password}
        if code is not None:
            body["codigo"] = code
        return self.client.post(f"/api/derechos/solicitudes/{request_id}/verificar", json=body, headers=headers or self.h)

    def test_access_portability_flow_with_identity_verification(self) -> None:
        self.order(self.token, factura=True)
        r = self.request({"tipo": "portabilidad"})
        self.assertEqual(r.status_code, 201)
        req = r.get_json()
        self.assertEqual(req["verificacion_requerida"], ["password", "codigo_correo"])
        rid = req["solicitud"]
        # sin verificar no hay exportación
        self.assertEqual(self.client.get(f"/api/derechos/solicitudes/{rid}/exportacion", headers=self.h).status_code, 409)
        self.assertEqual(self.verify(rid, "000000" if self.code_for(rid) != "000000" else "111111").status_code, 403)
        self.assertEqual(self.verify(rid, self.code_for(rid), password="incorrecta-123").status_code, 403)
        ok = self.verify(rid, self.code_for(rid))
        self.assertEqual(ok.get_json()["estado"], "ejecutada")
        export = self.client.get(f"/api/derechos/solicitudes/{rid}/exportacion", headers=self.h)
        self.assertEqual(export.status_code, 200)
        self.assertIn("attachment", export.headers["Content-Disposition"])
        data = export.get_json()
        self.assertEqual(data["titular"]["email"], self.person["email"])
        self.assertEqual(len(data["pedidos"]), 1)
        text = json.dumps(data, ensure_ascii=False)
        for forbidden in (self.other["email"], self.other["nombre"], "scrypt$", PAYMENT["token"],
                          PAYMENT["codigo_autorizacion"], "token_hash"):
            self.assertNotIn(forbidden, text)
        # estados registrados
        hist = self.client.get("/api/derechos/solicitudes", headers=self.h).get_json()["solicitudes"][0]["historial"]
        self.assertEqual([e["status"] for e in hist][:4], ["recibida", "verificacion", "evaluacion", "ejecutada"])
        self.assertIn("datos.exportacion", self.audit_actions())

    def test_other_user_cannot_touch_my_request(self) -> None:
        rid = self.request({"tipo": "acceso"}).get_json()["solicitud"]
        oh = self.auth(self.other_token)
        self.assertEqual(self.verify(rid, self.code_for(rid), headers=oh).status_code, 404)
        self.assertEqual(self.client.get(f"/api/derechos/solicitudes/{rid}/exportacion", headers=oh).status_code, 404)
        staff = self.auth(self.staff("soporte1"))
        self.assertEqual(self.client.get(f"/api/derechos/solicitudes/{rid}/exportacion", headers=staff).status_code, 403)

    def test_code_attempts_are_limited(self) -> None:
        rid = self.request({"tipo": "acceso"}).get_json()["solicitud"]
        real = self.code_for(rid)
        wrong = "999999" if real != "999999" else "888888"
        for _ in range(5):
            self.verify(rid, wrong)
        self.assertEqual(self.verify(rid, real).status_code, 409)  # ya cerrada como rechazada
        status = self.client.get("/api/derechos/solicitudes", headers=self.h).get_json()["solicitudes"][0]
        self.assertEqual(status["estado"], "cerrada")
        self.assertIn("No fue posible verificar", status["respuesta"])

    def test_rectification_validates_records_and_propagates(self) -> None:
        self.order(self.token)
        bad = self.request({"tipo": "rectificacion", "cambios": {"telefono": "123"}})
        self.assertEqual(bad.status_code, 400)
        extra = self.request({"tipo": "rectificacion", "cambios": {"fecha_nacimiento": "2000-01-01"}})
        self.assertEqual(extra.status_code, 400)
        r = self.request({"tipo": "rectificacion", "cambios": {"telefono": "+56 9 5555 1234"}}).get_json()
        self.assertEqual(r["verificacion_requerida"], ["password"])
        done = self.verify(r["solicitud"]).get_json()
        self.assertEqual(done["estado"], "cerrada")
        self.assertIn("Pedidos en curso actualizados: 1", done["respuesta"])
        me = self.client.get("/api/me", headers=self.h).get_json()
        self.assertEqual(me["telefono"], "+56955551234")
        lg = self.client.get("/api/logistica/despachos", headers=self.auth(self.staff("logistica1"))).get_json()
        self.assertEqual([d["telefono"] for d in lg["despachos"]], ["+56955551234"])  # pedido en curso actualizado
        event = [e for e in self.s.audit.query(action="datos.modificacion")][0]
        self.assertEqual(event["details"]["campos"], ["telefono"])
        self.assertNotIn("5555", json.dumps(event))  # se registra qué cambió, no el valor
        payload = self.s.system.execute("SELECT payload_enc FROM rights_requests WHERE public_id=?",
                                        (r["solicitud"],)).fetchone()[0]
        self.assertIsNone(payload)  # el valor solicitado se borra al cerrar

    def test_erasure_refused_with_active_order_then_executed(self) -> None:
        order = self.order(self.token, factura=True)
        self.client.post("/api/me/consentimientos/marketing_email/otorgar", json={"version_texto": "2026-10"}, headers=self.h)
        rid = self.request({"tipo": "supresion"}).get_json()["solicitud"]
        refused = self.verify(rid, self.code_for(rid)).get_json()
        self.assertEqual(refused["resultado"], "rechazada")
        self.assertIn("art. 7", refused["respuesta"])
        self.assertIn("30 días hábiles", refused["respuesta"])
        # se entrega el pedido y se vuelve a pedir
        lg = self.auth(self.staff("logistica1"))
        sid = self.client.get("/api/logistica/despachos", headers=lg).get_json()["despachos"][0]["despacho"]
        self.client.post(f"/api/logistica/despachos/{sid}/estado", json={"estado": "entregado"}, headers=lg)
        rid2 = self.request({"tipo": "supresion"}).get_json()["solicitud"]
        done = self.verify(rid2, self.code_for(rid2)).get_json()
        self.assertEqual(done["estado"], "cerrada")
        db = self.s.system
        c = db.execute("SELECT * FROM customers WHERE public_id=?", (self.person["public_id"],)).fetchone()
        self.assertEqual(c["status"], "erased")
        self.assertIsNone(c["email_enc"])
        self.assertIsNone(c["full_name_enc"])
        o = db.execute("SELECT * FROM orders WHERE public_id=?", (order["pedido"],)).fetchone()
        self.assertIsNotNone(o["total_clp"])        # conservado por obligación tributaria
        self.assertIsNone(o["recipient_name_enc"])  # pero sin datos de contacto
        self.assertEqual(db.execute("SELECT blocked FROM billing_profiles").fetchone()[0], 1)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM pseudonym_vault WHERE customer_id=?", (c["id"],)).fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM consent_events WHERE customer_id=?", (c["id"],)).fetchone()[0], 0)
        last = db.execute("SELECT action FROM consent_events ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.assertEqual(last, "revocado")  # la prueba de revocación se conserva, seudonimizada
        self.assertEqual(db.execute("SELECT COUNT(*) FROM erasure_tombstones").fetchone()[0], 1)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM suppression_list").fetchone()[0], 1)
        # la información suprimida deja de usarse
        login = self.client.post("/api/auth/login", json={"email": self.person["email"], "password": CUSTOMER_PASSWORD})
        self.assertEqual(login.status_code, 401)
        mk = self.client.get("/api/marketing/audiencia", headers=self.auth(self.staff("marketing1"))).get_json()
        self.assertEqual(mk["total"], 0)
        sup = self.client.get("/api/personal/clientes", headers=self.auth(self.staff("soporte1"))).get_json()
        self.assertNotIn(self.person["public_id"], str(sup))
        self.assertTrue(self.s.consent.verify_chain())

    def test_deadline_and_single_extension(self) -> None:
        rid = self.request({"tipo": "acceso"}).get_json()["solicitud"]
        row = self.s.system.execute("SELECT received_at, due_at FROM rights_requests WHERE public_id=?", (rid,)).fetchone()
        delta = datetime.fromisoformat(row["due_at"]) - datetime.fromisoformat(row["received_at"])
        self.assertEqual(delta.days, 30)
        dpo = self.auth(self.staff("dpo1"))
        motivo = {"motivo": "Volumen extraordinario de solicitudes esta semana"}
        self.assertEqual(self.client.post(f"/api/dpo/solicitudes/{rid}/prorroga", json=motivo, headers=dpo).status_code, 200)
        self.assertEqual(self.client.post(f"/api/dpo/solicitudes/{rid}/prorroga", json=motivo, headers=dpo).status_code, 409)
        listing = self.client.get("/api/dpo/solicitudes", headers=dpo).get_json()["solicitudes"]
        self.assertNotIn(self.person["email"], str(listing))  # el panel del DPO no expone datos personales

    def test_duplicate_open_requests_are_rejected(self) -> None:
        self.request({"tipo": "acceso"})
        self.assertEqual(self.request({"tipo": "acceso"}).status_code, 409)


class MinorsTests(AppTestCase):
    def test_minor_report_disables_and_erases_account(self) -> None:
        person, token = self.register()
        self.order(token)
        r = self.client.post(f"/api/dpo/clientes/{person['public_id']}/reporte-menor",
                             json={"fuente": "representante_legal"}, headers=self.auth(self.staff("dpo1")))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["pedidos_anulados_y_reembolsados"], 1)
        self.assertEqual(self.client.get("/api/me", headers=self.auth(token)).status_code, 401)
        self.assertIn("menores.reporte", self.audit_actions())
