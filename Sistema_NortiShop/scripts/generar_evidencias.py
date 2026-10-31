"""Genera las evidencias de los Hitos 2 y 3 en ``evidencias/``.

Uso (desde Sistema_NortiShop/):  python scripts/generar_evidencias.py [--sin-capturas]

Trabaja sobre una base temporal con llaves efímeras y datos sintéticos.
Las capturas de pantalla requieren Playwright con Chromium (opcional).
"""

from __future__ import annotations

import io
import json
import random
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from nortishop import create_app  # noqa: E402
from nortishop.crypto import Keyring  # noqa: E402
from nortishop.db import connect_for_role  # noqa: E402
from nortishop.rbac import EXPLICIT_DENIALS, PERMISSIONS, ROLES  # noqa: E402
from nortishop.seed import seed_staff, synthetic_person  # noqa: E402

OUT = ROOT / "evidencias"
PW_STAFF = "Personal-Demo-2026!"
PW_CUST = "Cliente-Demo-2026!"
PAY = {"token": "tok_demo_8f2a91c4", "marca": "VISA", "ultimos4": "1111", "codigo_autorizacion": "AUTH839201"}


def write(name: str, content) -> None:  # noqa: ANN001
    path = OUT / name
    if isinstance(content, (dict, list)):
        content = json.dumps(content, ensure_ascii=False, indent=2)
    path.write_text(content, encoding="utf-8")
    print("  ✓", path.relative_to(ROOT))


def run_tests() -> None:
    buf = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    with redirect_stderr(io.StringIO()):
        result = unittest.TextTestRunner(stream=buf, verbosity=2).run(suite)
    text = buf.getvalue()
    header = (f"Pruebas automatizadas NortiShop (Hitos 2 y 3)\nEjecutadas: {result.testsRun} · "
              f"Fallas: {len(result.failures)} · Errores: {len(result.errors)}\n\n")
    write("resultado_pruebas.txt", header + text)


class Scenario:
    def __init__(self, tmp: Path) -> None:
        self.app = create_app(db_path=str(tmp / "evidencia.db"), keyring=Keyring.ephemeral(),
                              evidence_dir=tmp / "incidentes")
        self.c = self.app.test_client()
        self.s = self.app.extensions["nortishop"]
        seed_staff(self.s, PW_STAFF)
        self.rng = random.Random(29)

    def h(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def customer(self) -> tuple[dict, str]:
        p = synthetic_person(self.rng)
        r = self.c.post("/api/auth/registro", json={"nombre_completo": p["nombre"], "email": p["email"], "password": PW_CUST,
                                                    "telefono": p["telefono"], "declaro_mayor_de_edad": True})
        p["public_id"] = r.get_json()["cliente"]
        t = self.c.post("/api/auth/login", json={"email": p["email"], "password": PW_CUST}).get_json()["token"]
        return p, t

    def staff(self, user: str) -> str:
        return self.c.post("/api/personal/login", json={"username": user, "password": PW_STAFF}).get_json()["token"]

    def order(self, token: str, region: str = "Antofagasta", factura: bool = False) -> dict:
        body = {"destinatario": "Destinatario Sintético", "telefono_contacto": "+56987654321",
                "direccion": {"calle": "Calle Falsa 123", "comuna": "Antofagasta", "region": region},
                "items": [{"sku": "MOUSE-ERGO", "cantidad": 1}, {"sku": "CABLE-USBC", "cantidad": 2}], "pago": dict(PAY)}
        if factura:
            body["factura"] = {"rut": "76.086.428-5", "razon_social": "Empresa Sintética SpA",
                               "direccion_facturacion": "Av. Grecia 1000, Antofagasta"}
        return self.c.post("/api/pedidos", json=body, headers=self.h(token)).get_json()

    def code(self, rid: str) -> str:
        return [m for m in self.s.mail if m["solicitud"] == rid][-1]["codigo"]

    def run(self) -> None:
        c, s = self.c, self.s
        people = [self.customer() for _ in range(6)]
        for i, (_, t) in enumerate(people):
            self.order(t, "Antofagasta" if i < 5 else "Atacama", factura=(i == 0))
        (a, ta), (b, tb), (cc, tc) = people[0], people[1], people[2]

        # --- Hito 2: minimización
        rej = c.post("/api/auth/registro", json={"nombre_completo": "Prueba Minimización", "email": "min@correo-sintetico.test",
                                                 "password": PW_CUST, "declaro_mayor_de_edad": True,
                                                 "fecha_nacimiento": "1990-05-01", "genero": "M"})
        rej_card = c.post("/api/pedidos", headers=self.h(ta), json={"destinatario": "X Y", "telefono_contacto": "+56987654321",
                          "direccion": {"calle": "Calle 1", "comuna": "Calama", "region": "Antofagasta"},
                          "items": [{"sku": "MOUSE-ERGO", "cantidad": 1}], "pago": dict(PAY), "cvv": "123"})
        raw = dict(s.system.execute("SELECT public_id, full_name_enc, email_enc, email_idx, phone_enc, adult_declared, status"
                                    " FROM customers LIMIT 1").fetchone())
        raw = {k: (v[:48] + "…" if isinstance(v, str) and len(v) > 48 else v) for k, v in raw.items()}
        cred = s.system.execute("SELECT password_hash FROM credentials LIMIT 1").fetchone()[0]
        write("h2_minimizacion_y_cifrado.json", {
            "registro_con_campos_eliminados": {"http": rej.status_code, "respuesta": rej.get_json()},
            "checkout_con_cvv": {"http": rej_card.status_code, "respuesta": rej_card.get_json()},
            "fila_customers_tal_como_queda_en_la_base": raw,
            "formato_hash_contrasena": cred.split("$")[:4] + ["<sal>", "<hash>"],
        })

        # --- Hito 2: RBAC (resultado HTTP real por rol)
        tokens = {u: self.staff(u) for u in ("soporte1", "logistica1", "marketing1", "finanzas1", "admin1", "dpo1",
                                             "seguridad1", "auditor1")}
        tokens["cliente"] = ta
        endpoints = ["/api/me", "/api/personal/clientes", "/api/logistica/despachos", "/api/marketing/audiencia",
                     "/api/finanzas/pagos", "/api/reportes/ventas", "/api/dpo/solicitudes", "/api/auditoria",
                     "/api/seguridad/alertas"]
        rows = ["| Endpoint | sin sesión | " + " | ".join(tokens) + " |", "|" + "---|" * (len(tokens) + 2)]
        for ep in endpoints:
            codes = [str(c.get(ep).status_code)] + [str(c.get(ep, headers=self.h(t)).status_code) for t in tokens.values()]
            rows.append(f"| `{ep}` | " + " | ".join(codes) + " |")
        db_denials = []
        for role, sql in [("soporte", "SELECT password_hash FROM credentials"), ("soporte", "SELECT * FROM pseudonym_vault"),
                          ("marketing", "SELECT full_name_enc FROM customers"), ("logistica", "SELECT email_enc FROM customers"),
                          ("finanzas", "SELECT gateway_token_enc FROM saved_payment_methods"),
                          ("administrador", "SELECT * FROM audit_log"), ("auditor", "DELETE FROM audit_log"),
                          ("cliente", "UPDATE consent_events SET action='otorgado'")]:
            conn = connect_for_role(s.db_path, role)
            try:
                conn.execute(sql).fetchall()
                outcome = "PERMITIDO (error)"
            except sqlite3.DatabaseError as exc:
                outcome = f"RECHAZADO por el motor: {exc}"
            conn.close()
            db_denials.append(f"| {role} | `{sql}` | {outcome} |")
        write("h2_rbac_resultados.md", "# Resultado real de la matriz RBAC\n\nCódigo HTTP obtenido por cada rol "
              "(200 = permitido, 401 = sin sesión, 403 = denegado).\n\n" + "\n".join(rows) +
              "\n\n# Restricciones en la capa de base de datos (authorizer SQLite)\n\n| Rol | Consulta | Resultado |\n|---|---|---|\n"
              + "\n".join(db_denials) + "\n")
        write("h2_matriz_permisos.json", {"roles": ROLES, "permisos": {k: sorted(v) for k, v in PERMISSIONS.items()},
                                          "denegaciones_explicitas": EXPLICIT_DENIALS})
        masked = c.get("/api/personal/clientes", headers=self.h(tokens["soporte1"])).get_json()["clientes"][:3]

        # --- Hito 2: seudonimización y anonimización
        c.post("/api/me/consentimientos/analitica/otorgar", json={"version_texto": "2026-10"}, headers=self.h(ta))
        c.post("/api/me/consentimientos/marketing_email/otorgar", json={"version_texto": "2026-10"}, headers=self.h(ta))
        c.post("/api/analitica/eventos", json={"evento": "vista_producto", "sku": "SSD-1TB"}, headers=self.h(ta))
        ev = dict(s.system.execute("SELECT customer_ref, event, sku, occurred_on FROM analytics_events").fetchone())
        audience = c.get("/api/marketing/audiencia", headers=self.h(tokens["marketing1"])).get_json()
        denied_resolve = c.post("/api/dpo/seudonimos/revertir", headers=self.h(tokens["marketing1"]),
                                json={"seudonimo": audience["destinatarios"][0], "motivo": "Intento sin autorización"})
        resolved = c.post("/api/dpo/seudonimos/revertir", headers=self.h(tokens["dpo1"]),
                          json={"seudonimo": audience["destinatarios"][0], "motivo": "Reclamo del titular por correo recibido"})
        write("h2_seudonimizacion_anonimizacion.json", {
            "vista_soporte_enmascarada": masked,
            "evento_analitica_almacenado": ev,
            "audiencia_marketing": audience,
            "reversion_por_marketing": {"http": denied_resolve.status_code},
            "reversion_por_dpo": {"http": resolved.status_code, "respuesta": resolved.get_json()},
            "reporte_ventas_k_anonimo": c.get("/api/reportes/ventas", headers=self.h(tokens["finanzas1"])).get_json(),
            "dataset_desarrollo_primeras_filas": c.get("/api/reportes/dataset-desarrollo",
                                                       headers=self.h(tokens["finanzas1"])).get_json()["filas"][:3],
        })

        # --- Hito 3: consentimiento
        c.post("/api/me/consentimientos/analitica/revocar", json={}, headers=self.h(ta))
        write("h3_consentimiento.json", {
            "estado_actual": c.get("/api/me/consentimientos", headers=self.h(ta)).get_json(),
            "historial": c.get("/api/me/consentimientos/historial", headers=self.h(ta)).get_json(),
            "version_desactualizada": c.post("/api/me/consentimientos/personalizacion/otorgar", headers=self.h(ta),
                                             json={"version_texto": "2025-01"}).get_json(),
            "registro_en_base": [dict(r) for r in s.system.execute(
                "SELECT id, subject_ref, purpose_code, text_version, action, channel, occurred_at, substr(mac,1,16)||'…' AS mac"
                " FROM consent_events")],
            "outbox_mailing": [dict(r) for r in s.system.execute("SELECT customer_ref, action, created_at FROM marketing_outbox")],
            "cadena_hmac_valida": s.consent.verify_chain(),
        })

        # --- Hito 3: derechos
        flow = {}
        r = c.post("/api/derechos/solicitudes", json={"tipo": "portabilidad"}, headers=self.h(ta)).get_json()
        flow["1_recepcion"] = r
        flow["2_verificacion_fallida"] = c.post(f"/api/derechos/solicitudes/{r['solicitud']}/verificar", headers=self.h(ta),
                                               json={"password": PW_CUST, "codigo": "000001"}).get_json()
        flow["3_verificacion_exitosa"] = c.post(f"/api/derechos/solicitudes/{r['solicitud']}/verificar", headers=self.h(ta),
                                               json={"password": PW_CUST, "codigo": self.code(r["solicitud"])}).get_json()
        export = c.get(f"/api/derechos/solicitudes/{r['solicitud']}/exportacion", headers=self.h(ta)).get_json()
        write("h3_exportacion_portabilidad_ejemplo.json", export)
        rect = c.post("/api/derechos/solicitudes", headers=self.h(tb), json={"tipo": "rectificacion", "cambios": {"telefono": "+56 9 5555 1234"}}).get_json()
        flow["rectificacion_invalida"] = c.post("/api/derechos/solicitudes", headers=self.h(tb),
                                                json={"tipo": "rectificacion", "cambios": {"telefono": "12"}}).get_json()
        flow["rectificacion"] = c.post(f"/api/derechos/solicitudes/{rect['solicitud']}/verificar", headers=self.h(tb),
                                       json={"password": PW_CUST}).get_json()
        sup = c.post("/api/derechos/solicitudes", json={"tipo": "supresion"}, headers=self.h(tc)).get_json()
        flow["supresion_con_pedido_en_curso"] = c.post(f"/api/derechos/solicitudes/{sup['solicitud']}/verificar",
                                                       headers=self.h(tc), json={"password": PW_CUST,
                                                                                 "codigo": self.code(sup["solicitud"])}).get_json()
        lg = self.h(tokens["logistica1"])
        for d in c.get("/api/logistica/despachos", headers=lg).get_json()["despachos"]:
            c.post(f"/api/logistica/despachos/{d['despacho']}/estado", json={"estado": "entregado"}, headers=lg)
        sup2 = c.post("/api/derechos/solicitudes", json={"tipo": "supresion"}, headers=self.h(tc)).get_json()
        flow["supresion_ejecutada"] = c.post(f"/api/derechos/solicitudes/{sup2['solicitud']}/verificar", headers=self.h(tc),
                                             json={"password": PW_CUST, "codigo": self.code(sup2["solicitud"])}).get_json()
        flow["cliente_suprimido_en_base"] = dict(s.system.execute(
            "SELECT public_id, full_name_enc, email_enc, phone_enc, email_idx, status, erased_at FROM customers WHERE public_id=?",
            (cc["public_id"],)).fetchone())
        flow["panel_dpo"] = c.get("/api/dpo/solicitudes", headers=self.h(tokens["dpo1"])).get_json()
        flow["historial_titular_A"] = c.get("/api/derechos/solicitudes", headers=self.h(ta)).get_json()
        write("h3_ejercicio_derechos.json", flow)

        # --- Hito 3: detección e incidente
        for _ in range(5):
            c.post("/api/auth/login", json={"email": b["email"], "password": "incorrecta"})
        for _ in range(5):
            c.get("/api/auditoria", headers=self.h(tokens["marketing1"]))
        sec = self.h(tokens["seguridad1"])
        alerts = c.get("/api/seguridad/alertas", headers=sec).get_json()["alertas"]
        brute = next(a for a in alerts if a["rule"] == "fuerza_bruta_login")
        inc = c.post("/api/seguridad/incidentes", headers=sec, json={"alertas": [brute["id"]],
                     "resumen": "Fuerza bruta contra una cuenta de cliente"}).get_json()["incidente"]
        steps = {"apertura": inc}
        steps["contencion_revocar"] = c.post(f"/api/seguridad/incidentes/{inc}/contencion", headers=sec,
                                             json={"accion": "revocar_sesiones", "objetivo": b["public_id"]}).get_json()
        steps["contencion_congelar"] = c.post(f"/api/seguridad/incidentes/{inc}/contencion", headers=sec,
                                              json={"accion": "congelar_exportaciones"}).get_json()
        steps["exportacion_durante_congelamiento"] = c.get("/api/derechos/solicitudes/X/exportacion", headers=self.h(ta)).get_json()
        steps["recuperacion"] = c.post(f"/api/seguridad/incidentes/{inc}/recuperacion", headers=sec,
                                       json={"accion": "descongelar_exportaciones",
                                             "causa_erradicada": "Bloqueo de cuenta y cambio de contraseña forzado"}).get_json()
        steps["evaluacion_notificacion"] = c.post(f"/api/seguridad/incidentes/{inc}/evaluacion-notificacion", headers=sec,
                                                  json={"categorias_datos": [], "riesgo_razonable": False,
                                                        "titulares_estimados": 1}).get_json()
        steps["cierre"] = c.post(f"/api/seguridad/incidentes/{inc}/cierre", headers=sec, json={
            "causas": "Contraseña del titular reutilizada en un sitio filtrado",
            "medidas_correctivas": "Bloqueo temporal, revocación de sesiones y aviso al titular",
            "mejoras": "Ofrecer segundo factor y detectar contraseñas filtradas al registrarse"}).get_json()
        steps["detalle"] = c.get(f"/api/seguridad/incidentes/{inc}", headers=sec).get_json()
        write("h3_alertas_e_incidente.json", {"alertas": alerts, "ciclo_incidente": steps})

        # --- Hito 3: auditoría
        events = s.audit.query(limit=40)
        write("h3_auditoria_ejemplos.json", {"verificacion_cadena": s.audit.verify(), "ultimos_eventos": events})
        copy = Path(s.db_path).with_name("copia_manipulada.db")
        s.system.execute(f"VACUUM INTO '{copy}'")
        tconn = sqlite3.connect(copy)
        tconn.execute("DROP TRIGGER audit_no_update")
        tconn.execute("UPDATE audit_log SET result='ok' WHERE result='denegado' AND id = (SELECT MIN(id) FROM audit_log WHERE result='denegado')")
        tconn.commit()
        tconn.close()
        from nortishop.audit import AuditLog  # noqa: PLC0415
        from nortishop.db import connect_system  # noqa: PLC0415
        write("h3_auditoria_manipulacion_detectada.json",
              {"escenario": "Copia de la base: se elimina el trigger y se cambia un 'denegado' por 'ok'",
               "resultado_verificacion": AuditLog(connect_system(str(copy)), s.keyring.audit_key).verify()})
        self.port_state = (people[3], people[4])


def screenshots(tmp: Path) -> None:
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except ImportError:
        print("  · Playwright no disponible: se omiten capturas")
        return
    from werkzeug.serving import make_server  # noqa: PLC0415
    app = create_app(db_path=str(tmp / "ui.db"), keyring=Keyring.ephemeral(), evidence_dir=tmp / "inc_ui")
    s = app.extensions["nortishop"]
    p = synthetic_person(random.Random(3))
    client = app.test_client()
    client.post("/api/auth/registro", json={"nombre_completo": p["nombre"], "email": p["email"], "password": PW_CUST,
                                            "telefono": p["telefono"], "declaro_mayor_de_edad": True})
    server = make_server("127.0.0.1", 5057, app, threaded=False)
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1100, "height": 900}, device_scale_factor=1)
            page.goto("http://127.0.0.1:5057/privacidad")
            page.fill("#email", p["email"])
            page.fill("#password", PW_CUST)
            page.click("#login-btn")
            page.wait_for_selector("#purposes .purpose")
            page.screenshot(path=str(OUT / "captura_1_centro_privacidad.png"), full_page=True)
            page.locator("#purposes .purpose button").nth(0).click()
            page.wait_for_timeout(400)
            page.locator("#purposes .purpose button").nth(2).click()
            page.wait_for_timeout(400)
            page.locator("#purposes .purpose button").nth(2).click()  # revocar analítica
            page.wait_for_timeout(500)
            page.screenshot(path=str(OUT / "captura_2_consentimiento_otorgado_revocado.png"), full_page=True)
            page.select_option("#tipo", "acceso")
            page.click("#req-btn")
            page.wait_for_selector("#verify-box:not(.hidden)")
            page.screenshot(path=str(OUT / "captura_3_solicitud_verificacion.png"), full_page=True)
            code = s.mail[-1]["codigo"]
            page.fill("#v-pass", PW_CUST)
            page.fill("#v-code", code)
            with page.expect_download():
                page.click("#verify-btn")
            page.wait_for_timeout(600)
            page.screenshot(path=str(OUT / "captura_4_solicitud_ejecutada.png"), full_page=True)
            browser.close()
        for f in sorted(OUT.glob("captura_*.png")):
            print("  ✓", f.relative_to(ROOT))
    finally:
        server.shutdown()


def main() -> None:
    OUT.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="nortishop_evid_"))
    try:
        print("Ejecutando pruebas…")
        run_tests()
        print("Escenario de evidencia…")
        Scenario(tmp).run()
        shutil.copy(ROOT / "nortishop" / "schema.sql", ROOT / "esquemas" / "esquema_redisenado.sql")
        if "--sin-capturas" not in sys.argv:
            print("Capturas de pantalla…")
            screenshots(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
