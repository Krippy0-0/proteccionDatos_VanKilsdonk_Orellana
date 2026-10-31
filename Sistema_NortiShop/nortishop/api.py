"""Rutas HTTP de NortiShop.

Cada endpoint protegido declara el permiso que exige con ``@require``. La
verificación ocurre en el servidor (no en la interfaz) y además la consulta SQL
corre sobre una conexión restringida al rol (``db.connect_for_role``).
"""

from __future__ import annotations

import functools
import json
import logging
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone

from flask import Blueprint, Flask, current_app, g, jsonify, render_template, request

from . import rbac
from . import validation as v
from .consent import PURPOSES, ConsentError
from .crypto import chain_mac, token_hash, GENESIS
from .db import connect_for_role, now_iso, plus
from .privacy import (anonymize_dataset_for_dev, ensure_pseudonym, mask_email, mask_name, mask_phone,
                      resolve_pseudonym, sales_report)
from .rights import RightsError, erase_customer
from .security import SEVERITY_FOR_RULE, notification_assessment, open_incident, preserve_evidence

bp = Blueprint("nortishop", __name__)
log = logging.getLogger("nortishop.api")

CUSTOMER_TTL_MIN = 120
STAFF_TTL_MIN = 30
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 15

CATALOG = {  # catálogo de demostración (precios en CLP)
    "NB-14-PRO": 899_990, "MOUSE-ERGO": 24_990, "TECLADO-MEC": 59_990, "AUDIF-BT": 39_990,
    "CARGADOR-65W": 19_990, "MONITOR-27": 229_990, "CABLE-USBC": 6_990, "SSD-1TB": 69_990,
}

ORDER_TRANSITIONS = {
    "pendiente_pago": {"pagado", "anulado"}, "pagado": {"preparando", "anulado"},
    "preparando": {"en_transito", "anulado"}, "en_transito": {"entregado"},
}


def svc():
    return current_app.extensions["nortishop"]


def rights():
    return current_app.extensions["rights_factory"]()


# ------------------------------------------------------------------ contexto de solicitud
@bp.before_app_request
def load_actor() -> None:
    g.request_id = uuid.uuid4().hex[:16]
    g.actor = {"type": "anonimo", "id": None, "public_id": "anonimo", "role": "anonimo"}
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        row = svc().system.execute(
            "SELECT * FROM sessions WHERE token_hash=? AND revoked_at IS NULL AND expires_at > ?",
            (token_hash(header[7:].strip()), now_iso())).fetchone()
        if row:
            table = "customers" if row["subject_type"] == "customer" else "staff_users"
            subject = svc().system.execute(f"SELECT public_id, status FROM {table} WHERE id=?",
                                           (row["subject_id"],)).fetchone()
            if subject and subject["status"] == "active":
                g.actor = {"type": row["subject_type"], "id": row["subject_id"],
                           "public_id": subject["public_id"], "role": row["role"]}
    g.db = connect_for_role(svc().db_path, g.actor["role"])
    # Modo solo lectura (contención): se bloquean escrituras salvo seguridad y login del personal.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        flag = svc().system.execute("SELECT value FROM system_flags WHERE name='read_only'").fetchone()
        if flag["value"] == "1" and not (request.path.startswith("/api/seguridad")
                                         or request.path == "/api/personal/login"):
            return jsonify(error="sistema_en_modo_solo_lectura", request_id=g.request_id), 503
    return None


@bp.teardown_app_request
def close_db(_exc) -> None:  # noqa: ANN001
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@bp.after_app_request
def security_headers(resp):  # noqa: ANN001
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Request-ID"] = g.get("request_id", "")
    return resp


def audit_current(action: str, resource_type: str, resource_ref: str | None, result: str = "ok",
                  details: dict | None = None) -> None:
    actor = g.get("actor") or {"type": "sistema", "public_id": "sistema", "role": "sistema"}
    svc().audit.record(action=action, actor_type=actor["type"], actor_ref=actor["public_id"],
                       actor_role=actor["role"], resource_type=resource_type, resource_ref=resource_ref,
                       result=result, request_id=g.get("request_id"), ip=request.remote_addr, details=details)


def deny(status: int, reason: str, permission: str | None = None):
    audit_current("acceso.denegado", "endpoint", request.path, "denegado",
                  {"metodo": request.method, "motivo": reason, "permiso": permission})
    svc().detector.evaluate(action="acceso.denegado", result="denegado", subject_ref=g.actor["public_id"])
    error = "no_autenticado" if status == 401 else "acceso_denegado"
    return jsonify(error=error, request_id=g.request_id), status


def require(permission: str):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if g.actor["type"] == "anonimo":
                return deny(401, "sin_sesion", permission)
            if not rbac.has_permission(g.actor["role"], permission):
                return deny(403, "rol_sin_permiso", permission)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def body() -> dict:
    data = request.get_json(silent=True)
    if data is None:
        raise v.ValidationError({"_": "se esperaba JSON"})
    return data


def current_customer() -> sqlite3.Row:
    return svc().system.execute("SELECT * FROM customers WHERE id=?", (g.actor["id"],)).fetchone()


# ------------------------------------------------------------------ manejo de errores
def register_handlers(app: Flask) -> None:
    @app.errorhandler(v.ValidationError)
    def _validation(exc: v.ValidationError):
        return jsonify(error="validacion", campos=exc.errors, request_id=g.request_id), 400

    @app.errorhandler(RightsError)
    def _rights(exc: RightsError):
        return jsonify(error=str(exc), request_id=g.request_id), exc.status

    @app.errorhandler(ConsentError)
    def _consent(exc: ConsentError):
        return jsonify(error=str(exc), request_id=g.request_id), 409

    @app.errorhandler(sqlite3.DatabaseError)
    def _db(exc: sqlite3.DatabaseError):
        if "not authorized" in str(exc) or "prohibited" in str(exc):
            # La capa de datos rechazó la consulta: defensa en profundidad.
            audit_current("acceso.denegado", "base_de_datos", request.path, "denegado",
                          {"capa": "authorizer_sqlite", "rol": g.actor["role"]})
            return jsonify(error="acceso_denegado", request_id=g.request_id), 403
        return _internal(exc)

    @app.errorhandler(404)
    def _not_found(_exc):
        return jsonify(error="no_encontrado", request_id=g.get("request_id")), 404

    @app.errorhandler(405)
    def _method(_exc):
        return jsonify(error="metodo_no_permitido", request_id=g.get("request_id")), 405

    @app.errorhandler(Exception)
    def _internal(exc: Exception):
        from werkzeug.exceptions import HTTPException  # noqa: PLC0415
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.name.lower().replace(" ", "_"), request_id=g.get("request_id")), exc.code
        log.error("Error no controlado en %s (request_id=%s)", request.path, g.get("request_id"), exc_info=exc)
        try:
            audit_current("error.interno", "endpoint", request.path, "error", {"tipo": type(exc).__name__})
        except Exception:  # noqa: BLE001
            pass
        return jsonify(error="error_interno", request_id=g.get("request_id")), 500


# ------------------------------------------------------------------ autenticación
def _issue_session(subject_type: str, subject_id: int, role: str) -> dict:
    token = secrets.token_urlsafe(32)
    ttl = CUSTOMER_TTL_MIN if subject_type == "customer" else STAFF_TTL_MIN
    g.db.execute("INSERT INTO sessions (token_hash, subject_type, subject_id, role, created_at, expires_at)"
                 " VALUES (?,?,?,?,?,?)", (token_hash(token), subject_type, subject_id, role, now_iso(), plus(minutes=ttl)))
    return {"token": token, "expira_en_min": ttl, "rol": role}


@bp.post("/api/auth/registro")
def register():
    data = v.validate(body(), v.REGISTER)
    s, now = svc(), now_iso()
    idx = s.fields.blind_index(data["email"], context="customer:email-index")
    if g.db.execute("SELECT 1 FROM customers WHERE email_idx=?", (idx,)).fetchone():
        # No se revela si el correo existe: respuesta genérica.
        return jsonify(mensaje="Si el correo es válido, recibirás un mensaje para continuar."), 202
    public_id = str(uuid.uuid4())
    cur = g.db.execute(
        "INSERT INTO customers (public_id, full_name_enc, email_enc, email_idx, phone_enc, adult_declared, status,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (public_id, s.fields.encrypt(data["nombre_completo"], context="customer:name"),
         s.fields.encrypt(data["email"], context="customer:email"), idx,
         s.fields.encrypt(data.get("telefono"), context="customer:phone"), 1, "active", now, now))
    g.db.execute("INSERT INTO credentials (customer_id, password_hash, password_changed_at) VALUES (?,?,?)",
                 (cur.lastrowid, s.hasher.hash(data["password"]), now))
    g.actor = {"type": "customer", "id": cur.lastrowid, "public_id": public_id, "role": "cliente"}
    audit_current("auth.registro", "cliente", public_id, "ok", {"telefono_informado": "telefono" in data})
    return jsonify(cliente=public_id, mensaje="Cuenta creada. Ningún consentimiento opcional fue otorgado."), 201


def _login(row, password_hash: str | None, password: str, subject_type: str, table: str, role: str | None,
           subject_ref: str):
    s = svc()
    locked = row is not None and row["locked_until"] and row["locked_until"] > now_iso()
    ok = s.hasher.verify(password, password_hash) and not locked and row["status"] == "active"
    if not ok:
        if row is not None and not locked:
            attempts = row["failed_attempts"] + 1
            key = "customer_id" if table == "credentials" else "id"
            if attempts >= MAX_FAILED_LOGINS:
                g.db.execute(f"UPDATE {table} SET failed_attempts=0, locked_until=? WHERE {key}=?",
                             (plus(minutes=LOCK_MINUTES), row[key]))
                audit_current("auth.bloqueo", subject_type, subject_ref, "denegado",
                              {"minutos": LOCK_MINUTES, "intentos": attempts})
            else:
                g.db.execute(f"UPDATE {table} SET failed_attempts=? WHERE {key}=?", (attempts, row[key]))
        audit_current("auth.login", subject_type, subject_ref, "denegado", {"bloqueada": bool(locked)})
        s.detector.evaluate(action="auth.login", result="denegado", subject_ref=subject_ref)
        return jsonify(error="credenciales_invalidas", request_id=g.request_id), 401
    key = "customer_id" if table == "credentials" else "id"
    g.db.execute(f"UPDATE {table} SET failed_attempts=0, locked_until=NULL WHERE {key}=?", (row[key],))
    return None


@bp.post("/api/auth/login")
def login():
    data = v.validate(body(), v.LOGIN)
    s = svc()
    idx = s.fields.blind_index(data["email"], context="customer:email-index")
    row = g.db.execute("SELECT c.id, c.public_id, c.status, k.customer_id, k.password_hash, k.failed_attempts,"
                       " k.locked_until FROM customers c JOIN credentials k ON k.customer_id=c.id"
                       " WHERE c.email_idx=?", (idx,)).fetchone()
    ref = row["public_id"] if row else "idx:" + idx[:12]
    failed = _login(row, row["password_hash"] if row else None, data["password"], "customer", "credentials",
                    "cliente", ref)
    if failed:
        return failed
    session = _issue_session("customer", row["id"], "cliente")
    g.actor = {"type": "customer", "id": row["id"], "public_id": row["public_id"], "role": "cliente"}
    audit_current("auth.login", "cliente", row["public_id"], "ok")
    return jsonify(session)


@bp.post("/api/personal/login")
def staff_login():
    data = v.validate(body(), v.STAFF_LOGIN)
    row = g.db.execute("SELECT * FROM staff_users WHERE username=?", (data["username"],)).fetchone()
    ref = row["public_id"] if row else "usuario_desconocido"
    failed = _login(row, row["password_hash"] if row else None, data["password"], "staff", "staff_users",
                    None, ref)
    if failed:
        return failed
    session = _issue_session("staff", row["id"], row["role"])
    g.actor = {"type": "staff", "id": row["id"], "public_id": row["public_id"], "role": row["role"]}
    audit_current("auth.login", "personal", row["public_id"], "ok")
    return jsonify(session)


@bp.post("/api/auth/logout")
def logout():
    if g.actor["type"] == "anonimo":
        return deny(401, "sin_sesion")
    token = request.headers["Authorization"][7:].strip()
    g.db.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (now_iso(), token_hash(token)))
    audit_current("auth.logout", g.actor["type"], g.actor["public_id"])
    return jsonify(mensaje="Sesión cerrada")


# ------------------------------------------------------------------ cliente: perfil, pedidos, contenido
@bp.get("/api/me")
@require("perfil:leer_propio")
def me():
    c = g.db.execute("SELECT * FROM customers WHERE id=?", (g.actor["id"],)).fetchone()
    f = svc().fields
    return jsonify(cliente=c["public_id"], nombre_completo=f.decrypt(c["full_name_enc"], context="customer:name"),
                   email=f.decrypt(c["email_enc"], context="customer:email"),
                   telefono=f.decrypt(c["phone_enc"], context="customer:phone"),
                   direcciones=[{"id": a["id"], "etiqueta": a["label"], "comuna": a["comuna"], "region": a["region"],
                                 "calle": f.decrypt(a["street_enc"], context="customer:street")}
                                for a in g.db.execute("SELECT * FROM addresses WHERE customer_id=?", (c["id"],))])


@bp.get("/api/me/pedidos")
@require("pedidos:leer_propios")
def my_orders():
    rows = g.db.execute("SELECT public_id, status, total_clp, created_at FROM orders WHERE customer_id=?"
                        " ORDER BY id DESC", (g.actor["id"],)).fetchall()
    return jsonify(pedidos=[dict(r) for r in rows])


def _loyalty_add(customer_id: int, points: int, reason: str) -> None:
    s = svc()
    last = s.system.execute("SELECT mac FROM loyalty_ledger ORDER BY id DESC LIMIT 1").fetchone()
    record = {"customer_id": customer_id, "points": points, "reason": reason, "created_at": now_iso()}
    mac = chain_mac(s.keyring.index_key, last["mac"] if last else GENESIS, record)
    g.db.execute("INSERT INTO loyalty_ledger (customer_id, points, reason, created_at, mac) VALUES (?,?,?,?,?)",
                 (customer_id, points, reason, record["created_at"], mac))


@bp.post("/api/pedidos")
@require("pedidos:crear")
def checkout():
    s = svc()
    data = v.validate(body(), {**v.CHECKOUT, "guardar_direccion": v.Field(required=False)})
    address = v.validate(data["direccion"], v.ADDRESS)
    if not isinstance(data["items"], list) or not 1 <= len(data["items"]) <= 20:
        raise v.ValidationError({"items": "entre 1 y 20 ítems"})
    items = [v.validate(i, v.ITEM) for i in data["items"]]
    unknown = [i["sku"] for i in items if i["sku"] not in CATALOG]
    if unknown:
        raise v.ValidationError({"items": f"SKU desconocido: {', '.join(unknown)}"})
    payment = v.validate(data["pago"], v.GATEWAY_RESULT)
    invoice = v.validate(data["factura"], v.FACTURA) if data.get("factura") else None
    total = sum(CATALOG[i["sku"]] * i["cantidad"] for i in items)
    cid, now = g.actor["id"], now_iso()
    public_id = "NS-" + uuid.uuid4().hex[:8].upper()
    enc = s.fields.encrypt
    billing_id = None
    if invoice:
        cur = g.db.execute(
            "INSERT INTO billing_profiles (customer_id, rut_enc, rut_idx, business_name_enc, billing_address_enc,"
            " created_at) VALUES (?,?,?,?,?,?)",
            (cid, enc(invoice["rut"], context="billing:rut"), s.fields.blind_index(invoice["rut"], context="billing:rut-index"),
             enc(invoice["razon_social"], context="billing:name"),
             enc(invoice["direccion_facturacion"], context="billing:address"), now))
        billing_id = cur.lastrowid
    cur = g.db.execute(
        "INSERT INTO orders (public_id, customer_id, status, document_type, billing_profile_id, recipient_name_enc,"
        " recipient_phone_enc, shipping_street_enc, shipping_comuna, shipping_region, total_clp, created_at,"
        " retention_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (public_id, cid, "pagado", "factura" if invoice else "boleta", billing_id,
         enc(data["destinatario"], context=f"order:{public_id}:recipient"),
         enc(data["telefono_contacto"], context=f"order:{public_id}:phone"),
         enc(address["calle"], context=f"order:{public_id}:street"), address["comuna"], address["region"],
         total, now, plus(days=365 * 6)))
    order_id = cur.lastrowid
    for i in items:
        g.db.execute("INSERT INTO order_items (order_id, sku, quantity, unit_price_clp) VALUES (?,?,?,?)",
                     (order_id, i["sku"], i["cantidad"], CATALOG[i["sku"]]))
    g.db.execute("INSERT INTO payments (order_id, brand, last4, amount_clp, status, auth_code_enc, created_at)"
                 " VALUES (?,?,?,?,?,?,?)", (order_id, payment["marca"], payment["ultimos4"], total, "aprobado",
                                            enc(payment["codigo_autorizacion"], context="payment:authorization"), now))
    g.db.execute("INSERT INTO shipments (order_id, carrier, tracking_code, status, access_expires_at)"
                 " VALUES (?,?,?,?,?)", (order_id, "TransNorte", "TN" + secrets.token_hex(5).upper(), "preparando",
                                         plus(days=10)))
    if data.get("guardar_direccion") is True:
        g.db.execute("INSERT INTO addresses (customer_id, street_enc, comuna, region, created_at) VALUES (?,?,?,?,?)",
                     (cid, enc(address["calle"], context="customer:street"), address["comuna"], address["region"], now))
    notes = []
    if data.get("guardar_medio_pago"):
        if s.consent.has_consent(cid, "guardar_medio_pago"):
            g.db.execute("INSERT INTO saved_payment_methods (customer_id, gateway_token_enc, brand, last4, created_at)"
                         " VALUES (?,?,?,?,?)", (cid, enc(payment["token"], context="payment:token"),
                                                 payment["marca"], payment["ultimos4"], now))
        else:
            notes.append("No se guardó el medio de pago: requiere consentimiento 'guardar_medio_pago'.")
    _loyalty_add(cid, max(total // 1000, 1), f"compra {public_id}")
    audit_current("pedido.creacion", "pedido", public_id, "ok", {"documento": "factura" if invoice else "boleta"})
    return jsonify(pedido=public_id, total_clp=total, notas=notes), 201


@bp.post("/api/tickets")
@require("pedidos:leer_propios")
def create_ticket():
    data = v.validate(body(), v.TICKET)
    cur = g.db.execute("INSERT INTO support_tickets (customer_id, subject, body_enc, status, created_at)"
                       " VALUES (?,?,?,?,?)", (g.actor["id"], data["asunto"],
                                               svc().fields.encrypt(data["mensaje"], context="ticket:body"),
                                               "abierto", now_iso()))
    return jsonify(ticket=cur.lastrowid), 201


@bp.post("/api/resenas")
@require("pedidos:leer_propios")
def create_review():
    data = v.validate(body(), v.REVIEW)
    g.db.execute("INSERT INTO reviews (customer_id, sku, alias, rating, body, created_at) VALUES (?,?,?,?,?,?)",
                 (g.actor["id"], data["sku"], data["alias"], data["calificacion"], data["texto"], now_iso()))
    return jsonify(mensaje="Reseña publicada con alias"), 201


@bp.post("/api/analitica/eventos")
@require("analitica:registrar_propia")
def track():
    data = v.validate(body(), {"evento": v.Field(check=v.one_of("vista_producto", "agregar_carrito", "busqueda")),
                               "sku": v.Field(required=False, check=v._str(2, 40))})  # noqa: SLF001
    s = svc()
    if not s.consent.has_consent(g.actor["id"], "analitica"):
        return jsonify(registrado=False, motivo="sin consentimiento de analítica"), 202
    ref = ensure_pseudonym(s.system, s.pseudo, g.actor["id"], "analitica")
    g.db.execute("INSERT INTO analytics_events (customer_ref, event, sku, occurred_on) VALUES (?,?,?,?)",
                 (ref, data["evento"], data.get("sku"), now_iso()[:10]))
    return jsonify(registrado=True), 201


@bp.get("/api/recomendaciones")
@require("perfil:leer_propio")
def recommendations():
    if svc().consent.has_consent(g.actor["id"], "personalizacion"):
        bought = {r["sku"] for r in g.db.execute(
            "SELECT i.sku FROM order_items i JOIN orders o ON o.id=i.order_id WHERE o.customer_id=?", (g.actor["id"],))}
        suggestions = [s for s in CATALOG if s not in bought][:3]
        return jsonify(tipo="personalizadas", productos=suggestions)
    return jsonify(tipo="genericas", productos=["CABLE-USBC", "MOUSE-ERGO", "CARGADOR-65W"])


# ------------------------------------------------------------------ consentimiento
@bp.get("/api/consentimientos/textos")
def consent_texts():
    s = svc()
    return jsonify(finalidades=[{"codigo": code, "nombre": p["name"], "descripcion": p["description"],
                                 "conservacion": p["retention"], "version": s.consent.current_text(code)["version"],
                                 "texto": s.consent.current_text(code)["body"]} for code, p in PURPOSES.items()])


@bp.get("/api/me/consentimientos")
@require("consentimiento:gestionar_propio")
def my_consents():
    return jsonify(consentimientos=svc().consent.state(g.actor["id"]))


@bp.get("/api/me/consentimientos/historial")
@require("consentimiento:gestionar_propio")
def my_consent_history():
    return jsonify(historial=svc().consent.history(g.actor["id"]))


@bp.post("/api/me/consentimientos/<purpose>/otorgar")
@require("consentimiento:gestionar_propio")
def grant_consent(purpose: str):
    if purpose not in PURPOSES:
        raise ConsentError("Finalidad desconocida")
    data = v.validate(body(), {"version_texto": v.Field(check=v._str(4, 20)),  # noqa: SLF001
                               "canal": v.Field(required=False, check=v.one_of("web", "app"))})
    record = svc().consent.grant(g.actor["id"], purpose, data["version_texto"], data.get("canal", "web"))
    audit_current("consentimiento.otorgado", "consentimiento", purpose, "ok", {"version": data["version_texto"]})
    return jsonify(finalidad=purpose, estado="otorgado", fecha_hora_utc=record["occurred_at"],
                   version_texto=record["text_version"]), 201


@bp.post("/api/me/consentimientos/<purpose>/revocar")
@require("consentimiento:gestionar_propio")
def revoke_consent(purpose: str):
    if purpose not in PURPOSES:
        raise ConsentError("Finalidad desconocida")
    record = svc().consent.revoke(g.actor["id"], purpose, "web")
    audit_current("consentimiento.revocado", "consentimiento", purpose, "ok", {"efectos": len(record["efectos"])})
    return jsonify(finalidad=purpose, estado="revocado", fecha_hora_utc=record["occurred_at"],
                   efectos=record["efectos"])


# ------------------------------------------------------------------ derechos del titular
@bp.post("/api/derechos/solicitudes")
@require("derechos:solicitar_propio")
def create_rights_request():
    return jsonify(rights().create(current_customer(), body())), 201


@bp.post("/api/derechos/solicitudes/<public_id>/verificar")
@require("derechos:solicitar_propio")
def verify_rights_request(public_id: str):
    cred = svc().system.execute("SELECT password_hash FROM credentials WHERE customer_id=?",
                                (g.actor["id"],)).fetchone()
    return jsonify(rights().verify(current_customer(), cred["password_hash"], public_id, body()))


@bp.get("/api/derechos/solicitudes")
@require("derechos:solicitar_propio")
def my_rights_requests():
    rows = g.db.execute("SELECT * FROM rights_requests WHERE customer_id=? ORDER BY id DESC", (g.actor["id"],))
    out = []
    for r in rows.fetchall():
        events = g.db.execute("SELECT status, at, note FROM rights_request_events WHERE request_id=? ORDER BY id",
                              (r["id"],)).fetchall()
        out.append({"solicitud": r["public_id"], "tipo": r["type"], "estado": r["status"], "recibida": r["received_at"],
                    "plazo": r["due_at"], "prorrogada": bool(r["extended"]), "respuesta": r["resolution"],
                    "historial": [dict(e) for e in events]})
    return jsonify(solicitudes=out)


@bp.get("/api/derechos/solicitudes/<public_id>/exportacion")
@require("derechos:solicitar_propio")
def export_rights(public_id: str):
    frozen = svc().system.execute("SELECT value FROM system_flags WHERE name='exports_frozen'").fetchone()
    if frozen["value"] == "1":
        return jsonify(error="exportaciones_suspendidas_temporalmente", request_id=g.request_id), 423
    data = rights().export(current_customer(), public_id)
    svc().detector.evaluate(action="datos.exportacion", result="ok", subject_ref=g.actor["public_id"])
    resp = jsonify(data)
    resp.headers["Content-Disposition"] = f'attachment; filename="nortishop_{public_id}.json"'
    return resp


# ------------------------------------------------------------------ personal: soporte / administración
@bp.get("/api/personal/clientes")
@require("clientes:leer_enmascarado")
def staff_customers():
    page = max(int(request.args.get("pagina", 1)), 1)
    f = svc().fields
    rows = g.db.execute("SELECT id, public_id, full_name_enc, email_enc, phone_enc, status FROM customers"
                        " WHERE status <> 'erased' ORDER BY id LIMIT 20 OFFSET ?", ((page - 1) * 20,)).fetchall()
    out = [{"cliente": r["public_id"], "nombre": mask_name(f.decrypt(r["full_name_enc"], context="customer:name")),
            "email": mask_email(f.decrypt(r["email_enc"], context="customer:email")),
            "telefono": mask_phone(f.decrypt(r["phone_enc"], context="customer:phone")), "estado": r["status"]}
           for r in rows]
    audit_current("datos.lectura_enmascarada", "clientes", f"pagina:{page}", "ok", {"registros": len(out)})
    svc().detector.evaluate(action="datos.lectura_enmascarada", result="ok", subject_ref=g.actor["public_id"])
    return jsonify(pagina=page, clientes=out)


@bp.get("/api/personal/pedidos")
@require("pedidos:leer")
def staff_orders():
    rows = g.db.execute("SELECT o.public_id, o.status, o.total_clp, o.created_at, o.shipping_region, c.public_id AS cliente"
                        " FROM orders o LEFT JOIN customers c ON c.id=o.customer_id ORDER BY o.id DESC LIMIT 50").fetchall()
    return jsonify(pedidos=[dict(r) for r in rows])


@bp.post("/api/admin/pedidos/<public_id>/estado")
@require("pedidos:actualizar_estado")
def admin_order_status(public_id: str):
    data = v.validate(body(), {"estado": v.Field(check=v.one_of("pagado", "preparando", "en_transito", "entregado",
                                                                "anulado"))})
    row = g.db.execute("SELECT id, status FROM orders WHERE public_id=?", (public_id,)).fetchone()
    if row is None:
        return jsonify(error="no_encontrado"), 404
    if data["estado"] not in ORDER_TRANSITIONS.get(row["status"], set()):
        return jsonify(error="transicion_no_permitida", desde=row["status"]), 409
    g.db.execute("UPDATE orders SET status=? WHERE id=?", (data["estado"], row["id"]))
    audit_current("admin.estado_pedido", "pedido", public_id, "ok", {"desde": row["status"], "hacia": data["estado"]})
    return jsonify(pedido=public_id, estado=data["estado"])


@bp.post("/api/admin/personal/<public_id>/rol")
@require("personal:gestionar_roles")
def change_role(public_id: str):
    data = v.validate(body(), {"rol": v.Field(check=v.one_of(*rbac.STAFF_ROLES))})
    target = g.db.execute("SELECT id, role FROM staff_users WHERE public_id=?", (public_id,)).fetchone()
    if target is None:
        return jsonify(error="no_encontrado"), 404
    if target["id"] == g.actor["id"]:
        return deny(403, "no_puede_modificar_su_propio_rol", "personal:gestionar_roles")
    if data["rol"] in rbac.PROTECTED_ROLES or target["role"] in rbac.PROTECTED_ROLES:
        return deny(403, "rol_protegido_requiere_doble_aprobacion", "personal:gestionar_roles")
    g.db.execute("UPDATE staff_users SET role=? WHERE id=?", (data["rol"], target["id"]))
    g.db.execute("UPDATE sessions SET revoked_at=? WHERE subject_type='staff' AND subject_id=? AND revoked_at IS NULL",
                 (now_iso(), target["id"]))
    audit_current("admin.cambio_rol", "personal", public_id, "ok", {"desde": target["role"], "hacia": data["rol"]})
    return jsonify(personal=public_id, rol=data["rol"], sesiones_revocadas=True)


# ------------------------------------------------------------------ logística
@bp.get("/api/logistica/despachos")
@require("despachos:leer_activos")
def active_shipments():
    f = svc().fields
    rows = g.db.execute(
        "SELECT s.id, s.tracking_code, s.status, o.public_id, o.recipient_name_enc, o.recipient_phone_enc,"
        " o.shipping_street_enc, o.shipping_comuna, o.shipping_region FROM shipments s JOIN orders o ON o.id=s.order_id"
        " WHERE s.status IN ('preparando','en_transito') AND s.access_expires_at > ?", (now_iso(),)).fetchall()
    out = [{"despacho": r["id"], "seguimiento": r["tracking_code"], "estado": r["status"], "pedido": r["public_id"],
            "destinatario": f.decrypt(r["recipient_name_enc"], context=f"order:{r['public_id']}:recipient"),
            "telefono": f.decrypt(r["recipient_phone_enc"], context=f"order:{r['public_id']}:phone"),
            "direccion": f.decrypt(r["shipping_street_enc"], context=f"order:{r['public_id']}:street"),
            "comuna": r["shipping_comuna"], "region": r["shipping_region"]} for r in rows]
    audit_current("datos.lectura_sensible", "despachos", None, "ok", {"registros": len(out)})
    return jsonify(despachos=out)


@bp.post("/api/logistica/despachos/<int:shipment_id>/estado")
@require("despachos:actualizar_estado")
def shipment_status(shipment_id: int):
    data = v.validate(body(), {"estado": v.Field(check=v.one_of("en_transito", "entregado", "fallido"))})
    row = g.db.execute("SELECT s.*, o.public_id FROM shipments s JOIN orders o ON o.id=s.order_id WHERE s.id=?"
                       " AND s.status IN ('preparando','en_transito')", (shipment_id,)).fetchone()
    if row is None:
        return jsonify(error="no_encontrado"), 404
    now = now_iso()
    if data["estado"] == "entregado":
        # Al entregar se cierra la ventana de acceso de logística.
        g.db.execute("UPDATE shipments SET status='entregado', delivered_at=?, access_expires_at=? WHERE id=?",
                     (now, now, shipment_id))
        g.db.execute("UPDATE orders SET status='entregado' WHERE id=?", (row["order_id"],))
    else:
        g.db.execute("UPDATE shipments SET status=? WHERE id=?", (data["estado"], shipment_id))
        if data["estado"] == "en_transito":
            g.db.execute("UPDATE orders SET status='en_transito' WHERE id=?", (row["order_id"],))
    audit_current("despacho.estado", "despacho", row["public_id"], "ok", {"estado": data["estado"]})
    return jsonify(despacho=shipment_id, estado=data["estado"])


# ------------------------------------------------------------------ marketing y finanzas
@bp.get("/api/marketing/audiencia")
@require("marketing:audiencia_seudonimizada")
def marketing_audience():
    rows = g.db.execute(
        "SELECT cs.customer_id FROM consent_state cs JOIN customers c ON c.id = cs.customer_id"
        " WHERE cs.purpose_code='marketing_email' AND cs.state='otorgado' AND c.status='active'").fetchall()
    pseudo = svc().pseudo
    refs = sorted(pseudo.pseudonym(r["customer_id"], domain="marketing") for r in rows)
    return jsonify(finalidad="marketing_email", total=len(refs), destinatarios=refs,
                   nota="Seudónimos; el proveedor de mailing resuelve el correo con su propia tabla de suscripción.")


@bp.get("/api/marketing/metricas")
@require("marketing:metricas_agregadas")
def marketing_metrics():
    rows = g.db.execute("SELECT event, sku, COUNT(*) AS n, COUNT(DISTINCT customer_ref) AS personas"
                        " FROM analytics_events GROUP BY event, sku").fetchall()
    published = [dict(r) for r in rows if r["personas"] >= 5]
    return jsonify(k_anonimato=5, metricas=published, filas_suprimidas=len(rows) - len(published))


@bp.get("/api/finanzas/pagos")
@require("pagos:leer_enmascarado")
def finance_payments():
    rows = g.db.execute("SELECT o.public_id, p.brand, p.last4, p.amount_clp, p.status, p.created_at FROM payments p"
                        " JOIN orders o ON o.id=p.order_id ORDER BY p.id DESC LIMIT 100").fetchall()
    return jsonify(pagos=[{"pedido": r["public_id"], "medio": f"{r['brand']} ****{r['last4']}",
                           "monto_clp": r["amount_clp"], "estado": r["status"], "fecha": r["created_at"]} for r in rows])


@bp.get("/api/reportes/ventas")
@require("reportes:ventas_anonimizadas")
def anonymized_sales():
    report = sales_report(g.db)
    audit_current("reporte.anonimizado", "reporte", "ventas_region_mes", "ok",
                  {"celdas": len(report["celdas_publicadas"]), "suprimidas": report["celdas_suprimidas"]})
    return jsonify(report)


@bp.get("/api/reportes/dataset-desarrollo")
@require("reportes:ventas_anonimizadas")
def dev_dataset():
    data = anonymize_dataset_for_dev(g.db)
    audit_current("reporte.anonimizado", "reporte", "dataset_desarrollo", "ok", {"filas": len(data)})
    return jsonify(filas=data)


# ------------------------------------------------------------------ DPO
@bp.get("/api/dpo/solicitudes")
@require("derechos:procesar")
def dpo_requests():
    rows = g.db.execute("SELECT public_id, type, status, received_at, due_at, extended, closed_at FROM rights_requests"
                        " ORDER BY id DESC LIMIT 200").fetchall()
    today = now_iso()
    return jsonify(solicitudes=[{**dict(r), "vencida": r["status"] not in ("cerrada",) and r["due_at"] < today}
                                for r in rows])


@bp.post("/api/dpo/solicitudes/<public_id>/prorroga")
@require("derechos:procesar")
def dpo_extend(public_id: str):
    data = v.validate(body(), {"motivo": v.Field(check=v._str(10, 300))})  # noqa: SLF001
    row = g.db.execute("SELECT * FROM rights_requests WHERE public_id=?", (public_id,)).fetchone()
    if row is None:
        return jsonify(error="no_encontrado"), 404
    if row["extended"] or row["status"] == "cerrada":
        return jsonify(error="la prórroga procede una sola vez y solo para solicitudes abiertas"), 409
    new_due = datetime.fromisoformat(row["due_at"]).replace(tzinfo=timezone.utc)
    from datetime import timedelta  # noqa: PLC0415
    due = (new_due + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
    g.db.execute("UPDATE rights_requests SET due_at=?, extended=1 WHERE id=?", (due, row["id"]))
    g.db.execute("INSERT INTO rights_request_events (request_id, status, at, actor_ref, note) VALUES (?,?,?,?,?)",
                 (row["id"], row["status"], now_iso(), g.actor["public_id"], "prórroga: " + data["motivo"]))
    audit_current("derechos.prorroga", "solicitud_derechos", public_id, "ok", {"nuevo_plazo": due[:10]})
    return jsonify(solicitud=public_id, nuevo_plazo=due)


@bp.post("/api/dpo/seudonimos/revertir")
@require("seudonimos:revertir")
def dpo_resolve():
    data = v.validate(body(), {"seudonimo": v.Field(check=v._str(10, 40)),  # noqa: SLF001
                               "motivo": v.Field(check=v._str(10, 300))})  # noqa: SLF001
    result = resolve_pseudonym(g.db, data["seudonimo"])
    audit_current("seudonimo.reversion", "seudonimo", data["seudonimo"], "ok" if result else "rechazado",
                  {"motivo": data["motivo"]})
    if result is None:
        return jsonify(error="no_encontrado"), 404
    return jsonify(result)


@bp.get("/api/dpo/clientes/<public_id>/consentimientos")
@require("consentimiento:leer_cualquiera")
def dpo_consents(public_id: str):
    row = g.db.execute("SELECT id FROM customers WHERE public_id=?", (public_id,)).fetchone()
    if row is None:
        return jsonify(error="no_encontrado"), 404
    audit_current("consentimiento.consulta", "cliente", public_id, "ok")
    s = svc()
    return jsonify(estado=s.consent.state(row["id"]), historial=s.consent.history(row["id"]))


@bp.post("/api/dpo/clientes/<public_id>/reporte-menor")
@require("menores:reportar")
def dpo_minor_report(public_id: str):
    """Cuenta de un menor detectada pese a la declaración: se bloquea y se suprime."""
    data = v.validate(body(), {"fuente": v.Field(check=v.one_of("soporte", "representante_legal", "revision_interna"))})
    s = svc()
    row = s.system.execute("SELECT id, status FROM customers WHERE public_id=?", (public_id,)).fetchone()
    if row is None or row["status"] == "erased":
        return jsonify(error="no_encontrado"), 404
    s.system.execute("UPDATE customers SET status='disabled' WHERE id=?", (row["id"],))
    s.system.execute("UPDATE sessions SET revoked_at=? WHERE subject_type='customer' AND subject_id=?",
                     (now_iso(), row["id"]))
    active = s.system.execute("SELECT COUNT(*) FROM orders WHERE customer_id=? AND status IN"
                              " ('pendiente_pago','pagado','preparando')", (row["id"],)).fetchone()[0]
    if active:
        s.system.execute("UPDATE orders SET status='anulado' WHERE customer_id=? AND status IN"
                         " ('pendiente_pago','pagado','preparando')", (row["id"],))
    summary = erase_customer(s.system, s.consent, s.pseudo, row["id"], public_id)
    audit_current("menores.reporte", "cliente", public_id, "ok", {"fuente": data["fuente"], "pedidos_anulados": active})
    return jsonify(cliente=public_id, estado="suprimido", pedidos_anulados_y_reembolsados=active, detalle=summary)


# ------------------------------------------------------------------ auditoría
@bp.get("/api/auditoria")
@require("auditoria:leer")
def audit_query():
    events = svc().audit.query(g.db, action=request.args.get("accion"), actor_ref=request.args.get("actor"),
                               resource_ref=request.args.get("recurso"), limit=int(request.args.get("limite", 100)))
    # La propia consulta también se audita.
    audit_current("auditoria.consulta", "auditoria", None, "ok", {"filtros": dict(request.args)})
    return jsonify(eventos=events)


@bp.get("/api/auditoria/verificar")
@require("auditoria:verificar")
def audit_verify():
    status = svc().detector.check_audit_integrity()
    audit_current("auditoria.verificacion", "auditoria", None, "ok" if status["valida"] else "error", status)
    return jsonify(status)


# ------------------------------------------------------------------ seguridad e incidentes
def _incident(public_id: str) -> sqlite3.Row:
    row = g.db.execute("SELECT * FROM incidents WHERE public_id=?", (public_id,)).fetchone()
    if row is None:
        raise RightsError("Incidente no encontrado", 404)
    return row


def _action(incident: sqlite3.Row, action: str, target: str | None, result: str, digest: str | None = None) -> None:
    g.db.execute("INSERT INTO incident_actions (incident_id, at, actor_ref, action, target_ref, result, evidence_sha256)"
                 " VALUES (?,?,?,?,?,?,?)", (incident["id"], now_iso(), g.actor["public_id"], action, target, result, digest))


@bp.get("/api/seguridad/alertas")
@require("alertas:leer")
def alerts():
    rows = g.db.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify(alertas=[{**dict(r), "details": json.loads(r["details"])} for r in rows])


@bp.post("/api/seguridad/incidentes")
@require("incidentes:gestionar")
def create_incident():
    data = v.validate(body(), {
        "alertas": v.Field(required=False), "resumen": v.Field(check=v._str(10, 300)),  # noqa: SLF001
        "severidad": v.Field(required=False, check=v.one_of("baja", "media", "alta", "critica")),
        "categorias_datos": v.Field(required=False)})
    alert_ids = [int(a) for a in (data.get("alertas") or [])]
    severity = data.get("severidad")
    if not severity:
        rules = [r["rule"] for r in g.db.execute(
            f"SELECT rule FROM security_alerts WHERE id IN ({','.join('?' * len(alert_ids)) or 'NULL'})", alert_ids)]
        order = ["baja", "media", "alta", "critica"]
        severity = max((SEVERITY_FOR_RULE.get(r, "media") for r in rules), key=order.index, default="media")
    s = svc()
    public_id = open_incident(s.system, s.audit, actor_ref=g.actor["public_id"], severity=severity,
                              summary=data["resumen"], alert_ids=alert_ids,
                              data_categories=data.get("categorias_datos") or [],
                              request_id=g.request_id, ip=request.remote_addr)
    return jsonify(incidente=public_id, severidad=severity, fase="analisis"), 201


@bp.get("/api/seguridad/incidentes/<public_id>")
@require("incidentes:gestionar")
def get_incident(public_id: str):
    inc = _incident(public_id)
    actions = g.db.execute("SELECT at, actor_ref, action, target_ref, result, evidence_sha256 FROM incident_actions"
                           " WHERE incident_id=? ORDER BY id", (inc["id"],)).fetchall()
    return jsonify(incidente={**dict(inc), "data_categories": json.loads(inc["data_categories"])},
                   acciones=[dict(a) for a in actions])


CONTAINMENT = {"revocar_sesiones", "deshabilitar_cuenta", "congelar_exportaciones", "modo_solo_lectura"}
RECOVERY = {"habilitar_cuenta", "descongelar_exportaciones", "salir_modo_solo_lectura"}


def _target_account(ref: str) -> tuple[str, int] | None:
    for table, kind in (("customers", "customer"), ("staff_users", "staff")):
        row = g.db.execute(f"SELECT id FROM {table} WHERE public_id=?", (ref,)).fetchone()
        if row:
            return kind, row["id"]
    return None


@bp.post("/api/seguridad/incidentes/<public_id>/contencion")
@require("contencion:ejecutar")
def contain(public_id: str):
    data = v.validate(body(), {"accion": v.Field(check=v.one_of(*sorted(CONTAINMENT))),
                               "objetivo": v.Field(required=False, check=v._str(3, 60))})  # noqa: SLF001
    inc = _incident(public_id)
    s = svc()
    already = g.db.execute("SELECT 1 FROM incident_actions WHERE incident_id=? AND action='preservar_evidencia'",
                           (inc["id"],)).fetchone()
    if not already:
        # Primero se preserva la evidencia: la contención no debe destruirla.
        digest = preserve_evidence(s.system, s.audit, s.evidence_dir, public_id)
        _action(inc, "preservar_evidencia", None, "ok", digest)
        audit_current("incidente.evidencia", "incidente", public_id, "ok", {"sha256": digest})
    action, target = data["accion"], data.get("objetivo")
    now = now_iso()
    if action in ("revocar_sesiones", "deshabilitar_cuenta"):
        found = _target_account(target or "")
        if not found:
            return jsonify(error="objetivo_no_encontrado"), 404
        kind, sid = found
        n = g.db.execute("UPDATE sessions SET revoked_at=? WHERE subject_type=? AND subject_id=? AND revoked_at IS NULL",
                         (now, kind, sid)).rowcount
        result = f"{n} sesiones revocadas"
        if action == "deshabilitar_cuenta":
            g.db.execute(f"UPDATE {'customers' if kind == 'customer' else 'staff_users'} SET status='disabled'"
                         " WHERE id=?", (sid,))
            result += "; cuenta deshabilitada"
    elif action == "congelar_exportaciones":
        g.db.execute("UPDATE system_flags SET value='1' WHERE name='exports_frozen'")
        result = "exportaciones congeladas"
    else:
        g.db.execute("UPDATE system_flags SET value='1' WHERE name='read_only'")
        result = "sistema en modo solo lectura"
    g.db.execute("UPDATE incidents SET phase='contencion' WHERE id=?", (inc["id"],))
    _action(inc, action, target, result)
    audit_current("incidente.contencion", "incidente", public_id, "ok", {"accion": action, "objetivo": target})
    return jsonify(incidente=public_id, accion=action, resultado=result)


@bp.post("/api/seguridad/incidentes/<public_id>/recuperacion")
@require("contencion:ejecutar")
def recover(public_id: str):
    data = v.validate(body(), {"accion": v.Field(check=v.one_of(*sorted(RECOVERY))),
                               "objetivo": v.Field(required=False, check=v._str(3, 60)),  # noqa: SLF001
                               "causa_erradicada": v.Field(check=v._str(10, 300))})  # noqa: SLF001
    inc = _incident(public_id)
    s = svc()
    integrity = s.audit.verify()
    if not integrity["valida"]:
        return jsonify(error="no se puede restablecer: la auditoría no verifica", detalle=integrity), 409
    action, target = data["accion"], data.get("objetivo")
    if action == "habilitar_cuenta":
        found = _target_account(target or "")
        if not found:
            return jsonify(error="objetivo_no_encontrado"), 404
        kind, sid = found
        table = "customers" if kind == "customer" else "staff_users"
        g.db.execute(f"UPDATE {table} SET status='active' WHERE id=? AND status='disabled'", (sid,))
        result = "cuenta habilitada (debe cambiar contraseña)"
    elif action == "descongelar_exportaciones":
        g.db.execute("UPDATE system_flags SET value='0' WHERE name='exports_frozen'")
        result = "exportaciones restablecidas"
    else:
        g.db.execute("UPDATE system_flags SET value='0' WHERE name='read_only'")
        result = "escrituras restablecidas"
    g.db.execute("UPDATE incidents SET phase='recuperacion' WHERE id=?", (inc["id"],))
    _action(inc, "erradicacion", None, data["causa_erradicada"][:200])
    _action(inc, action, target, result)
    audit_current("incidente.recuperacion", "incidente", public_id, "ok", {"accion": action})
    return jsonify(incidente=public_id, accion=action, resultado=result, auditoria=integrity)


@bp.post("/api/seguridad/incidentes/<public_id>/evaluacion-notificacion")
@require("incidentes:gestionar")
def notification(public_id: str):
    data = v.validate(body(), {"categorias_datos": v.Field(), "riesgo_razonable": v.Field(),
                               "titulares_estimados": v.Field(check=v.int_range(0, 10**8))})
    inc = _incident(public_id)
    if not isinstance(data["categorias_datos"], list) or not isinstance(data["riesgo_razonable"], bool):
        raise v.ValidationError({"categorias_datos": "lista", "riesgo_razonable": "booleano"})
    result = notification_assessment(data["categorias_datos"], data["riesgo_razonable"])
    g.db.execute("UPDATE incidents SET phase='notificacion', data_categories=?, affected_estimate=?,"
                 " requires_agency_report=?, requires_subject_notice=? WHERE id=?",
                 (json.dumps(data["categorias_datos"]), data["titulares_estimados"], int(result["reportar_agencia"]),
                  int(result["comunicar_titulares"]), inc["id"]))
    _action(inc, "evaluacion_notificacion", None, json.dumps(result, ensure_ascii=False)[:200])
    return jsonify(incidente=public_id, **result)


@bp.post("/api/seguridad/incidentes/<public_id>/cierre")
@require("incidentes:gestionar")
def close_incident(public_id: str):
    data = v.validate(body(), {"causas": v.Field(check=v._str(10, 500)),  # noqa: SLF001
                               "medidas_correctivas": v.Field(check=v._str(10, 500)),  # noqa: SLF001
                               "mejoras": v.Field(check=v._str(10, 500))})  # noqa: SLF001
    inc = _incident(public_id)
    flags = {r["name"]: r["value"] for r in g.db.execute("SELECT * FROM system_flags")}
    if flags.get("read_only") == "1" or flags.get("exports_frozen") == "1":
        return jsonify(error="no se puede cerrar con medidas de contención activas"), 409
    if inc["requires_agency_report"] is None:
        return jsonify(error="falta la evaluación de notificación"), 409
    if not s_audit_ok():
        return jsonify(error="la auditoría no verifica"), 409
    _action(inc, "lecciones_aprendidas", None, json.dumps(data, ensure_ascii=False)[:500])
    g.db.execute("UPDATE incidents SET phase='cerrado', closed_at=? WHERE id=?", (now_iso(), inc["id"]))
    audit_current("incidente.cierre", "incidente", public_id, "ok")
    return jsonify(incidente=public_id, fase="cerrado")


def s_audit_ok() -> bool:
    return svc().audit.verify()["valida"]


# ------------------------------------------------------------------ interfaz web mínima
@bp.get("/")
def index():
    return render_template("index.html")


@bp.get("/privacidad")
def privacy_center():
    return render_template("privacidad.html")
