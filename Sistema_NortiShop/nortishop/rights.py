"""Ejercicio de derechos del titular (Hito 3, etapa 2).

Flujo: recibida → verificacion → evaluacion → ejecutada | rechazada → cerrada.
Cada transición queda en ``rights_request_events`` y en la auditoría.

Verificación de identidad proporcional al riesgo, sin pedir datos nuevos:
- Toda solicitud exige sesión iniciada y reingresar la contraseña.
- Acceso, portabilidad, supresión y cambio de correo exigen además un código de
  un solo uso enviado al correo registrado (10 minutos, 5 intentos, guardado como hash).
- No se solicita copia de cédula ni selfie: serían datos adicionales innecesarios.

Plazo: 30 días corridos desde la recepción, prorrogable una vez hasta 30 días
(Ley 19.628 modificada por Ley 21.719, art. 11).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import uuid

from . import validation as v
from .consent import ConsentService
from .crypto import FieldProtector, PasswordHasher, token_hash
from .db import now_iso, plus

HIGH_RISK = {"acceso", "portabilidad", "supresion"}
EXPORT_WINDOW_HOURS = 24
ACTIVE_ORDER_STATES = ("pendiente_pago", "pagado", "preparando", "en_transito")


class RightsError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class RightsService:
    def __init__(self, system: sqlite3.Connection, fields: FieldProtector, hasher: PasswordHasher,
                 consent: ConsentService, pseudo, mail_sink, audit_fn) -> None:  # noqa: ANN001
        self.db = system
        self.fields = fields
        self.hasher = hasher
        self.consent = consent
        self.pseudo = pseudo
        self.mail = mail_sink
        self.audit = audit_fn  # callable(action, resource_ref, result, details)

    # ---------- utilidades ----------
    def _event(self, request_id: int, status: str, actor: str, note: str | None = None) -> None:
        self.db.execute("INSERT INTO rights_request_events (request_id, status, at, actor_ref, note)"
                        " VALUES (?,?,?,?,?)", (request_id, status, now_iso(), actor, note))

    def _get_owned(self, public_id: str, customer_id: int) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM rights_requests WHERE public_id=?", (public_id,)).fetchone()
        if row is None or row["customer_id"] != customer_id:
            # misma respuesta si no existe o es de otro titular: no se revela su existencia
            raise RightsError("Solicitud no encontrada", 404)
        return row

    def _send_code(self, req: sqlite3.Row, customer: sqlite3.Row) -> None:
        code = f"{secrets.randbelow(10**6):06d}"
        self.db.execute("UPDATE rights_requests SET verification_code_hash=?, verification_expires_at=?,"
                        " verification_attempts=0 WHERE id=?", (token_hash(code), plus(minutes=10), req["id"]))
        email = self.fields.decrypt(customer["email_enc"], context="customer:email")
        # El proveedor de correo es externo; en la demo, ``mail_sink`` recibe el mensaje y no se persiste.
        self.mail.append({"para": email, "asunto": "Código para tu solicitud de privacidad",
                          "solicitud": req["public_id"], "codigo": code})

    # ---------- 1. recepción ----------
    def create(self, customer: sqlite3.Row, payload: dict) -> dict:
        data = v.validate(payload, v.RIGHTS_REQUEST)
        kind = data["tipo"]
        changes_enc = None
        if kind == "rectificacion":
            changes = v.validate(data.get("cambios") or {}, v.RECTIFICATION)
            if not changes:
                raise v.ValidationError({"cambios": "indique al menos un dato a corregir"})
            if any(k in changes for k in ("calle", "comuna", "region")) and "direccion_id" not in changes:
                raise v.ValidationError({"direccion_id": "indique qué dirección corregir"})
            changes_enc = self.fields.encrypt(json.dumps(changes, ensure_ascii=False), context="rights:payload")
        elif data.get("cambios"):
            raise v.ValidationError({"cambios": "solo aplica a rectificación"})
        open_same = self.db.execute(
            "SELECT 1 FROM rights_requests WHERE customer_id=? AND type=? AND status NOT IN ('cerrada')",
            (customer["id"], kind)).fetchone()
        if open_same:
            raise RightsError("Ya existe una solicitud del mismo tipo en curso", 409)
        public_id = "SOL-" + uuid.uuid4().hex[:10].upper()
        ref = self.consent.subject_ref(customer["id"])
        cur = self.db.execute(
            "INSERT INTO rights_requests (public_id, customer_id, subject_ref, type, status, received_at, due_at,"
            " payload_enc) VALUES (?,?,?,?,?,?,?,?)",
            (public_id, customer["id"], ref, kind, "recibida", now_iso(), plus(days=30), changes_enc))
        self._event(cur.lastrowid, "recibida", customer["public_id"])
        self.audit("derechos.solicitud", public_id, "ok", {"tipo": kind})
        req = self.db.execute("SELECT * FROM rights_requests WHERE id=?", (cur.lastrowid,)).fetchone()
        needs_code = kind in HIGH_RISK or (kind == "rectificacion" and "email" in self._changes(req))
        self.db.execute("UPDATE rights_requests SET status='verificacion' WHERE id=?", (req["id"],))
        self._event(req["id"], "verificacion", "sistema",
                    "contraseña + código por correo" if needs_code else "contraseña")
        if needs_code:
            self._send_code(req, customer)
        return {"solicitud": public_id, "tipo": kind, "estado": "verificacion",
                "plazo_respuesta": plus(days=30)[:10],
                "verificacion_requerida": ["password", "codigo_correo"] if needs_code else ["password"]}

    def _changes(self, req: sqlite3.Row) -> dict:
        if not req["payload_enc"]:
            return {}
        return json.loads(self.fields.decrypt(req["payload_enc"], context="rights:payload"))

    # ---------- 2. verificación ----------
    def verify(self, customer: sqlite3.Row, password_hash: str, public_id: str, payload: dict) -> dict:
        req = self._get_owned(public_id, customer["id"])
        if req["status"] != "verificacion":
            raise RightsError("La solicitud no está pendiente de verificación", 409)
        if not isinstance(payload, dict) or set(payload) - {"password", "codigo"}:
            raise v.ValidationError({"_": "solo se aceptan 'password' y 'codigo'"})
        if not self.hasher.verify(str(payload.get("password", "")), password_hash):
            self.audit("derechos.verificacion", public_id, "denegado", {"motivo": "contraseña"})
            raise RightsError("Verificación fallida", 403)
        if req["verification_code_hash"]:
            attempts = req["verification_attempts"] + 1
            self.db.execute("UPDATE rights_requests SET verification_attempts=? WHERE id=?", (attempts, req["id"]))
            expired = req["verification_expires_at"] < now_iso()
            ok = token_hash(str(payload.get("codigo", ""))) == req["verification_code_hash"]
            if attempts > 5 or expired or not ok:
                self.audit("derechos.verificacion", public_id, "denegado",
                           {"motivo": "codigo_expirado" if expired else "codigo", "intento": attempts})
                if attempts >= 5 or expired:
                    self._reject(req, "No fue posible verificar la identidad del solicitante (código vencido o"
                                      " intentos agotados). Puede presentar una nueva solicitud.")
                raise RightsError("Verificación fallida", 403)
        self.db.execute("UPDATE rights_requests SET status='evaluacion', verified_at=?, verification_code_hash=NULL"
                        " WHERE id=?", (now_iso(), req["id"]))
        self._event(req["id"], "evaluacion", customer["public_id"], "identidad verificada")
        self.audit("derechos.verificacion", public_id, "ok", {})
        return self.evaluate_and_execute(req["id"], actor="sistema")

    # ---------- 3-4. evaluación y ejecución ----------
    def evaluate_and_execute(self, request_id: int, actor: str) -> dict:
        req = self.db.execute("SELECT * FROM rights_requests WHERE id=?", (request_id,)).fetchone()
        customer = self.db.execute("SELECT * FROM customers WHERE id=?", (req["customer_id"],)).fetchone()
        self.db.execute("UPDATE rights_requests SET evaluated_at=? WHERE id=?", (now_iso(), request_id))
        kind = req["type"]
        if kind in ("acceso", "portabilidad"):
            frozen = self.db.execute("SELECT value FROM system_flags WHERE name='exports_frozen'").fetchone()
            if frozen["value"] == "1":
                note = "Exportaciones suspendidas temporalmente por un incidente de seguridad; se responderá dentro del plazo legal."
                self._event(request_id, "evaluacion", actor, note)
                return {"solicitud": req["public_id"], "estado": "evaluacion", "respuesta": note}
            resolution = (f"Copia disponible para descarga durante {EXPORT_WINDOW_HOURS} horas en formato JSON "
                          "estructurado (Ley 21.719, arts. 5 y 9).")
            return self._execute(req, resolution, {"descarga": f"/api/derechos/solicitudes/{req['public_id']}/exportacion"})
        if kind == "rectificacion":
            return self._rectify(req, customer)
        if kind == "oposicion":
            return self._oppose_marketing(req, customer)
        if kind == "supresion":
            return self._erase(req, customer)
        raise RightsError("Tipo no soportado")

    def _execute(self, req: sqlite3.Row, resolution: str, extra: dict | None = None) -> dict:
        now = now_iso()
        self.db.execute("UPDATE rights_requests SET status='ejecutada', executed_at=?, resolution=? WHERE id=?",
                        (now, resolution, req["id"]))
        self._event(req["id"], "ejecutada", "sistema", resolution[:200])
        self.audit("derechos.ejecucion", req["public_id"], "ok", {"tipo": req["type"]})
        if req["type"] in ("rectificacion", "supresion", "oposicion"):
            self._close(req["id"], req["public_id"])
        return {"solicitud": req["public_id"], "estado": "ejecutada" if req["type"] in ("acceso", "portabilidad")
                else "cerrada", "respuesta": resolution, **(extra or {})}

    def _reject(self, req: sqlite3.Row, reason: str) -> dict:
        self.db.execute("UPDATE rights_requests SET status='rechazada', resolution=? WHERE id=?", (reason, req["id"]))
        self._event(req["id"], "rechazada", "sistema", reason[:200])
        self.audit("derechos.rechazo", req["public_id"], "rechazado", {"tipo": req["type"]})
        self._close(req["id"], req["public_id"])
        return {"solicitud": req["public_id"], "estado": "cerrada", "resultado": "rechazada",
                "respuesta": reason + " Puede reclamar ante la Agencia de Protección de Datos Personales "
                                      "dentro de 30 días hábiles (Ley 21.719, art. 11)."}

    def _close(self, request_id: int, public_id: str) -> None:
        self.db.execute("UPDATE rights_requests SET status='cerrada', closed_at=?, payload_enc=NULL WHERE id=?",
                        (now_iso(), request_id))
        self._event(request_id, "cerrada", "sistema")
        self.audit("derechos.cierre", public_id, "ok", {})

    # ---------- acceso / portabilidad ----------
    def export(self, customer: sqlite3.Row, public_id: str) -> dict:
        req = self._get_owned(public_id, customer["id"])
        if req["type"] not in ("acceso", "portabilidad") or req["status"] != "ejecutada":
            raise RightsError("La exportación no está disponible", 409)
        if req["executed_at"] < plus(minutes=-60 * EXPORT_WINDOW_HOURS):
            self._close(req["id"], public_id)
            raise RightsError("La ventana de descarga expiró; presente una nueva solicitud", 410)
        data = self.build_export(customer["id"])
        self.audit("datos.exportacion", public_id, "ok", {"tipo": req["type"], "secciones": sorted(data)})
        return data

    def build_export(self, customer_id: int) -> dict:
        """Solo datos del titular; excluye información interna y datos de terceros."""
        f, db = self.fields, self.db
        c = db.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
        dec = lambda value, ctx: f.decrypt(value, context=ctx)  # noqa: E731
        orders = []
        for o in db.execute("SELECT * FROM orders WHERE customer_id=? ORDER BY id", (customer_id,)):
            items = [{"sku": i["sku"], "cantidad": i["quantity"], "precio_unitario_clp": i["unit_price_clp"]}
                     for i in db.execute("SELECT * FROM order_items WHERE order_id=?", (o["id"],))]
            pay = db.execute("SELECT brand, last4, amount_clp, status, created_at FROM payments WHERE order_id=?",
                             (o["id"],)).fetchone()
            shipment = db.execute("SELECT carrier, tracking_code, status, delivered_at FROM shipments"
                                  " WHERE order_id=?", (o["id"],)).fetchone()
            orders.append({
                "pedido": o["public_id"], "fecha": o["created_at"], "estado": o["status"],
                "documento": o["document_type"], "total_clp": o["total_clp"],
                "destinatario": dec(o["recipient_name_enc"], f"order:{o['public_id']}:recipient"),
                "telefono_destinatario": dec(o["recipient_phone_enc"], f"order:{o['public_id']}:phone")
                if o["recipient_phone_enc"] else None,
                "direccion_despacho": dec(o["shipping_street_enc"], f"order:{o['public_id']}:street"),
                "comuna": o["shipping_comuna"], "region": o["shipping_region"], "items": items,
                "despacho": dict(shipment) if shipment else None,
                # Sin token ni código de autorización: son datos internos del medio de pago.
                "pago": dict(pay) if pay else None,
            })
        return {
            "formato": "NortiShop-portabilidad/1.0 (JSON, UTF-8)",
            "generado_utc": now_iso(),
            "titular": {
                "identificador": c["public_id"],
                "nombre_completo": dec(c["full_name_enc"], "customer:name"),
                "email": dec(c["email_enc"], "customer:email"),
                "telefono": dec(c["phone_enc"], "customer:phone"),
                "cuenta_creada": c["created_at"],
                "mayor_de_edad_declarado": bool(c["adult_declared"]),
                "estado_cuenta": c["status"],
            },
            "direcciones": [{"id": a["id"], "etiqueta": a["label"], "calle": dec(a["street_enc"], "customer:street"),
                             "comuna": a["comuna"], "region": a["region"]}
                            for a in db.execute("SELECT * FROM addresses WHERE customer_id=?", (customer_id,))],
            "pedidos": orders,
            "nortipuntos": [{"puntos": l["points"], "motivo": l["reason"], "fecha": l["created_at"]}
                            for l in db.execute("SELECT * FROM loyalty_ledger WHERE customer_id=? ORDER BY id",
                                                (customer_id,))],
            "resenas": [{"sku": r["sku"], "alias": r["alias"], "calificacion": r["rating"], "texto": r["body"],
                         "fecha": r["created_at"]}
                        for r in db.execute("SELECT * FROM reviews WHERE customer_id=?", (customer_id,))],
            "consentimientos": {"estado_actual": self.consent.state(customer_id),
                                "historial": self.consent.history(customer_id)},
            "medios_de_pago_guardados": [{"marca": p["brand"], "ultimos4": p["last4"]}
                                         for p in db.execute("SELECT brand, last4 FROM saved_payment_methods"
                                                             " WHERE customer_id=?", (customer_id,))],
            "facturacion": [{"rut": dec(b["rut_enc"], "billing:rut"),
                              "razon_social": dec(b["business_name_enc"], "billing:name"),
                              "direccion": dec(b["billing_address_enc"], "billing:address"),
                              "bloqueado_por_conservacion": bool(b["blocked"]), "fecha": b["created_at"]}
                             for b in db.execute("SELECT * FROM billing_profiles WHERE customer_id=? ORDER BY id",
                                                 (customer_id,))],
            "soporte": [{"asunto": t["subject"],
                         "mensaje": dec(t["body_enc"], "ticket:body") if t["body_enc"] else None,
                         "estado": t["status"], "fecha": t["created_at"]}
                        for t in db.execute("SELECT * FROM support_tickets WHERE customer_id=? ORDER BY id",
                                            (customer_id,))],
            "analitica": [{"evento": a["event"], "sku": a["sku"], "fecha": a["occurred_on"]}
                          for a in db.execute("SELECT event, sku, occurred_on FROM analytics_events"
                                              " WHERE customer_ref=? ORDER BY id",
                                              (self.pseudo.pseudonym(customer_id, domain="analitica"),))],
            "solicitudes_derechos": [{"solicitud": r["public_id"], "tipo": r["type"],
                                      "estado": r["status"], "recibida": r["received_at"],
                                      "respuesta": r["resolution"]}
                                     for r in db.execute("SELECT * FROM rights_requests WHERE customer_id=? ORDER BY id",
                                                         (customer_id,))],
            "actividad_seguridad": [{"fecha": a["occurred_at"], "accion": a["action"],
                                     "resultado": a["result"], "recurso": a["resource_type"]}
                                    for a in db.execute("SELECT occurred_at, action, result, resource_type"
                                                        " FROM audit_log WHERE actor_ref=? OR resource_ref=? ORDER BY id",
                                                        (c["public_id"], c["public_id"]))],
            "excluido": ["hash de contraseña", "tokens de sesión y de pago", "códigos de autorización",
                         "notas internas y detalles de alertas", "datos de otros clientes"],
        }

    # ---------- rectificación ----------
    def _rectify(self, req: sqlite3.Row, customer: sqlite3.Row) -> dict:
        changes = self._changes(req)
        f, cid, now = self.fields, customer["id"], now_iso()
        addr = None
        if "direccion_id" in changes:
            addr = self.db.execute("SELECT * FROM addresses WHERE id=? AND customer_id=?",
                                   (changes["direccion_id"], cid)).fetchone()
            if addr is None:
                return self._reject(req, "La dirección indicada no pertenece a la cuenta.")
        updated = []
        if "email" in changes:
            idx = f.blind_index(changes["email"], context="customer:email-index")
            clash = self.db.execute("SELECT 1 FROM customers WHERE email_idx=? AND id<>?", (idx, cid)).fetchone()
            if clash:
                return self._reject(req, "El correo indicado no puede asociarse a esta cuenta.")
            self.db.execute("UPDATE customers SET email_enc=?, email_idx=?, updated_at=? WHERE id=?",
                            (f.encrypt(changes["email"], context="customer:email"), idx, now, cid))
            updated.append("email")
        if "nombre_completo" in changes:
            self.db.execute("UPDATE customers SET full_name_enc=?, updated_at=? WHERE id=?",
                            (f.encrypt(changes["nombre_completo"], context="customer:name"), now, cid))
            updated.append("nombre_completo")
        if "telefono" in changes:
            self.db.execute("UPDATE customers SET phone_enc=?, updated_at=? WHERE id=?",
                            (f.encrypt(changes["telefono"], context="customer:phone"), now, cid))
            updated.append("telefono")
        propagated = 0
        if "direccion_id" in changes:
            street = changes.get("calle") or f.decrypt(addr["street_enc"], context="customer:street")
            comuna = changes.get("comuna", addr["comuna"])
            region = changes.get("region", addr["region"])
            self.db.execute("UPDATE addresses SET street_enc=?, comuna=?, region=? WHERE id=?",
                            (f.encrypt(street, context="customer:street"), comuna, region, addr["id"]))
            updated.append("direccion")
            # Propagación: pedidos aún no despachados toman la dirección corregida.
            for o in self.db.execute("SELECT id, public_id FROM orders WHERE customer_id=? AND status IN"
                                     " ('pendiente_pago','pagado','preparando')", (cid,)).fetchall():
                self.db.execute("UPDATE orders SET shipping_street_enc=?, shipping_comuna=?, shipping_region=?"
                                " WHERE id=?", (f.encrypt(street, context=f"order:{o['public_id']}:street"),
                                                comuna, region, o["id"]))
                propagated += 1
        if "telefono" in changes:
            for o in self.db.execute("SELECT id, public_id FROM orders WHERE customer_id=? AND status IN"
                                     " ('pendiente_pago','pagado','preparando','en_transito')", (cid,)).fetchall():
                self.db.execute("UPDATE orders SET recipient_phone_enc=? WHERE id=?",
                                (f.encrypt(changes["telefono"], context=f"order:{o['public_id']}:phone"), o["id"]))
                propagated += 1
        self.audit("datos.modificacion", customer["public_id"], "ok",
                   {"campos": updated, "pedidos_actualizados": propagated, "solicitud": req["public_id"]})
        return self._execute(req, f"Datos corregidos: {', '.join(updated)}. Pedidos en curso actualizados: "
                                  f"{propagated}. Las facturas ya emitidas no se modifican (documento tributario).")

    # ---------- supresión ----------
    def _oppose_marketing(self, req: sqlite3.Row, customer: sqlite3.Row) -> dict:
        """Detiene la audiencia y comunica la baja al proveedor de mailing."""
        cid = customer["id"]
        current = self.consent.state(cid)["marketing_email"]
        if current["estado"] == "otorgado":
            self.consent.revoke(cid, "marketing_email", channel="sistema")
        else:
            ref = self.pseudo.pseudonym(cid, domain="marketing")
            self.db.execute("INSERT INTO marketing_outbox (customer_ref, action, created_at)"
                            " VALUES (?,?,?)", (ref, "suppress", now_iso()))
        self.audit("datos.oposicion", customer["public_id"], "ok",
                   {"finalidad": "marketing_email", "solicitud": req["public_id"]})
        return self._execute(req, "Se bloqueó el correo de marketing y se registró la baja para el proveedor de mailing.")

    # ---------- supresión ----------
    def _erase(self, req: sqlite3.Row, customer: sqlite3.Row) -> dict:
        cid = customer["id"]
        active = self.db.execute(f"SELECT COUNT(*) FROM orders WHERE customer_id=? AND status IN"
                                 f" ({','.join('?' * len(ACTIVE_ORDER_STATES))})",
                                 (cid, *ACTIVE_ORDER_STATES)).fetchone()[0]
        if active:
            return self._reject(req, f"Hay {active} pedido(s) en curso. La supresión no procede mientras el"
                                     " tratamiento sea necesario para ejecutar el contrato (Ley 21.719, art. 7)."
                                     " Podrá solicitarla cuando se entreguen o anulen.")
        summary = erase_customer(self.db, self.consent, self.pseudo, cid, customer["public_id"])
        self.audit("datos.supresion", customer["public_id"], "ok", summary)
        return self._execute(req, "Datos suprimidos. Se conservan bloqueados solo los registros de pedidos y"
                                  " facturas exigidos por la normativa tributaria hasta su plazo, y la prueba"
                                  " seudonimizada de sus decisiones de consentimiento.", {"detalle": summary})


def erase_customer(db: sqlite3.Connection, consent: ConsentService, pseudo, cid: int, public_id: str) -> dict:  # noqa: ANN001
    """Supresión con conservación mínima legalmente justificada (una sola transacción)."""
    now = now_iso()
    out: dict[str, int] = {}
    db.execute("BEGIN IMMEDIATE")
    try:
        # 1. Revocar consentimientos vigentes: deja constancia y propaga efectos.
        revoked = 0
        for purpose, st in consent.state(cid).items():
            if st["estado"] == "otorgado":
                consent.append_event(cid, purpose, st["version_texto"], "revocado", "sistema")
                revoked += 1
        out["consentimientos_revocados"] = revoked
        email_idx = db.execute("SELECT email_idx FROM customers WHERE id=?", (cid,)).fetchone()["email_idx"]
        # 2. Datos sin obligación de conservación: se eliminan.
        out["direcciones"] = db.execute("DELETE FROM addresses WHERE customer_id=?", (cid,)).rowcount
        out["medios_pago_guardados"] = db.execute("DELETE FROM saved_payment_methods WHERE customer_id=?",
                                                  (cid,)).rowcount
        out["sesiones"] = db.execute("DELETE FROM sessions WHERE subject_type='customer' AND subject_id=?",
                                     (cid,)).rowcount
        db.execute("DELETE FROM credentials WHERE customer_id=?", (cid,))
        out["nortipuntos"] = db.execute("DELETE FROM loyalty_ledger WHERE customer_id=?", (cid,)).rowcount
        out["eventos_analitica"] = db.execute("DELETE FROM analytics_events WHERE customer_ref=?",
                                              (pseudo.pseudonym(cid, domain="analitica"),)).rowcount
        out["resenas_anonimizadas"] = db.execute(
            "UPDATE reviews SET customer_id=NULL, alias='Cliente' WHERE customer_id=?", (cid,)).rowcount
        out["tickets_vaciados"] = db.execute(
            "UPDATE support_tickets SET body_enc=NULL, customer_id=NULL WHERE customer_id=?", (cid,)).rowcount
        # 3. Pedidos entregados: se borran destinatario, teléfono y calle; quedan monto, ítems, comuna/región
        #    y fecha por obligación tributaria y de consumo hasta retention_until (bloqueados).
        out["pedidos_minimizados"] = db.execute(
            "UPDATE orders SET recipient_name_enc=NULL, recipient_phone_enc=NULL, shipping_street_enc=NULL"
            " WHERE customer_id=?", (cid,)).rowcount
        out["perfiles_factura_bloqueados"] = db.execute(
            "UPDATE billing_profiles SET blocked=1 WHERE customer_id=?", (cid,)).rowcount
        # 4. Baja de marketing y lista de supresión (solo índice ciego, no el correo).
        db.execute("INSERT INTO marketing_outbox (customer_ref, action, created_at) VALUES (?,?,?)",
                   (pseudo.pseudonym(cid, domain="marketing"), "suppress", now))
        db.execute("INSERT OR IGNORE INTO suppression_list (email_idx, reason, created_at) VALUES (?,?,?)",
                   (email_idx, "supresion_titular", now))
        # 5. Desvincular el id interno de la evidencia de consentimiento y destruir la tabla de seudónimos:
        #    lo seudonimizado que queda pasa a ser anónimo.
        db.execute("UPDATE consent_events SET customer_id=NULL WHERE customer_id=?", (cid,))
        out["seudonimos_destruidos"] = db.execute("DELETE FROM pseudonym_vault WHERE customer_id=?",
                                                  (cid,)).rowcount
        db.execute("UPDATE customers SET full_name_enc=NULL, email_enc=NULL, phone_enc=NULL, email_idx=?,"
                   " status='erased', erased_at=?, updated_at=? WHERE id=?",
                   ("suprimido:" + uuid.uuid4().hex, now, now, cid))
        # 6. Lápida: si se restaura un respaldo anterior, la supresión se vuelve a aplicar.
        db.execute("INSERT OR IGNORE INTO erasure_tombstones (customer_public_id, erased_at) VALUES (?,?)",
                   (public_id, now))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return out
