"""Demostración guiada para el video del examen.

Habla con el servidor en ejecución (``python run.py``) por HTTP, como lo haría
cualquier cliente, y lee la base SQLite solo para mostrar cómo quedan los datos
guardados. Usa exclusivamente datos sintéticos y nunca imprime contraseñas,
tokens ni llaves.

Uso (desde Sistema_NortiShop/, con el servidor corriendo en otra terminal):

    python scripts/demo_video.py preparar        # una vez, antes de grabar
    python scripts/demo_video.py 1               # una sección
    python scripts/demo_video.py todo            # todas, con pausa entre pasos

Secciones: 1 minimización · 2 cifrado · 3 RBAC · 4 seudonimización
           5 consentimiento · 6 derechos · 7 auditoría · 8 incidentes
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

BASE = os.environ.get("NORTISHOP_URL", "http://127.0.0.1:5000")
PAUSE = "--sin-pausa" not in sys.argv
CAMILA = {"nombre": "Camila Demo Rojas", "email": "camila.demo@correo-sintetico.test", "telefono": "+56911112222"}
BRUNO = {"nombre": "Bruno Demo Soto", "email": "bruno.demo@correo-sintetico.test", "telefono": "+56933334444"}
VICTIMA = {"nombre": "Valeria Demo Araya", "email": "valeria.demo@correo-sintetico.test", "telefono": "+56955556666"}
PAGO = {"token": "tok_demo_8f2a91c4", "marca": "VISA", "ultimos4": "1111", "codigo_autorizacion": "AUTH839201"}

if os.name == "nt":
    os.system("")  # habilita colores ANSI en la consola de Windows
B, DIM, OK, BAD, WARN, CY, RST = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[0m"


# ------------------------------------------------------------------ utilidades
def load_env() -> None:
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def password() -> str:
    pw = os.environ.get("NORTISHOP_DEMO_PASSWORD")
    if not pw:
        sys.exit("Defina NORTISHOP_DEMO_PASSWORD en .env (la misma usada en seed-demo).")
    return pw


def title(n: str, text: str, legal: str) -> None:
    print(f"\n{B}{CY}━━━ {n} · {text} ━━━{RST}")
    print(f"{DIM}Fundamento: {legal}{RST}")


def step(text: str) -> None:
    if PAUSE:
        input(f"\n{WARN}▶ {text}{RST} {DIM}[Enter]{RST}")
    else:
        print(f"\n{WARN}▶ {text}{RST}")


def show(label: str, value) -> None:  # noqa: ANN001
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, indent=2)
    print(f"  {B}{label}{RST}")
    for line in value.splitlines():
        print("    " + line)


def verdict(ok: bool, text: str) -> None:
    print(f"  {OK + '✔' if ok else BAD + '✘'} {text}{RST}")


def call(method: str, path: str, body: dict | None = None, token: str | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except json.JSONDecodeError:
            return e.code, {}
    except urllib.error.URLError:
        sys.exit(f"No se pudo conectar a {BASE}. Inicie el servidor con: python run.py")


def login(person: dict) -> str:
    code, r = call("POST", "/api/auth/login", {"email": person["email"], "password": password()})
    if code != 200:
        sys.exit(f"No se pudo iniciar sesión con {person['email']} ({code}). Ejecute 'preparar'.")
    return r["token"]


def staff(user: str) -> str:
    code, r = call("POST", "/api/personal/login", {"username": user, "password": password()})
    if code != 200:
        sys.exit(f"No se pudo iniciar sesión como {user}. ¿Ejecutó seed-demo con NORTISHOP_DEMO_PASSWORD?")
    return r["token"]


def register(person: dict) -> None:
    call("POST", "/api/auth/registro", {"nombre_completo": person["nombre"], "email": person["email"],
                                        "password": password(), "telefono": person["telefono"],
                                        "declaro_mayor_de_edad": True})


def order(token: str, factura: bool = False, region: str = "Antofagasta") -> dict:
    body = {"destinatario": "Destinatario Demo", "telefono_contacto": "+56987654321",
            "direccion": {"calle": "Avenida Demo 123", "comuna": "Antofagasta", "region": region},
            "items": [{"sku": "MOUSE-ERGO", "cantidad": 1}, {"sku": "CABLE-USBC", "cantidad": 2}],
            "pago": dict(PAGO), "guardar_direccion": True}
    if factura:
        body["factura"] = {"rut": "76.086.428-5", "razon_social": "Empresa Demo SpA",
                           "direccion_facturacion": "Avenida Grecia 1000, Antofagasta"}
    return call("POST", "/api/pedidos", body, token)[1]


def mailbox_code(request_id: str) -> str:
    code, r = call("GET", "/demo/buzon.json")
    if code != 200:
        sys.exit("Inicie el servidor con NORTISHOP_DEMO_MAILBOX=1 para usar el buzón de prueba.")
    return next(m["codigo"] for m in r["mensajes"] if m["solicitud"] == request_id)


def db_path() -> str:
    return os.environ.get("NORTISHOP_DB", "instance/nortishop.db")


def ro_db() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{Path(db_path()).resolve().as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def cut(v, n: int = 46):  # noqa: ANN001
    return v if not isinstance(v, str) or len(v) <= n else v[:n] + "…"


# ------------------------------------------------------------------ secciones
def preparar() -> None:
    print(f"{B}Preparando datos sintéticos para la demostración…{RST}")
    for p in (CAMILA, BRUNO, VICTIMA):
        register(p)
    order(login(CAMILA), factura=True)
    # Cinco compradores en Antofagasta y dos en Atacama para el reporte k-anónimo.
    for i in range(7):
        p = {"nombre": f"Cliente Reporte {i}", "email": f"reporte{i}@correo-sintetico.test", "telefono": "+56900000000"}
        register(p)
        order(login(p), region="Antofagasta" if i < 5 else "Atacama")
    print(f"{OK}Listo.{RST} Cliente para el navegador: {CAMILA['email']} (contraseña: la de NORTISHOP_DEMO_PASSWORD)")


def s1_minimizacion() -> None:
    title("1", "Minimización de datos", "Ley 21.719, art. 3 (proporcionalidad) · Hito 2")
    step("Registro que intenta guardar fecha de nacimiento, género y un segundo teléfono")
    code, r = call("POST", "/api/auth/registro", {
        "nombre_completo": "Persona Demo", "email": "minimo@correo-sintetico.test", "password": password(),
        "declaro_mayor_de_edad": True, "fecha_nacimiento": "1999-05-01", "genero": "F",
        "telefono_secundario": "+56911111111"})
    show(f"HTTP {code}", r.get("campos", r))
    verdict(code == 400, "El servidor rechaza los campos que el rediseño eliminó")
    step("Checkout que envía el CVV y el número de tarjeta")
    code, r = call("POST", "/api/pedidos", {"destinatario": "X Y", "telefono_contacto": "+56987654321",
                                           "direccion": {"calle": "Calle 1", "comuna": "Calama", "region": "Antofagasta"},
                                           "items": [{"sku": "MOUSE-ERGO", "cantidad": 1}], "pago": dict(PAGO),
                                           "cvv": "123", "pan": "4111111111111111"}, login(CAMILA))
    show(f"HTTP {code}", {k: v for k, v in r.get("campos", {}).items() if k in ("cvv", "pan")})
    verdict(code == 400, "NortiShop nunca recibe ni guarda datos de tarjeta")
    step("Una persona que no declara ser mayor de edad")
    code, r = call("POST", "/api/auth/registro", {"nombre_completo": "Menor Demo", "email": "menor@correo-sintetico.test",
                                                  "password": password(), "declaro_mayor_de_edad": False})
    show(f"HTTP {code}", r.get("campos", r))
    verdict(code == 400, "Sin cuentas de menores y sin pedir fecha de nacimiento")


def s2_cifrado() -> None:
    title("2", "Cifrado, hashing y tokenización", "Ley 21.719, art. 14 quinquies (medidas de seguridad) · Actividad 2")
    step("Así queda el cliente Camila guardado en la base de datos")
    from nortishop.crypto import FieldProtector, Keyring  # noqa: PLC0415
    db = ro_db()
    f = FieldProtector(Keyring.from_environment())
    idx = f.blind_index(CAMILA["email"], context="customer:email-index")
    row = db.execute("SELECT public_id, full_name_enc, email_enc, email_idx, phone_enc FROM customers WHERE email_idx=?",
                     (idx,)).fetchone()
    show("customers (fila cruda)", {k: cut(row[k]) for k in row.keys()})
    pw = db.execute("SELECT password_hash FROM credentials c JOIN customers u ON u.id=c.customer_id WHERE u.email_idx=?",
                    (idx,)).fetchone()[0]
    show("credentials.password_hash", "$".join(pw.split("$")[:4]) + "$<sal>$<hash>")
    step("Pago y factura: sin número de tarjeta; RUT cifrado")
    pay = db.execute("SELECT brand, last4, auth_code_enc, amount_clp FROM payments ORDER BY id DESC LIMIT 1").fetchone()
    show("payments", {"marca": pay[0], "ultimos4": pay[1], "auth_code_enc": cut(pay[2]), "monto": pay[3]})
    bp = db.execute("SELECT rut_enc FROM billing_profiles ORDER BY id DESC LIMIT 1").fetchone()
    show("billing_profiles.rut_enc", cut(bp[0]) if bp else "(sin factura)")
    step("El mismo dato, descifrado por la aplicación con la llave (que no está en la base)")
    verdict(f.decrypt(row["email_enc"], context="customer:email") == CAMILA["email"],
            "AES-256-GCM recupera el correo solo con la llave y el contexto 'customer:email'")
    try:
        f.decrypt(row["email_enc"], context="customer:phone")
        verdict(False, "Contexto incorrecto aceptado")
    except Exception:  # noqa: BLE001
        verdict(True, "Con otro contexto el descifrado falla: no se pueden intercambiar campos")


def s3_rbac() -> None:
    title("3", "Control de acceso por roles (dos capas)", "Ley 21.719, art. 14 quinquies · mínimo privilegio · Hito 2")
    step("Cada rol consulta los mismos endpoints: 200 permitido · 401 sin sesión · 403 denegado")
    users = ["soporte1", "logistica1", "marketing1", "finanzas1", "dpo1", "seguridad1", "auditor1"]
    tokens = {u: staff(u) for u in users}
    tokens["cliente"] = login(CAMILA)
    eps = ["/api/personal/clientes", "/api/logistica/despachos", "/api/marketing/audiencia",
           "/api/reportes/ventas", "/api/auditoria", "/api/seguridad/alertas"]
    head = f"  {'endpoint':28}" + "".join(f"{n[:9]:>10}" for n in ["anónimo", *tokens])
    print(B + head + RST)
    for ep in eps:
        cells = [call("GET", ep)[0]] + [call("GET", ep, token=t)[0] for t in tokens.values()]
        print(f"  {ep:28}" + "".join(f"{(OK if c == 200 else BAD)}{c:>10}{RST}" for c in cells))
    step("Soporte ve a los clientes, pero enmascarados")
    show("GET /api/personal/clientes (soporte)", call("GET", "/api/personal/clientes", token=tokens["soporte1"])[1]["clientes"][:2])
    step("Segunda capa: aunque alguien salte la API, el motor SQL rechaza la consulta del rol")
    from nortishop.db import connect_for_role  # noqa: PLC0415
    for role, sql in [("soporte", "SELECT password_hash FROM credentials"),
                      ("marketing", "SELECT full_name_enc FROM customers"),
                      ("administrador", "SELECT * FROM audit_log"),
                      ("auditor", "DELETE FROM audit_log")]:
        conn = connect_for_role(db_path(), role)
        try:
            conn.execute(sql).fetchall()
            verdict(False, f"{role}: {sql}")
        except sqlite3.DatabaseError as e:
            verdict(True, f"{role:13} {sql:40} → {e}")
        conn.close()


def s4_seudonimizacion() -> None:
    title("4", "Seudonimización y anonimización", "Ley 21.719, art. 2 letras k y l · Hito 2")
    cam = login(CAMILA)
    for p in ("marketing_email", "analitica"):
        call("POST", f"/api/me/consentimientos/{p}/otorgar", {"version_texto": "2026-10"}, cam)
    call("POST", "/api/analitica/eventos", {"evento": "vista_producto", "sku": "SSD-1TB"}, cam)
    step("Marketing pide su audiencia: recibe seudónimos, no correos")
    mk = staff("marketing1")
    aud = call("GET", "/api/marketing/audiencia", token=mk)[1]
    show("GET /api/marketing/audiencia", aud)
    step("Marketing intenta revertir un seudónimo → denegado. El DPO puede, con motivo auditado")
    ref = aud["destinatarios"][0] if aud["destinatarios"] else "ps_inexistente000000"
    body = {"seudonimo": ref, "motivo": "Reclamo del titular por un correo recibido"}
    c1, _ = call("POST", "/api/dpo/seudonimos/revertir", body, mk)
    c2, r2 = call("POST", "/api/dpo/seudonimos/revertir", body, staff("dpo1"))
    verdict(c1 == 403, f"marketing → HTTP {c1}")
    verdict(c2 == 200, f"dpo → HTTP {c2} {r2}")
    step("Finanzas recibe ventas anonimizadas: celdas con menos de 5 clientes se suprimen")
    show("GET /api/reportes/ventas", call("GET", "/api/reportes/ventas", token=staff("finanzas1"))[1])


def s5_consentimiento() -> None:
    title("5", "Consentimiento por finalidad", "Ley 21.719, arts. 12 y 13 · Actividad 5 / Hito 3")
    cam = login(CAMILA)
    step("Estado actual por finalidad (independientes entre sí)")
    st = call("GET", "/api/me/consentimientos", token=cam)[1]["consentimientos"]
    show("GET /api/me/consentimientos", {k: v["estado"] for k, v in st.items()})
    step("Intentar otorgar con una versión antigua del texto informado")
    show("HTTP %d" % call("POST", "/api/me/consentimientos/personalizacion/otorgar",
                          {"version_texto": "2025-01"}, cam)[0], "versión desactualizada → rechazado")
    step("Revocar analítica: efecto inmediato en los procesos que dependen de ella")
    code, r = call("POST", "/api/me/consentimientos/analitica/revocar", {}, cam)
    show(f"HTTP {code}", r)
    c, r = call("POST", "/api/analitica/eventos", {"evento": "busqueda"}, cam)
    verdict(r.get("registrado") is False, "El evento de navegación ya no se registra")
    step("Historial completo (solo de inserción, sellado con HMAC)")
    show("GET /api/me/consentimientos/historial", call("GET", "/api/me/consentimientos/historial", token=cam)[1]["historial"][-4:])


def s6_derechos() -> None:
    title("6", "Ejercicio de derechos", "Ley 21.719, arts. 5 a 9 y 11 (30 días) · Actividad 6")
    register(BRUNO)
    bru = login(BRUNO)
    order(bru)
    step("Bruno pide supresión teniendo un pedido en curso")
    rid = call("POST", "/api/derechos/solicitudes", {"tipo": "supresion"}, bru)[1]["solicitud"]
    code, r = call("POST", f"/api/derechos/solicitudes/{rid}/verificar", {"password": "incorrecta-123", "codigo": "000000"}, bru)
    verdict(code == 403, f"Sin contraseña y código correctos no se ejecuta nada (HTTP {code})")
    r = call("POST", f"/api/derechos/solicitudes/{rid}/verificar",
             {"password": password(), "codigo": mailbox_code(rid)}, bru)[1]
    show("Respuesta fundamentada", r.get("respuesta"))
    step("Logística entrega el pedido y Bruno vuelve a pedir la supresión")
    lg = staff("logistica1")
    for d in call("GET", "/api/logistica/despachos", token=lg)[1]["despachos"]:
        if d["destinatario"] == "Destinatario Demo":
            call("POST", f"/api/logistica/despachos/{d['despacho']}/estado", {"estado": "entregado"}, lg)
    rid = call("POST", "/api/derechos/solicitudes", {"tipo": "supresion"}, bru)[1]["solicitud"]
    r = call("POST", f"/api/derechos/solicitudes/{rid}/verificar",
             {"password": password(), "codigo": mailbox_code(rid)}, bru)[1]
    show("Resultado", r)
    code, _ = call("POST", "/api/auth/login", {"email": BRUNO["email"], "password": password()})
    verdict(code == 401, "La cuenta suprimida ya no puede iniciar sesión")
    step("Panel del DPO: seguimiento de plazos sin ver datos personales")
    show("GET /api/dpo/solicitudes", call("GET", "/api/dpo/solicitudes", token=staff("dpo1"))[1]["solicitudes"][:4])


def s7_auditoria() -> None:
    title("7", "Registro de auditoría", "Ley 21.719, art. 14 quinquies · responsabilidad demostrable · Actividad 7")
    aud = staff("auditor1")
    step("Últimos eventos: quién, qué, sobre qué recurso y con qué resultado — sin datos personales")
    ev = call("GET", "/api/auditoria?limite=6", token=aud)[1]["eventos"]
    for e in ev:
        print(f"  {DIM}{e['occurred_at']}{RST} {e['actor_role']:17} {e['action']:26} {str(e['resource_ref'])[:34]:34} "
              f"{OK if e['result'] == 'ok' else BAD}{e['result']}{RST}")
    step("Verificación de la cadena HMAC")
    show("GET /api/auditoria/verificar", call("GET", "/api/auditoria/verificar", token=aud)[1])
    step("Ataque simulado sobre una COPIA de la base: borrar el trigger y cambiar un 'denegado' por 'ok'")
    from nortishop.audit import AuditLog  # noqa: PLC0415
    from nortishop.crypto import Keyring  # noqa: PLC0415
    from nortishop.db import connect_system  # noqa: PLC0415
    tmp = Path(tempfile.mkdtemp(prefix="nortishop_copia_"))
    try:
        copy = tmp / "copia.db"
        src = sqlite3.connect(db_path())
        src.execute(f"VACUUM INTO '{copy.as_posix()}'")
        src.close()
        t = sqlite3.connect(copy)
        try:
            t.execute("UPDATE audit_log SET result='ok' WHERE result='denegado'")
        except sqlite3.DatabaseError as e:
            verdict(True, f"Con el trigger activo el UPDATE se rechaza: {e}")
        t.execute("DROP TRIGGER audit_no_update")
        t.execute("UPDATE audit_log SET result='ok' WHERE id=(SELECT MIN(id) FROM audit_log WHERE result='denegado')")
        t.commit()
        t.close()
        conn = connect_system(str(copy))
        res = AuditLog(conn, Keyring.from_environment().audit_key).verify()
        conn.close()
        show("Verificación de la copia manipulada", res)
        verdict(not res["valida"], "La manipulación se detecta aunque se eliminen los triggers")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def s8_incidentes() -> None:
    title("8", "Detección y respuesta a incidentes", "Ley 21.719, art. 14 sexies · Actividad 7")
    register(VICTIMA)
    step("Detección: 5 intentos de inicio de sesión fallidos contra una cuenta")
    for _ in range(5):
        call("POST", "/api/auth/login", {"email": VICTIMA["email"], "password": "adivinando-123"})
    sec = staff("seguridad1")
    alerts = call("GET", "/api/seguridad/alertas", token=sec)[1]["alertas"]
    brute = next((a for a in alerts if a["rule"] == "fuerza_bruta_login"), None)
    show("Alerta generada", {k: brute[k] for k in ("id", "rule", "level", "status", "details")} if brute else "sin alerta")
    step("El oficial de seguridad confirma y abre un incidente")
    code, r = call("POST", "/api/seguridad/incidentes",
                   {"alertas": [brute["id"]] if brute else [], "resumen": "Fuerza bruta contra una cuenta de cliente"}, sec)
    inc = r["incidente"]
    show(f"HTTP {code}", r)
    step("Contención: congelar exportaciones (antes se preserva la evidencia con SHA-256)")
    show("congelar_exportaciones", call("POST", f"/api/seguridad/incidentes/{inc}/contencion",
                                         {"accion": "congelar_exportaciones"}, sec)[1])
    c, r = call("GET", "/api/derechos/solicitudes/X/exportacion", token=login(CAMILA))
    verdict(c == 423, f"Durante la contención las descargas responden HTTP {c}")
    step("Cierre bloqueado mientras haya contención activa")
    close = {"causas": "Contraseña adivinada por fuerza bruta", "medidas_correctivas": "Bloqueo temporal y aviso al titular",
             "mejoras": "Agregar segundo factor opcional para clientes"}
    c, r = call("POST", f"/api/seguridad/incidentes/{inc}/cierre", close, sec)
    verdict(c == 409, f"HTTP {c}: {r.get('error')}")
    step("Recuperación (exige auditoría íntegra) y evaluación de notificación")
    show("recuperación", call("POST", f"/api/seguridad/incidentes/{inc}/recuperacion",
                              {"accion": "descongelar_exportaciones",
                               "causa_erradicada": "Cuenta bloqueada y contraseña restablecida"}, sec)[1].get("resultado"))
    show("evaluación art. 14 sexies", call("POST", f"/api/seguridad/incidentes/{inc}/evaluacion-notificacion",
                                           {"categorias_datos": [], "riesgo_razonable": False, "titulares_estimados": 1}, sec)[1])
    step("Cierre con lecciones aprendidas y bitácora del incidente")
    show("cierre", call("POST", f"/api/seguridad/incidentes/{inc}/cierre", close, sec)[1])
    acts = call("GET", f"/api/seguridad/incidentes/{inc}", token=sec)[1]["acciones"]
    for a in acts:
        print(f"  {DIM}{a['at']}{RST} {a['action']:26} {cut(a['result'], 50)}"
              + (f" {DIM}sha256={a['evidence_sha256'][:16]}…{RST}" if a["evidence_sha256"] else ""))


SECTIONS = {"1": s1_minimizacion, "2": s2_cifrado, "3": s3_rbac, "4": s4_seudonimizacion,
            "5": s5_consentimiento, "6": s6_derechos, "7": s7_auditoria, "8": s8_incidentes}


def main() -> None:
    load_env()
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return
    if args[0] == "preparar":
        preparar()
    elif args[0] == "todo":
        for fn in SECTIONS.values():
            fn()
    else:
        for a in args:
            SECTIONS[a]()


if __name__ == "__main__":
    main()
