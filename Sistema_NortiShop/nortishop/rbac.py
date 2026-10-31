"""Modelo RBAC de NortiShop (Hito 2, parte 3).

Dos capas complementarias:
1. ``PERMISSIONS``: qué operaciones de la API puede invocar cada rol
   (se verifica en el servidor con el decorador ``require``).
2. ``DB_POLICY``: qué tablas puede leer o escribir la conexión SQL de cada rol.
   Se aplica con ``sqlite3.Connection.set_authorizer``: aunque un endpoint
   tuviera un error de lógica, la consulta a una tabla no autorizada falla en
   el motor de base de datos.
"""

from __future__ import annotations

ROLES = {
    "cliente": "Titular de los datos. Gestiona su cuenta, pedidos, consentimientos y solicitudes de derechos.",
    "soporte": "Atiende tickets y consultas. Ve datos de clientes enmascarados.",
    "logistica": "Coordina despachos activos. Ve destinatario, contacto y dirección solo durante la ventana de entrega.",
    "marketing": "Gestiona campañas. Solo ve audiencias seudonimizadas con consentimiento vigente y métricas agregadas.",
    "finanzas": "Concilia pagos y emite facturas. Ve pagos enmascarados y reportes anonimizados.",
    "administrador": "Administra catálogo, estados de pedidos y cuentas del personal. No ve datos personales completos.",
    "dpo": "Encargado de protección de datos. Procesa solicitudes de derechos y es el único que revierte seudónimos.",
    "oficial_seguridad": "Gestiona alertas e incidentes y ejecuta acciones de contención y recuperación.",
    "auditor": "Revisa el registro de auditoría en modo solo lectura.",
}

STAFF_ROLES = tuple(r for r in ROLES if r != "cliente")

PERMISSIONS: dict[str, set[str]] = {
    "cliente": {
        "perfil:leer_propio", "pedidos:leer_propios", "pedidos:crear",
        "consentimiento:gestionar_propio", "derechos:solicitar_propio", "analitica:registrar_propia",
    },
    "soporte": {"clientes:leer_enmascarado", "pedidos:leer", "tickets:gestionar"},
    "logistica": {"despachos:leer_activos", "despachos:actualizar_estado"},
    "marketing": {"marketing:audiencia_seudonimizada", "marketing:metricas_agregadas"},
    "finanzas": {"pagos:leer_enmascarado", "reportes:ventas_anonimizadas"},
    "administrador": {"clientes:leer_enmascarado", "pedidos:leer", "pedidos:actualizar_estado",
                      "personal:gestionar_roles"},
    "dpo": {"derechos:procesar", "seudonimos:revertir", "consentimiento:leer_cualquiera",
            "clientes:leer_enmascarado", "auditoria:leer", "menores:reportar"},
    "oficial_seguridad": {"alertas:leer", "incidentes:gestionar", "contencion:ejecutar",
                          "auditoria:leer", "auditoria:verificar"},
    "auditor": {"auditoria:leer", "auditoria:verificar"},
}

# Acciones explícitamente denegadas (para la matriz y para pruebas negativas).
EXPLICIT_DENIALS: dict[str, list[str]] = {
    "cliente": ["Datos de otros clientes", "Registro de auditoría", "Seudónimos", "Funciones administrativas"],
    "soporte": ["RUT, dirección y teléfono completos", "Tokens y códigos de pago", "Exportaciones masivas",
                "Ejecutar supresiones", "Auditoría"],
    "logistica": ["Pedidos entregados o fuera de la ventana", "RUT, correo, historial y pagos", "Datos de clientes sin despacho"],
    "marketing": ["Identidad real (nombre, correo, RUT)", "Revertir seudónimos", "Clientes sin consentimiento",
                  "Historial individual de compras"],
    "finanzas": ["Token de pago y PAN", "Datos de contacto", "Registros individuales en reportes"],
    "administrador": ["Descifrar datos personales completos", "Modificar o borrar auditoría", "Llaves criptográficas",
                      "Cambiar su propio rol", "Asignar roles dpo/oficial_seguridad/auditor"],
    "dpo": ["Modificar o borrar auditoría", "Llaves criptográficas", "Cambiar roles"],
    "oficial_seguridad": ["Datos personales de clientes", "Revertir seudónimos", "Modificar auditoría"],
    "auditor": ["Cualquier escritura", "Datos personales de clientes"],
}

# Roles que solo un proceso fuera de banda (dos personas) puede asignar.
PROTECTED_ROLES = {"administrador", "dpo", "oficial_seguridad", "auditor"}

R, W = "read", "write"
_ALL_CUSTOMER_DATA = {
    "customers", "credentials", "addresses", "billing_profiles", "orders", "order_items", "payments",
    "saved_payment_methods", "shipments", "loyalty_ledger", "reviews", "support_tickets",
}

# Política de la capa de datos: tablas por rol y tipo de operación.
# audit_log, security_alerts, incidents y pseudonym_vault (inserción) los escribe
# solo la conexión de sistema (servicios internos), nunca la conexión de un rol.
DB_POLICY: dict[str, dict[str, set[str]]] = {
    "anonimo": {
        R: {"customers", "credentials", "staff_users", "sessions", "consent_purposes", "consent_texts",
            "system_flags"},
        W: {"customers", "credentials", "sessions", "staff_users"},
    },
    "cliente": {
        R: _ALL_CUSTOMER_DATA | {"sessions", "consent_purposes", "consent_texts", "consent_events",
                                 "rights_requests", "rights_request_events", "system_flags"},
        W: {"addresses", "billing_profiles", "orders", "order_items", "payments", "saved_payment_methods",
            "shipments", "loyalty_ledger", "reviews", "support_tickets", "sessions", "rights_requests",
            "rights_request_events", "analytics_events"},
    },
    "soporte": {R: {"customers", "orders", "order_items", "support_tickets", "sessions", "system_flags"},
                W: {"support_tickets", "sessions"}},
    "logistica": {R: {"orders", "shipments", "sessions", "system_flags"}, W: {"shipments", "orders", "sessions"}},
    "marketing": {R: {"consent_events", "analytics_events", "customers", "sessions", "system_flags"},
                  W: {"sessions"}},
    "finanzas": {R: {"payments", "orders", "order_items", "billing_profiles", "sessions", "system_flags"},
                 W: {"sessions"}},
    "administrador": {R: {"customers", "orders", "order_items", "staff_users", "sessions", "system_flags"},
                      W: {"orders", "staff_users", "sessions"}},
    "dpo": {R: _ALL_CUSTOMER_DATA | {"sessions", "consent_events", "consent_purposes", "consent_texts",
                                     "rights_requests", "rights_request_events", "pseudonym_vault",
                                     "analytics_events", "system_flags", "audit_log", "audit_anchor"},
            W: {"sessions", "rights_requests", "rights_request_events", "customers"}},
    "oficial_seguridad": {R: {"sessions", "security_alerts", "incidents", "incident_actions", "audit_log",
                              "audit_anchor", "system_flags", "staff_users", "customers"},
                          W: {"sessions", "system_flags", "customers", "staff_users", "security_alerts", "incidents",
                             "incident_actions"}},
    "auditor": {R: {"sessions", "audit_log", "audit_anchor", "system_flags"}, W: {"sessions"}},
}

# Roles que leen ``customers`` pero solo estas columnas (estado de cuenta, sin datos personales).
CUSTOMER_STATUS_ROLES = {"marketing", "oficial_seguridad"}
CUSTOMER_STATUS_COLUMNS = {"id", "public_id", "status"}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())


def permission_matrix() -> list[dict]:
    """Matriz rol × permiso para el informe y la evidencia."""
    all_perms = sorted({p for perms in PERMISSIONS.values() for p in perms})
    return [{"permiso": p, **{r: ("Permitido" if p in PERMISSIONS[r] else "Denegado") for r in ROLES}}
            for p in all_perms]
