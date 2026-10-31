-- NortiShop: esquema rediseñado (Hito 2) + módulos de cumplimiento (Hito 3).
-- Convenciones:
--   *_enc  : AES-256-GCM por campo (nortishop/crypto.py), nunca texto claro.
--   *_idx  : índice ciego HMAC-SHA-256 para búsqueda exacta.
--   public_id : identificador opaco (UUID) para APIs y auditoría; el id entero no sale del sistema.

PRAGMA foreign_keys = ON;

-- ============ Identidad y cuentas ============
CREATE TABLE IF NOT EXISTS customers (
    id              INTEGER PRIMARY KEY,
    public_id       TEXT    NOT NULL UNIQUE,
    full_name_enc   TEXT,                       -- NULL tras supresión
    email_enc       TEXT,
    email_idx       TEXT    NOT NULL UNIQUE,
    phone_enc       TEXT,                       -- opcional
    adult_declared  INTEGER NOT NULL CHECK (adult_declared IN (0, 1)),  -- reemplaza fecha de nacimiento
    status          TEXT    NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'locked', 'disabled', 'erased')),
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    erased_at       TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    customer_id      INTEGER PRIMARY KEY REFERENCES customers(id) ON DELETE CASCADE,
    password_hash    TEXT    NOT NULL,           -- scrypt$N$r$p$sal$hash
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT,
    password_changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS staff_users (
    id               INTEGER PRIMARY KEY,
    public_id        TEXT    NOT NULL UNIQUE,
    username         TEXT    NOT NULL UNIQUE,
    role             TEXT    NOT NULL CHECK (role IN ('soporte', 'logistica', 'marketing', 'finanzas',
                                                      'administrador', 'dpo', 'oficial_seguridad', 'auditor')),
    status           TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'locked', 'disabled')),
    password_hash    TEXT    NOT NULL,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT,
    created_at       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash    TEXT PRIMARY KEY,               -- SHA-256 del token; el token no se guarda
    subject_type  TEXT NOT NULL CHECK (subject_type IN ('customer', 'staff')),
    subject_id    INTEGER NOT NULL,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT
);

-- ============ Direcciones y facturación ============
CREATE TABLE IF NOT EXISTS addresses (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    label        TEXT    NOT NULL DEFAULT 'principal',
    street_enc   TEXT    NOT NULL,                -- calle y número cifrados
    comuna       TEXT    NOT NULL,                -- en claro: necesario para tarifas y reportes agregados
    region       TEXT    NOT NULL,
    created_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS billing_profiles (       -- solo si el cliente pide factura
    id                   INTEGER PRIMARY KEY,
    customer_id          INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    rut_enc              TEXT NOT NULL,
    rut_idx              TEXT NOT NULL,
    business_name_enc    TEXT NOT NULL,
    billing_address_enc  TEXT NOT NULL,
    blocked              INTEGER NOT NULL DEFAULT 0,  -- 1 = conservado solo por obligación legal
    created_at           TEXT NOT NULL
);

-- ============ Pedidos, pagos y despacho ============
CREATE TABLE IF NOT EXISTS orders (
    id                   INTEGER PRIMARY KEY,
    public_id            TEXT    NOT NULL UNIQUE,
    customer_id          INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    status               TEXT    NOT NULL CHECK (status IN ('pendiente_pago', 'pagado', 'preparando',
                                                        'en_transito', 'entregado', 'anulado')),
    document_type        TEXT    NOT NULL CHECK (document_type IN ('boleta', 'factura')),
    billing_profile_id   INTEGER REFERENCES billing_profiles(id),
    recipient_name_enc   TEXT,
    recipient_phone_enc  TEXT,
    shipping_street_enc  TEXT,
    shipping_comuna      TEXT    NOT NULL,
    shipping_region      TEXT    NOT NULL,
    total_clp            INTEGER NOT NULL CHECK (total_clp >= 0),
    created_at           TEXT    NOT NULL,
    retention_until      TEXT    NOT NULL           -- respaldo comercial/tributario
);

CREATE TABLE IF NOT EXISTS order_items (
    id              INTEGER PRIMARY KEY,
    order_id        INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    sku             TEXT    NOT NULL,
    quantity        INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_clp  INTEGER NOT NULL CHECK (unit_price_clp >= 0)
);

CREATE TABLE IF NOT EXISTS payments (               -- sin PAN, sin CVV, sin vencimiento
    id             INTEGER PRIMARY KEY,
    order_id       INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    brand          TEXT    NOT NULL,
    last4          TEXT    NOT NULL CHECK (length(last4) = 4),
    amount_clp     INTEGER NOT NULL,
    status         TEXT    NOT NULL CHECK (status IN ('aprobado', 'rechazado', 'reembolsado')),
    auth_code_enc  TEXT,
    created_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_payment_methods (  -- solo con consentimiento 'guardar_medio_pago'
    id                INTEGER PRIMARY KEY,
    customer_id       INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    gateway_token_enc TEXT    NOT NULL,
    brand             TEXT    NOT NULL,
    last4             TEXT    NOT NULL,
    created_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS shipments (
    id                 INTEGER PRIMARY KEY,
    order_id           INTEGER NOT NULL UNIQUE REFERENCES orders(id) ON DELETE CASCADE,
    carrier            TEXT    NOT NULL,
    tracking_code      TEXT    NOT NULL,
    status             TEXT    NOT NULL CHECK (status IN ('preparando', 'en_transito', 'entregado', 'fallido')),
    delivered_at       TEXT,
    access_expires_at  TEXT    NOT NULL           -- fin de la ventana en que logística ve los datos
);

-- ============ Fidelización, contenido y soporte ============
CREATE TABLE IF NOT EXISTS loyalty_ledger (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    points       INTEGER NOT NULL CHECK (points <> 0),
    reason       TEXT    NOT NULL,
    created_at   TEXT    NOT NULL,
    mac          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    sku          TEXT    NOT NULL,
    alias        TEXT    NOT NULL,                -- alias público, no nombre completo
    rating       INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    body         TEXT    NOT NULL,
    created_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS support_tickets (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    subject      TEXT    NOT NULL,
    body_enc     TEXT,
    status       TEXT    NOT NULL CHECK (status IN ('abierto', 'cerrado')),
    created_at   TEXT    NOT NULL,
    closed_at    TEXT
);

-- ============ Seudonimización ============
CREATE TABLE IF NOT EXISTS pseudonym_vault (        -- información adicional que revierte seudónimos: solo DPO
    pseudonym    TEXT PRIMARY KEY,
    domain       TEXT    NOT NULL,
    customer_id  INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    created_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS analytics_events (       -- seudonimizado; requiere consentimiento 'analitica'
    id            INTEGER PRIMARY KEY,
    customer_ref  TEXT NOT NULL,
    event         TEXT NOT NULL CHECK (event IN ('vista_producto', 'agregar_carrito', 'busqueda')),
    sku           TEXT,
    occurred_on   TEXT NOT NULL                    -- solo fecha (día), sin hora exacta ni IP
);

CREATE TABLE IF NOT EXISTS marketing_outbox (       -- sincronización con proveedor de mailing
    id            INTEGER PRIMARY KEY,
    customer_ref  TEXT NOT NULL,
    action        TEXT NOT NULL CHECK (action IN ('subscribe', 'suppress')),
    created_at    TEXT NOT NULL,
    sent_at       TEXT
);

CREATE TABLE IF NOT EXISTS suppression_list (       -- evita volver a contactar a quien se opuso o fue suprimido
    email_idx    TEXT PRIMARY KEY,
    reason       TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- ============ Consentimiento (Hito 3) ============
CREATE TABLE IF NOT EXISTS consent_purposes (
    code         TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL,
    retention    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consent_texts (
    id            INTEGER PRIMARY KEY,
    purpose_code  TEXT NOT NULL REFERENCES consent_purposes(code),
    version       TEXT NOT NULL,
    body          TEXT NOT NULL,
    body_sha256   TEXT NOT NULL,
    published_at  TEXT NOT NULL,
    is_current    INTEGER NOT NULL DEFAULT 1,
    UNIQUE (purpose_code, version)
);

CREATE TABLE IF NOT EXISTS consent_events (         -- append-only, sellado con HMAC encadenado
    id             INTEGER PRIMARY KEY,
    customer_id    INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    subject_ref    TEXT NOT NULL,                  -- seudónimo estable: conserva la prueba aunque se suprima la cuenta
    purpose_code   TEXT NOT NULL REFERENCES consent_purposes(code),
    text_version   TEXT NOT NULL,
    action         TEXT NOT NULL CHECK (action IN ('otorgado', 'revocado')),
    channel        TEXT NOT NULL CHECK (channel IN ('web', 'app', 'soporte', 'sistema')),
    occurred_at    TEXT NOT NULL,
    prev_mac       TEXT NOT NULL,
    mac            TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS consent_events_no_update BEFORE UPDATE OF
    subject_ref, purpose_code, text_version, action, channel, occurred_at, prev_mac, mac ON consent_events
BEGIN SELECT RAISE(ABORT, 'consent_events es solo de inserción'); END;

CREATE TRIGGER IF NOT EXISTS consent_events_no_delete BEFORE DELETE ON consent_events
BEGIN SELECT RAISE(ABORT, 'consent_events es solo de inserción'); END;

CREATE VIEW IF NOT EXISTS consent_state AS
SELECT e.subject_ref, e.customer_id, e.purpose_code, e.action AS state, e.text_version, e.occurred_at
FROM consent_events e
WHERE e.id = (SELECT MAX(id) FROM consent_events x
              WHERE x.subject_ref = e.subject_ref AND x.purpose_code = e.purpose_code);

-- ============ Ejercicio de derechos (Hito 3) ============
CREATE TABLE IF NOT EXISTS rights_requests (
    id                       INTEGER PRIMARY KEY,
    public_id                TEXT NOT NULL UNIQUE,
    customer_id              INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    subject_ref              TEXT NOT NULL,
    type                     TEXT NOT NULL CHECK (type IN ('acceso', 'portabilidad', 'rectificacion', 'supresion')),
    status                   TEXT NOT NULL CHECK (status IN ('recibida', 'verificacion', 'evaluacion', 'ejecutada',
                                                            'rechazada', 'cerrada')),
    received_at              TEXT NOT NULL,
    due_at                   TEXT NOT NULL,       -- 30 días corridos (Ley 21.719, art. 11)
    extended                 INTEGER NOT NULL DEFAULT 0,
    verified_at              TEXT,
    evaluated_at             TEXT,
    executed_at              TEXT,
    closed_at                TEXT,
    resolution               TEXT,                -- respuesta fundamentada, sin datos personales
    payload_enc              TEXT,                -- valores pedidos en rectificación, cifrados; se borra al cerrar
    verification_code_hash   TEXT,
    verification_expires_at  TEXT,
    verification_attempts    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rights_request_events (
    id          INTEGER PRIMARY KEY,
    request_id  INTEGER NOT NULL REFERENCES rights_requests(id) ON DELETE CASCADE,
    status      TEXT NOT NULL,
    at          TEXT NOT NULL,
    actor_ref   TEXT NOT NULL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS erasure_tombstones (     -- se reaplican al restaurar respaldos
    customer_public_id  TEXT PRIMARY KEY,
    erased_at           TEXT NOT NULL
);

-- ============ Auditoría (Hito 3) ============
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY,
    event_id       TEXT NOT NULL UNIQUE,
    occurred_at    TEXT NOT NULL,
    actor_type     TEXT NOT NULL,                  -- customer | staff | anonimo | sistema
    actor_ref      TEXT NOT NULL,                  -- public_id, nunca nombre ni correo
    actor_role     TEXT NOT NULL,
    action         TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_ref   TEXT,
    result         TEXT NOT NULL CHECK (result IN ('ok', 'denegado', 'error', 'rechazado')),
    request_id     TEXT,
    ip_prefix      TEXT,                           -- IPv4 truncada a /24
    details        TEXT NOT NULL DEFAULT '{}',     -- JSON saneado
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log es inmutable'); END;

-- Solo se permite borrar registros vencidos (2 años) mediante el proceso de retención.
CREATE TRIGGER IF NOT EXISTS audit_no_early_delete BEFORE DELETE ON audit_log
WHEN OLD.occurred_at >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '-730 days')
BEGIN SELECT RAISE(ABORT, 'audit_log: no se pueden borrar registros dentro del plazo de conservación'); END;

CREATE TABLE IF NOT EXISTS audit_anchor (           -- punto de partida de la cadena tras una purga
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    last_id     INTEGER NOT NULL,
    last_hash   TEXT NOT NULL
);

-- ============ Seguridad e incidentes (Hito 3) ============
CREATE TABLE IF NOT EXISTS security_alerts (
    id           INTEGER PRIMARY KEY,
    created_at   TEXT NOT NULL,
    rule         TEXT NOT NULL,
    level        TEXT NOT NULL CHECK (level IN ('alerta', 'sospechoso', 'incidente')),
    subject_ref  TEXT,
    details      TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'abierta' CHECK (status IN ('abierta', 'en_analisis', 'descartada', 'escalada')),
    incident_id  INTEGER REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY,
    public_id     TEXT NOT NULL UNIQUE,
    opened_at     TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('baja', 'media', 'alta', 'critica')),
    phase         TEXT NOT NULL CHECK (phase IN ('analisis', 'contencion', 'erradicacion', 'recuperacion',
                                                  'notificacion', 'lecciones', 'cerrado')),
    summary       TEXT NOT NULL,
    data_categories TEXT NOT NULL DEFAULT '[]',
    affected_estimate INTEGER,
    requires_agency_report  INTEGER,
    requires_subject_notice INTEGER,
    closed_at     TEXT
);

CREATE TABLE IF NOT EXISTS incident_actions (
    id           INTEGER PRIMARY KEY,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id),
    at           TEXT NOT NULL,
    actor_ref    TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_ref   TEXT,
    result       TEXT NOT NULL,
    evidence_sha256 TEXT
);

CREATE TABLE IF NOT EXISTS system_flags (
    name   TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

INSERT OR IGNORE INTO system_flags (name, value) VALUES ('exports_frozen', '0'), ('read_only', '0');

CREATE INDEX IF NOT EXISTS ix_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit_log(actor_ref, occurred_at);
CREATE INDEX IF NOT EXISTS ix_audit_action ON audit_log(action, occurred_at);
CREATE INDEX IF NOT EXISTS ix_consent_subject ON consent_events(subject_ref, purpose_code);
