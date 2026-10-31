-- NortiShop: ESQUEMA ORIGINAL (versión inicial, antes del Hito 2).
-- Reconstruido a partir del inventario del Hito 1 tal como quedaría si el
-- sistema se construyera sin criterios de privacidad. Se conserva solo como
-- punto de comparación: NO se usa en la aplicación.
-- Problemas marcados con  -- [!]

CREATE TABLE usuarios (
    id                   INTEGER PRIMARY KEY,
    nombre               TEXT NOT NULL,
    apellido_paterno     TEXT NOT NULL,
    apellido_materno     TEXT,
    rut                  TEXT NOT NULL UNIQUE,       -- [!] obligatorio para todos y en texto claro
    email                TEXT NOT NULL UNIQUE,       -- [!] texto claro
    telefono             TEXT NOT NULL,              -- [!] obligatorio
    telefono_secundario  TEXT,                       -- [!] innecesario
    fecha_nacimiento     TEXT NOT NULL,              -- [!] solo se necesita saber si es mayor de edad
    genero               TEXT,                       -- [!] innecesario para vender
    password             TEXT NOT NULL,              -- [!] MD5 sin sal
    rol                  TEXT NOT NULL DEFAULT 'cliente', -- [!] clientes y personal en la misma tabla
    acepta_marketing     INTEGER NOT NULL DEFAULT 1, -- [!] premarcado, sin fecha ni versión
    ultima_ip            TEXT,                       -- [!] IP completa sin plazo
    fecha_registro       TEXT NOT NULL
);

CREATE TABLE direcciones (
    id          INTEGER PRIMARY KEY,
    usuario_id  INTEGER REFERENCES usuarios(id),
    calle       TEXT NOT NULL,                       -- [!] texto claro
    numero      TEXT NOT NULL,
    depto       TEXT,
    comuna      TEXT NOT NULL,
    region      TEXT NOT NULL,
    latitud     REAL,                                -- [!] geolocalización precisa del domicilio
    longitud    REAL,
    referencia  TEXT                                 -- [!] texto libre ("casa de mi mamá…")
);

CREATE TABLE tarjetas (
    id               INTEGER PRIMARY KEY,
    usuario_id       INTEGER REFERENCES usuarios(id),
    numero_tarjeta   TEXT NOT NULL,                  -- [!] PAN completo en la base del comercio
    vencimiento      TEXT NOT NULL,                  -- [!]
    cvv              TEXT,                           -- [!] prohibido almacenar
    titular          TEXT NOT NULL
);

CREATE TABLE pedidos (
    id                 INTEGER PRIMARY KEY,
    usuario_id         INTEGER REFERENCES usuarios(id),
    estado             TEXT NOT NULL,
    nombre_destinatario TEXT,                        -- [!] texto claro, sin plazo
    telefono_destinatario TEXT,
    direccion_despacho TEXT,                         -- [!] copia en claro
    rut_facturacion    TEXT,                         -- [!] se pide también para boleta
    total              INTEGER NOT NULL,
    tarjeta_id         INTEGER REFERENCES tarjetas(id),
    codigo_autorizacion TEXT,                        -- [!] texto claro
    fecha              TEXT NOT NULL
);

CREATE TABLE detalle_pedido (
    id         INTEGER PRIMARY KEY,
    pedido_id  INTEGER REFERENCES pedidos(id),
    sku        TEXT NOT NULL,
    cantidad   INTEGER NOT NULL,
    precio     INTEGER NOT NULL
);

CREATE TABLE despachos (
    id               INTEGER PRIMARY KEY,
    pedido_id        INTEGER REFERENCES pedidos(id),
    transportista    TEXT,
    seguimiento      TEXT,
    gps_entrega_lat  REAL,                           -- [!] coordenada exacta de entrega, sin plazo
    gps_entrega_lon  REAL,
    foto_entrega     BLOB,                           -- [!] puede capturar personas y domicilios
    firma_receptor   BLOB                            -- [!] dato innecesario
);

CREATE TABLE nortipuntos (
    usuario_id  INTEGER PRIMARY KEY REFERENCES usuarios(id),
    saldo       INTEGER NOT NULL                     -- [!] saldo editable, sin historial ni integridad
);

CREATE TABLE resenas (
    id          INTEGER PRIMARY KEY,
    usuario_id  INTEGER REFERENCES usuarios(id),
    sku         TEXT,
    nombre_publico TEXT,                             -- [!] nombre y apellido reales publicados
    texto       TEXT,
    calificacion INTEGER
);

CREATE TABLE tickets_soporte (
    id          INTEGER PRIMARY KEY,
    usuario_id  INTEGER REFERENCES usuarios(id),
    asunto      TEXT,
    mensaje     TEXT,                                -- [!] texto libre en claro (puede incluir tarjeta)
    adjunto     BLOB                                 -- [!] copias de cédula, comprobantes
);

CREATE TABLE eventos_navegacion (
    id          INTEGER PRIMARY KEY,
    usuario_id  INTEGER REFERENCES usuarios(id),     -- [!] identificador directo
    email       TEXT,                                -- [!] duplicado
    ip          TEXT,                                -- [!]
    user_agent  TEXT,
    url         TEXT,
    fecha_hora  TEXT                                 -- [!] sin consentimiento ni plazo
);

CREATE TABLE logs (
    id        INTEGER PRIMARY KEY,
    fecha     TEXT,
    usuario   TEXT,                                  -- [!] correo del usuario
    accion    TEXT,
    detalle   TEXT                                   -- [!] request completo (incluía contraseñas)
);
