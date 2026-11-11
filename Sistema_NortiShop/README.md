# Sistema NortiShop: Hitos 2 y 3

Implementación académica de la plataforma de comercio electrónico NortiShop con los controles de protección de datos del **Hito 2** (minimización, cifrado, seudonimización/anonimización y RBAC) y del **Hito 3** (consentimiento, ejercicio de derechos, auditoría y respuesta a incidentes). Continúa el trabajo del Hito 1 y reutiliza las técnicas criptográficas de la Actividad 2.

Integrantes: Ariel Van Kilsdonk y Carlos Orellana.

## Ejecución

Requiere Python 3.10 o superior.

```powershell
cd Sistema_NortiShop
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v          # 51 pruebas
python scripts/probar_actividades_6_7.py          # 6 pruebas directas de derechos y auditoría
python scripts/generar_evidencias.py             # regenera la carpeta evidencias/
```

Servidor local con interfaz del centro de privacidad:

```powershell
python -m nortishop.cli new-keys > .env          # llaves locales (no se suben: .env está en .gitignore)
python -m nortishop.cli seed-demo                # personal por rol + clientes sintéticos
python run.py                                    # http://127.0.0.1:5000/privacidad
```

Si `NORTISHOP_DEMO_PASSWORD` no está definida, `seed-demo` genera contraseñas aleatorias y las muestra una sola vez.

## Estructura

| Ruta | Contenido | Hito |
|---|---|---|
| `esquemas/esquema_original.sql` | Esquema inicial sin criterios de privacidad (comparación) | 2 |
| `nortishop/schema.sql` (copia en `esquemas/esquema_redisenado.sql`) | Esquema rediseñado y tablas de cumplimiento | 2 y 3 |
| `nortishop/validation.py` | Listas blancas por operación, campos prohibidos, RUT, teléfono, detección de tarjetas en texto libre | 2 |
| `nortishop/crypto.py` | AES-256-GCM por campo con llaves versionadas, índice ciego, scrypt, seudónimos HMAC | 2 |
| `nortishop/privacy.py` | Seudonimización, enmascaramiento, reporte k-anónimo y dataset anonimizado para desarrollo | 2 |
| `nortishop/rbac.py`, `nortishop/db.py` | Roles, permisos, denegaciones explícitas y *authorizer* SQLite por rol | 2 |
| `nortishop/logging_utils.py` | Registros técnicos con redacción de datos personales | 2 |
| `nortishop/consent.py` | Consentimiento por finalidad, versión, historial sellado y efectos de la revocación | 3 |
| `nortishop/marketing.py` | Entrega de altas y bajas al proveedor con confirmación en la cola | 3 |
| `nortishop/rights.py` | Acceso, portabilidad, rectificación, supresión y oposición a marketing con verificación de identidad y flujo de estados | 3 |
| `nortishop/audit.py` | Auditoría encadenada con HMAC, saneamiento, inmutabilidad y retención | 3 |
| `nortishop/security.py` | Reglas de detección, incidentes, preservación de evidencia y criterio de notificación | 3 |
| `nortishop/maintenance.py`, `nortishop/cli.py` | Rotación de llaves, purga de auditoría y reaplicación de supresiones tras restaurar | 3 |
| `nortishop/api.py`, `nortishop/templates/` | API HTTP y centro de privacidad | 2 y 3 |
| `tests/` | Pruebas de controles permitidos y denegados | 2 y 3 |
| `evidencias/` | Resultados de pruebas y ejemplos JSON de auditoría, exportación y matriz RBAC | 2 y 3 |
| `scripts/probar_actividades_6_7.py` | Pruebas directas de solicitudes, exportación, oposición, supresión y simulación de incidente | 3 |
| `evidencias/resultado_suite_http_actividades_6_7.txt` | Salida de las 51 pruebas HTTP ejecutadas el 11 de noviembre de 2026 | 3 |

## Endpoints principales

| Método y ruta | Permiso |
|---|---|
| `POST /api/auth/registro`, `POST /api/auth/login`, `POST /api/personal/login` | público |
| `GET /api/me`, `POST /api/pedidos`, `POST /api/tickets`, `POST /api/resenas` | cliente |
| `GET/POST /api/me/consentimientos[/historial | /<finalidad>/otorgar | /<finalidad>/revocar]` | cliente |
| `POST /api/derechos/solicitudes`, `.../<id>/verificar`, `GET .../<id>/exportacion` | cliente |
| `GET /api/personal/clientes` (enmascarado) | soporte, administrador, dpo |
| `GET /api/logistica/despachos` (solo ventana activa) | logística |
| `GET /api/marketing/audiencia` (seudónimos con consentimiento) | marketing |
| `GET /api/reportes/ventas` (k-anónimo), `GET /api/finanzas/pagos` (enmascarado) | finanzas |
| `POST /api/dpo/seudonimos/revertir`, `POST /api/dpo/solicitudes/<id>/prorroga` | dpo |
| `GET /api/auditoria`, `GET /api/auditoria/verificar` | auditor, dpo, oficial de seguridad |
| `POST /api/seguridad/incidentes[/<id>/contencion | /recuperacion | /evaluacion-notificacion | /cierre]` | oficial de seguridad |

## Límites conocidos

- SQLite no tiene usuarios de base de datos ni seguridad por fila. Las restricciones de la capa de datos se aplican con un *authorizer* por conexión. En producción se usarían roles de PostgreSQL con `GRANT` por tabla y *Row Level Security*.
- El correo y la pasarela de pago se simulan: el código de verificación llega a un buzón en memoria y el token de pago lo entrega la pasarela.
- La baja del proveedor de mailing queda en `marketing_outbox` con acción `suppress`. `dispatch_pending` confirma cada orden aceptada por el adaptador; el proveedor real debe tratar los reintentos de forma idempotente.
- Las llaves llegan por variables de entorno. En producción las entregaría un KMS o HSM con rotación automática y acceso auditado.
- No hay segundo factor para el personal; está propuesto como mejora en el plan de incidentes.
