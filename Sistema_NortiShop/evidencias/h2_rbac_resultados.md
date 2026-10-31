# Resultado real de la matriz RBAC

Código HTTP obtenido por cada rol (200 = permitido, 401 = sin sesión, 403 = denegado).

| Endpoint | sin sesión | soporte1 | logistica1 | marketing1 | finanzas1 | admin1 | dpo1 | seguridad1 | auditor1 | cliente |
|---|---|---|---|---|---|---|---|---|---|---|
| `/api/me` | 401 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 403 | 200 |
| `/api/personal/clientes` | 401 | 200 | 403 | 403 | 403 | 200 | 200 | 403 | 403 | 403 |
| `/api/logistica/despachos` | 401 | 403 | 200 | 403 | 403 | 403 | 403 | 403 | 403 | 403 |
| `/api/marketing/audiencia` | 401 | 403 | 403 | 200 | 403 | 403 | 403 | 403 | 403 | 403 |
| `/api/finanzas/pagos` | 401 | 403 | 403 | 403 | 200 | 403 | 403 | 403 | 403 | 403 |
| `/api/reportes/ventas` | 401 | 403 | 403 | 403 | 200 | 403 | 403 | 403 | 403 | 403 |
| `/api/dpo/solicitudes` | 401 | 403 | 403 | 403 | 403 | 403 | 200 | 403 | 403 | 403 |
| `/api/auditoria` | 401 | 403 | 403 | 403 | 403 | 403 | 200 | 200 | 200 | 403 |
| `/api/seguridad/alertas` | 401 | 403 | 403 | 403 | 403 | 403 | 403 | 200 | 403 | 403 |

# Restricciones en la capa de base de datos (authorizer SQLite)

| Rol | Consulta | Resultado |
|---|---|---|
| soporte | `SELECT password_hash FROM credentials` | RECHAZADO por el motor: access to credentials.password_hash is prohibited |
| soporte | `SELECT * FROM pseudonym_vault` | RECHAZADO por el motor: access to pseudonym_vault.pseudonym is prohibited |
| marketing | `SELECT full_name_enc FROM customers` | RECHAZADO por el motor: access to customers.full_name_enc is prohibited |
| logistica | `SELECT email_enc FROM customers` | RECHAZADO por el motor: access to customers.email_enc is prohibited |
| finanzas | `SELECT gateway_token_enc FROM saved_payment_methods` | RECHAZADO por el motor: access to saved_payment_methods.gateway_token_enc is prohibited |
| administrador | `SELECT * FROM audit_log` | RECHAZADO por el motor: access to audit_log.id is prohibited |
| auditor | `DELETE FROM audit_log` | RECHAZADO por el motor: not authorized |
| cliente | `UPDATE consent_events SET action='otorgado'` | RECHAZADO por el motor: not authorized |
