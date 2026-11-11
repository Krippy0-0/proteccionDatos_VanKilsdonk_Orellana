# Protección de Datos NortiShop

Entrega académica desarrollada por:

- Ariel Van Kilsdonk
- Carlos Orellana

El repositorio contiene las actividades y los hitos del proyecto de Seguridad y Protección de Datos aplicados al caso de la plataforma de comercio electrónico NortiShop.

## Contenido

- `Actividades/Actividad_1`: mapeo de actores, datos y riesgos CIA.
- `Actividades/Actividad_2`: matriz de cifrado, código fuente, pruebas y evidencia.
- `Actividades/Actividad_3`: Hito 1 (informe en Word y PDF y presentación oral).
- `Actividades/Actividad_6`: ejercicio de derechos en Word y PDF.
- `Actividades/Actividad_7`: trazabilidad y respuesta a incidentes en Word y PDF.
- `Actividades/Hito_2`: informe técnico de minimización, seudonimización/anonimización y RBAC.
- `Actividades/Hito_3`: informe de consentimiento, ejercicio de derechos, auditoría y plan de respuesta a incidentes.
- `Sistema_NortiShop`: código fuente del sistema de los Hitos 2 y 3, con pruebas y evidencias.

## Demostración técnica

El código de la Actividad 2 incluye ejemplos de AES-256-GCM, hashing de contraseñas con scrypt, índices ciegos con HMAC, tokenización de medios de pago y sellos HMAC de integridad para consentimientos y NortiPuntos.

`Sistema_NortiShop` integra esas técnicas en una aplicación Flask + SQLite con RBAC en dos capas, consentimiento por finalidad, solicitudes de derechos con verificación de identidad, auditoría inmutable y procedimientos de contención y recuperación (51 pruebas automatizadas). Instrucciones en `Sistema_NortiShop/README.md`.

Las actividades 6 y 7 también se comprueban sin iniciar el servidor con `python scripts/probar_actividades_6_7.py` desde `Sistema_NortiShop` (6 pruebas directas).

Las llaves se obtienen desde variables de entorno y no se almacenan en el repositorio.
