# Protección de campos críticos de NortiShop

Este ejemplo académico aplica controles coherentes con la clase de cifrado:

- AES-256-GCM para RUT, correo, teléfono y direcciones que deben recuperarse.
- HMAC-SHA-256 como índice ciego cuando se necesita buscar un correo sin guardarlo legible.
- scrypt con sal aleatoria (N=2^17, r=8, p=1, mínimo recomendado por OWASP) para validar contraseñas sin posibilidad de recuperación.
- tokenización para que la base del comercio guarde solo un token (cifrado en reposo), la marca y los últimos cuatro dígitos del medio de pago.
- HMAC-SHA-256 encadenado para sellar eventos de consentimiento y movimientos de NortiPuntos: modificar, borrar o reordenar un evento rompe la cadena.

## Ejecución

El entorno requiere Python 3.10 o superior y `cryptography>=42`.

```powershell
python -m pip install -r requirements.txt
python demo.py
python -m unittest discover -s tests -v
```

`demo.py` crea llaves efímeras solo para la demostración y nunca las imprime. En producción, las llaves deben venir de un gestor de secretos o KMS y exponerse al proceso mediante las variables `NORTISHOP_DATA_KEY_B64` y `NORTISHOP_INDEX_KEY_B64`. Cada variable contiene 32 bytes aleatorios codificados en Base64.

## Pruebas

Las 10 pruebas cubren: round trip AES-GCM con nonce aleatorio; contexto que impide sustituir ciphertexts; índice ciego normalizado; scrypt; tokenización sin PAN en el comercio; teléfono y direcciones; manipulación del código de autorización (falla el tag); token cifrado en reposo; cadena HMAC de consentimientos; integridad y conciliación de NortiPuntos. El resultado está en `evidencia_funcionamiento.txt`.

## Recuperación y validación

Los campos cifrados se recuperan con `FieldProtector.decrypt` solo en un flujo autorizado y usando el mismo contexto asociado al campo. AES-GCM verifica autenticidad: un cambio en el texto cifrado o en el contexto provoca un error. La contraseña no se recupera; `verify_password` deriva nuevamente scrypt con la sal guardada y compara en tiempo constante. La integridad de consentimientos y NortiPuntos se valida recalculando la cadena HMAC con `IntegrityProtector.verify_chain`; el saldo de NortiPuntos se deriva de los movimientos y no se acepta si la cadena no verifica. La tokenización resuelve el token únicamente dentro de la bóveda de pago; la base principal de NortiShop no recibe el PAN.

## Gestión de secretos

El repositorio no contiene llaves reales. `.env`, archivos de bóveda y material de llaves están excluidos por `.gitignore`. `.env.example` documenta nombres y formatos con marcadores sin valor. La rotación se implementaría manteniendo una versión de llave en el prefijo del texto cifrado y recifrando por lotes bajo control de acceso y auditoría.

