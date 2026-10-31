"""Comandos de operación: ``python -m nortishop.cli <comando>``.

Las llaves se leen de variables de entorno (en producción, inyectadas por el
gestor de secretos o KMS). Ningún comando imprime material criptográfico.

  init          crea la base de datos y las finalidades de consentimiento
  seed-demo     crea cuentas del personal y clientes sintéticos
  verify-audit  verifica la cadena del registro de auditoría
  purge-audit   elimina registros de auditoría vencidos (2 años) dejando un ancla
  rotate-keys   recifra los campos con la última versión de NORTISHOP_DATA_KEYS
  reapply-erasures  reaplica supresiones tras restaurar un respaldo
  new-keys      imprime un .env de ejemplo con llaves nuevas para desarrollo local
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path

from .crypto import new_key_b64


def _app(db: str):
    from . import create_app  # noqa: PLC0415
    return create_app(db_path=db)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nortishop")
    parser.add_argument("comando", choices=["init", "seed-demo", "verify-audit", "purge-audit", "rotate-keys",
                                            "reapply-erasures", "new-keys"])
    parser.add_argument("--db", default=os.environ.get("NORTISHOP_DB", "instance/nortishop.db"))
    args = parser.parse_args(argv)
    env_file = Path(".env")
    if env_file.exists():  # carga local de desarrollo; no sobrescribe variables existentes
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())

    if args.comando == "new-keys":
        print("# Solo para desarrollo local. No subir este archivo al repositorio.")
        print(f"NORTISHOP_DATA_KEYS=v1:{new_key_b64()}")
        for name in ("INDEX", "AUDIT", "PSEUDO"):
            print(f"NORTISHOP_{name}_KEY_B64={new_key_b64()}")
        return 0

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    app = _app(args.db)
    s = app.extensions["nortishop"]
    if args.comando == "init":
        print(f"Base inicializada en {args.db}")
    elif args.comando == "seed-demo":
        from .seed import seed_staff, synthetic_person  # noqa: PLC0415
        password = os.environ.get("NORTISHOP_DEMO_PASSWORD")
        creds = seed_staff(s, password)
        client = app.test_client()
        rng = random.Random(2026)
        for _ in range(12):
            p = synthetic_person(rng)
            client.post("/api/auth/registro", json={"nombre_completo": p["nombre"], "email": p["email"],
                                                    "password": password or "Cliente-Demo-2026!",
                                                    "telefono": p["telefono"], "declaro_mayor_de_edad": True})
        print(f"Personal creado: {', '.join(creds) or 'ya existía'}")
        if creds and not password:
            print("Contraseñas generadas (se muestran una sola vez, guárdelas en un gestor):")
            for user, pw in creds.items():
                print(f"  {user}: {pw}")
    elif args.comando == "verify-audit":
        print(json.dumps(s.audit.verify(), ensure_ascii=False))
    elif args.comando == "purge-audit":
        print(f"Registros purgados: {s.audit.purge_expired()}")
    elif args.comando == "rotate-keys":
        from .maintenance import rotate_keys  # noqa: PLC0415
        counts = rotate_keys(s.system, s.fields)
        s.audit.record(action="sistema.rotacion_llaves", actor_type="sistema", actor_ref="cli",
                       actor_role="sistema", resource_type="llaves", resource_ref=s.keyring.active_version,
                       details={"filas": counts})
        print(json.dumps({"version_activa": s.keyring.active_version, "filas_recifradas": counts}, ensure_ascii=False))
    elif args.comando == "reapply-erasures":
        from .maintenance import reapply_erasures  # noqa: PLC0415
        print(json.dumps({"reaplicadas": reapply_erasures(s.system, s.consent, s.pseudo)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
