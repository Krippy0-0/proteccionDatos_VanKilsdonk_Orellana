"""Servidor de desarrollo: python run.py (requiere variables de .env cargadas)."""

import os
from pathlib import Path

from nortishop import create_app


def load_dotenv(path: str = ".env") -> None:
    """Carga un .env local sin dependencias extra; no sobrescribe variables existentes."""
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


if __name__ == "__main__":
    load_dotenv()
    db = os.environ.get("NORTISHOP_DB", "instance/nortishop.db")
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    app = create_app(db_path=db)
    # Un hilo: la conexión de sistema de SQLite se comparte entre solicitudes.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=False)
