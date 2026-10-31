"""Aplicación NortiShop: API + interfaz mínima de privacidad."""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask

from .audit import AuditLog
from .consent import ConsentService, seed_purposes
from .crypto import FieldProtector, Keyring, PasswordHasher, Pseudonymizer
from .db import connect_system, init_db
from .logging_utils import configure_logging
from .rights import RightsService
from .security import Detector


class Services:
    """Dependencias compartidas por la aplicación (una instancia por app)."""

    def __init__(self, db_path: str, keyring: Keyring, evidence_dir: Path, scrypt_n: int | None = None,
                 mail_sink: list | None = None) -> None:
        self.db_path = db_path
        self.keyring = keyring
        self.evidence_dir = evidence_dir
        init_db(db_path)
        self.system = connect_system(db_path)
        self.fields = FieldProtector(keyring)
        self.hasher = PasswordHasher(scrypt_n)
        self.pseudo = Pseudonymizer(keyring)
        self.audit = AuditLog(self.system, keyring.audit_key)
        self.detector = Detector(self.system, self.audit)
        self.consent = ConsentService(self.system, keyring.index_key, self.pseudo)
        self.mail: list = mail_sink if mail_sink is not None else []
        seed_purposes(self.system)


def create_app(*, db_path: str, keyring: Keyring | None = None, evidence_dir: str | Path | None = None,
               scrypt_n: int | None = None, testing: bool = False) -> Flask:
    app = Flask(__name__)
    app.config.update(TESTING=testing, JSON_AS_ASCII=False, MAX_CONTENT_LENGTH=64 * 1024)
    app.json.ensure_ascii = False
    app.json.sort_keys = False
    configure_logging(app)
    keyring = keyring or Keyring.from_environment()
    evidence = Path(evidence_dir) if evidence_dir else Path(db_path).with_suffix("").parent / "evidencia_incidentes"
    services = Services(db_path, keyring, evidence, scrypt_n)
    app.extensions["nortishop"] = services

    from .api import bp, register_handlers  # noqa: PLC0415
    app.register_blueprint(bp)
    register_handlers(app)

    def rights_service() -> RightsService:
        from .api import audit_current  # noqa: PLC0415
        return RightsService(services.system, services.fields, services.hasher, services.consent,
                             services.pseudo, services.mail,
                             lambda action, ref, result, details: audit_current(action, "solicitud_derechos",
                                                                                ref, result, details))

    app.extensions["rights_factory"] = rights_service
    logging.getLogger("nortishop").info("Aplicación iniciada (llaves: %r)", keyring)
    return app
