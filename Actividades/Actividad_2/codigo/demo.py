"""Demostración reproducible sin exponer llaves ni datos reales."""

from __future__ import annotations

import base64
import os
import secrets

from src.proteccion_datos import (
    FieldProtector,
    IntegrityProtector,
    LoyaltyLedger,
    PasswordProtector,
    PaymentTokenizer,
    SecretKeys,
)


def _configure_ephemeral_demo_keys() -> None:
    os.environ.setdefault(
        "NORTISHOP_DATA_KEY_B64",
        base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    )
    os.environ.setdefault(
        "NORTISHOP_INDEX_KEY_B64",
        base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    )


def main() -> None:
    _configure_ephemeral_demo_keys()
    keys = SecretKeys.from_environment()
    protector = FieldProtector(keys)
    integrity = IntegrityProtector(keys)

    rut = "12.345.678-5"  # dato ficticio para la demostración
    protected_rut = protector.encrypt(rut, context="customer:rut")
    recovered_rut = protector.decrypt(protected_rut, context="customer:rut")

    password_hash = PasswordProtector.hash_password("Demo-Password-2026!")
    valid_password = PasswordProtector.verify_password(
        "Demo-Password-2026!", password_hash
    )
    invalid_password = PasswordProtector.verify_password("incorrecta", password_hash)

    tokenizer = PaymentTokenizer(protector)
    payment = tokenizer.tokenize("4111 1111 1111 1111", brand="VISA TEST")
    merchant_record = payment.merchant_record(protector)

    consent_log: list[dict] = []
    integrity.append(consent_log, {"customer": "c-1", "purpose": "marketing_email",
                                   "action": "grant", "text_version": "2026-10"})
    consent_ok = integrity.verify_chain(consent_log)
    consent_log[0]["record"]["purpose"] = "analytics"
    consent_tamper_detected = not integrity.verify_chain(consent_log)

    ledger = LoyaltyLedger(integrity)
    ledger.add("c-1", 500, "compra")
    ledger.add("c-1", -200, "canje")
    balance = ledger.balance("c-1")

    print("NortiShop - evidencia de controles")
    print(f"RUT almacenado legible: {rut in protected_rut}")
    print(f"RUT recuperado por flujo autorizado: {recovered_rut == rut}")
    print(f"Contraseña correcta validada: {valid_password}")
    print(f"Contraseña incorrecta rechazada: {not invalid_password}")
    print(f"Registro comercio contiene PAN: {'4111111111111111' in str(merchant_record)}")
    print(f"Token generado: {payment.token.startswith('tok_')}")
    print(f"Token legible en registro comercio: {payment.token in str(merchant_record)}")
    print(f"Consentimiento sellado verificado: {consent_ok}")
    print(f"Alteración de consentimiento detectada: {consent_tamper_detected}")
    print(f"Saldo NortiPuntos conciliado (500 - 200): {balance == 300}")
    print("Llaves impresas: False")


if __name__ == "__main__":
    main()

