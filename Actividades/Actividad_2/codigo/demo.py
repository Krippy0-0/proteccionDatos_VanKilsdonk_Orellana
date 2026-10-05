"""Demostración reproducible sin exponer llaves ni datos reales."""

from __future__ import annotations

import base64
import os
import secrets

from src.proteccion_datos import (
    FieldProtector,
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
    protector = FieldProtector(SecretKeys.from_environment())

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
    merchant_record = {
        "payment_token": payment.token,
        "brand": payment.brand,
        "last4": payment.last4,
    }

    print("NortiShop - evidencia de controles")
    print(f"RUT almacenado legible: {rut in protected_rut}")
    print(f"RUT recuperado por flujo autorizado: {recovered_rut == rut}")
    print(f"Contraseña correcta validada: {valid_password}")
    print(f"Contraseña incorrecta rechazada: {not invalid_password}")
    print(f"Registro comercio contiene PAN: {'4111111111111111' in str(merchant_record)}")
    print(f"Token generado: {payment.token.startswith('tok_')}")
    print("Llaves impresas: False")


if __name__ == "__main__":
    main()

