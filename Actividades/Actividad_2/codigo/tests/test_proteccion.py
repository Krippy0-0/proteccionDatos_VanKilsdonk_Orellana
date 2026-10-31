import base64
import os
import secrets
import unittest

from cryptography.exceptions import InvalidTag

from src.proteccion_datos import (
    FieldProtector,
    IntegrityProtector,
    LoyaltyLedger,
    PasswordProtector,
    PaymentTokenizer,
    SecretKeys,
)


class ProtectionTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["NORTISHOP_DATA_KEY_B64"] = base64.b64encode(
            secrets.token_bytes(32)
        ).decode("ascii")
        os.environ["NORTISHOP_INDEX_KEY_B64"] = base64.b64encode(
            secrets.token_bytes(32)
        ).decode("ascii")
        self.keys = SecretKeys.from_environment()
        self.protector = FieldProtector(self.keys)
        self.integrity = IntegrityProtector(self.keys)

    def test_aes_gcm_round_trip_and_random_nonce(self) -> None:
        one = self.protector.encrypt("cliente@example.com", context="customer:email")
        two = self.protector.encrypt("cliente@example.com", context="customer:email")
        self.assertNotEqual(one, two)
        self.assertEqual(
            self.protector.decrypt(one, context="customer:email"),
            "cliente@example.com",
        )

    def test_context_prevents_ciphertext_substitution(self) -> None:
        encrypted = self.protector.encrypt("12.345.678-5", context="customer:rut")
        with self.assertRaises(InvalidTag):
            self.protector.decrypt(encrypted, context="customer:email")

    def test_blind_index_is_deterministic_after_normalization(self) -> None:
        a = self.protector.blind_index(
            " Cliente@Example.com ", context="customer:email-index"
        )
        b = self.protector.blind_index(
            "cliente@example.com", context="customer:email-index"
        )
        self.assertEqual(a, b)

    def test_password_validation(self) -> None:
        encoded = PasswordProtector.hash_password("Secreta-2026!")
        self.assertTrue(PasswordProtector.verify_password("Secreta-2026!", encoded))
        self.assertFalse(PasswordProtector.verify_password("otra", encoded))

    def test_tokenization_keeps_pan_out_of_merchant_record(self) -> None:
        tokenizer = PaymentTokenizer(self.protector)
        reference = tokenizer.tokenize("4111 1111 1111 1111", brand="VISA TEST")
        merchant_record = reference.__dict__
        self.assertNotIn("4111111111111111", str(merchant_record))
        self.assertEqual(reference.last4, "1111")
        self.assertEqual(
            tokenizer.detokenize_for_authorized_processor(reference.token),
            "4111111111111111",
        )

    def test_phone_and_billing_address_round_trip(self) -> None:
        for value, context in [
            ("+56 9 1234 5678", "customer:phone"),
            ("Av. Siempre Viva 742, Antofagasta", "order:billing-address"),
            ("Pasaje Uno 123, Calama", "order:shipping-address"),
        ]:
            protected = self.protector.encrypt(value, context=context)
            self.assertNotIn(value, protected)
            self.assertEqual(self.protector.decrypt(protected, context=context), value)

    def test_tampered_authorization_code_fails_authentication(self) -> None:
        protected = self.protector.encrypt("AUTH-839201", context="payment:authorization")
        version, body = protected.split(":", 1)
        raw = bytearray(base64.urlsafe_b64decode(body))
        raw[-1] ^= 0x01
        tampered = version + ":" + base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(InvalidTag):
            self.protector.decrypt(tampered, context="payment:authorization")

    def test_payment_token_is_encrypted_at_rest(self) -> None:
        tokenizer = PaymentTokenizer(self.protector)
        reference = tokenizer.tokenize("4111 1111 1111 1111", brand="VISA TEST")
        record = reference.merchant_record(self.protector)
        self.assertNotIn(reference.token, str(record))
        self.assertNotIn("4111111111111111", str(record))
        self.assertEqual(
            self.protector.decrypt(record["payment_token_enc"], context="payment:token"),
            reference.token,
        )

    def test_consent_log_hmac_detects_changes(self) -> None:
        chain: list[dict] = []
        self.integrity.append(chain, {"customer": "c-1", "purpose": "marketing_email",
                                      "action": "grant", "text_version": "2026-10", "channel": "web"})
        self.integrity.append(chain, {"customer": "c-1", "purpose": "marketing_email",
                                      "action": "revoke", "text_version": "2026-10", "channel": "web"})
        self.assertTrue(self.integrity.verify_chain(chain))
        chain[1]["record"]["action"] = "grant"  # intento de ocultar la revocación
        self.assertFalse(self.integrity.verify_chain(chain))
        chain[1]["record"]["action"] = "revoke"
        del chain[0]  # eliminar un evento también rompe la cadena
        self.assertFalse(self.integrity.verify_chain(chain))

    def test_loyalty_ledger_integrity_and_reconciliation(self) -> None:
        ledger = LoyaltyLedger(self.integrity)
        ledger.add("c-1", 500, "compra #1001")
        ledger.add("c-1", -200, "canje")
        ledger.add("c-2", 100, "compra #1002")
        self.assertEqual(ledger.balance("c-1"), 300)
        with self.assertRaises(ValueError):
            ledger.add("c-1", -1000, "canje sin saldo")
        ledger.entries[0]["record"]["points"] = 50000  # manipulación directa
        with self.assertRaises(ValueError):
            ledger.balance("c-1")


if __name__ == "__main__":
    unittest.main()

