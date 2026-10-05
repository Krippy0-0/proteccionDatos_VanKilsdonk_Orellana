import base64
import os
import secrets
import unittest

from src.proteccion_datos import (
    FieldProtector,
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
        self.protector = FieldProtector(SecretKeys.from_environment())

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
        with self.assertRaises(Exception):
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


if __name__ == "__main__":
    unittest.main()

