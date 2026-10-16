"""Pruebas unitarias del laboratorio ChaCha20.

Autor: Volodymyr Osebchuk
"""

import os
import sys
import unittest

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import chacha20_lab as lab  # noqa: E402


class TestParte1(unittest.TestCase):
    def test_longitudes(self):
        self.assertEqual(len(lab.TEXTO_PLANO.encode("utf-8")), 44)
        self.assertEqual(len(lab.CLAVE), 32)
        self.assertEqual(len(lab.NONCE), 8)

    def test_cifrado_esperado(self):
        cifrado = lab.cifrar(lab.TEXTO_PLANO)
        self.assertEqual(cifrado.hex(), lab.CIFRADO_ESPERADO_HEX)
        self.assertEqual(len(cifrado), 44)

    def test_reversible(self):
        self.assertEqual(lab.descifrar(lab.cifrar("Hola ñandú")), "Hola ñandú")


class TestNonce(unittest.TestCase):
    def test_tamanos(self):
        res = lab.analizar_tamanos_nonce()
        for tam in (8, 12, 24):
            self.assertTrue(res[tam]["aceptado"])
        self.assertFalse(res[16]["aceptado"])
        self.assertIn("Nonce must be", res[16]["error"])

    def test_cifrados_distintos(self):
        res = lab.analizar_tamanos_nonce()
        self.assertEqual(res[8]["cifrado_hex"], lab.CIFRADO_ESPERADO_HEX)
        self.assertNotEqual(res[12]["cifrado_hex"], res[8]["cifrado_hex"])
        self.assertNotEqual(res[24]["cifrado_hex"], res[8]["cifrado_hex"])
        self.assertNotEqual(res[12]["cifrado_hex"], res[24]["cifrado_hex"])

    def test_clave_invalida(self):
        with self.assertRaises(ValueError):
            ChaCha20.new(key=b"\x00" * 64, nonce=lab.NONCE)

    def test_reutilizacion(self):
        r = lab.demostrar_reutilizacion_nonce()
        self.assertEqual(r["c1_xor_c2"], r["p1_xor_p2"])
        self.assertTrue(r["keystream_se_cancela"])
        self.assertEqual(r["p2_recuperado"], "Transferir 9999 euros a la cuenta ES99")


class TestPoly1305(unittest.TestCase):
    def test_alteracion(self):
        r = lab.comparar_chacha20_poly1305()
        self.assertNotEqual(r["chacha20_descifrado_alterado"], "Pago de 100 euros a Ana")
        self.assertEqual(r["poly1305_legitimo"], "Pago de 100 euros a Ana")
        self.assertEqual(r["tam_etiqueta"], 16)
        self.assertIsNotNone(r["poly1305_error"])

    def test_valueerror_directo(self):
        nonce = b"\x01" * 12
        c, tag = ChaCha20_Poly1305.new(key=lab.CLAVE, nonce=nonce).encrypt_and_digest(b"datos")
        malo = bytes([c[0] ^ 1]) + c[1:]
        with self.assertRaises(ValueError):
            ChaCha20_Poly1305.new(key=lab.CLAVE, nonce=nonce).decrypt_and_verify(malo, tag)


class TestParte2yExtra(unittest.TestCase):
    def test_parte2(self):
        self.assertEqual(len(lab.CIFRADO_PARTE2), 51)
        self.assertEqual(
            lab.descifrar(lab.CIFRADO_PARTE2),
            "Este es un mensaje secreto que quiero que descifres",
        )

    def test_extra(self):
        self.assertEqual(len(lab.CIFRADO_EXTRA), 42)
        self.assertEqual(
            lab.sincronizar_keystream().decode("utf-8"),
            "saje ha sufrido un error en la transmision",
        )

    def test_extra_sin_seek_falla(self):
        self.assertNotEqual(
            lab.crear_cifrador().decrypt(lab.CIFRADO_EXTRA)[:10], b"saje ha su"
        )

    def test_extra_mensaje_completo(self):
        # El prefijo perdido es desconocido: cualquier prefijo de 8 bytes
        # produce el mismo cifrado a partir de la posición 8 del keystream.
        recuperado = lab.sincronizar_keystream().decode("utf-8")
        completo = lab.cifrar("X" * lab.BYTES_PERDIDOS + recuperado)
        self.assertEqual(completo[lab.BYTES_PERDIDOS:], lab.CIFRADO_EXTRA)


if __name__ == "__main__":
    unittest.main()
