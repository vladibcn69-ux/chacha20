"""Laboratorio PE 89.1 - Fundamentos de ChaCha20 (MF0489).

Cifrado y descifrado con ChaCha20 usando PyCryptodome, análisis del nonce,
reutilización de nonce, comparación con ChaCha20-Poly1305 y sincronización
del keystream mediante ``seek()``.

Autor: Volodymyr Osebchuk
"""

from __future__ import annotations

import sys

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# --------------------------------------------------------------------------
# Constantes del laboratorio
# --------------------------------------------------------------------------
TEXTO_PLANO = "Este es un mensaje secreto que quiero cifrar"

# Clave de 32 bytes = 256 bits (el único tamaño que acepta ChaCha20).
CLAVE = bytes.fromhex(
    "7ae87e22ca79571467182b1c2bf98006509e6a8838b447dfe4c5302c8d598019"
)
# Nonce de 8 bytes = 64 bits (ChaCha20 original de Bernstein).
NONCE = bytes.fromhex("d67f36c7e8692aa4")

# Resultado esperado de la Parte 1 (verificado con PyCryptodome).
CIFRADO_ESPERADO_HEX = (
    "4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516e"
    "ad33ec2e08929f92b8778a0d"
)

# Parte 2: 51 bytes. En el texto del enunciado las barras están duplicadas
# (\\x83), así que el literal no se puede copiar tal cual. Se define desde hex
# (más fiable al copiar bytes no imprimibles) y se contrasta con el literal.
CIFRADO_PARTE2_HEX = (
    "4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516e"
    "ad33ec2e08928d8ebb258f1aa6c93d150f35aa"
)
CIFRADO_PARTE2 = bytes.fromhex(CIFRADO_PARTE2_HEX)
CIFRADO_PARTE2_LITERAL = (
    b"Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb"
    b"\x88\x18\x60W\xc3yQn\xad3\xec.\x08\x92\x8d\x8e\xbb%\x8f\x1a\xa6\xc9=\x15"
    b"\x0f5\xaa"
)

# EXTRA: 42 bytes (faltan los 8 primeros bytes del mensaje original).
# Se define desde hex (más fiable al copiar bytes no imprimibles) y se
# contrasta con el literal mediante assert.
CIFRADO_EXTRA_HEX = (
    "ade29a5b43caa9ad6ef9aa2913c2589e89196043c46e1e6df83fe77c0bd3dc8f"
    "ac64850cb8c3271a123e"
)
CIFRADO_EXTRA = bytes.fromhex(CIFRADO_EXTRA_HEX)
CIFRADO_EXTRA_LITERAL = (
    b"\xad\xe2\x9a[C\xca\xa9\xadn\xf9\xaa)\x13\xc2X\x9e\x89\x19\x60C\xc4n"
    b"\x1em\xf8?\xe7|\x0b\xd3\xdc\x8f\xacd\x85\x0c\xb8\xc3'\x1a\x12>"
)
BYTES_PERDIDOS = 8

assert len(CLAVE) == 32, "La clave debe tener 32 bytes"
assert len(NONCE) == 8, "El nonce debe tener 8 bytes"
assert len(CIFRADO_PARTE2) == 51 and CIFRADO_PARTE2 == CIFRADO_PARTE2_LITERAL
assert len(CIFRADO_EXTRA) == 42 and CIFRADO_EXTRA == CIFRADO_EXTRA_LITERAL

TAMANOS_NONCE_PRUEBA = (8, 12, 16, 24)


# --------------------------------------------------------------------------
# Funciones
# --------------------------------------------------------------------------
def crear_cifrador(clave: bytes = CLAVE, nonce: bytes = NONCE) -> ChaCha20.ChaCha20Cipher:
    """Crea un objeto ChaCha20 nuevo (keystream en la posición 0)."""
    return ChaCha20.new(key=clave, nonce=nonce)


def cifrar(texto: str, clave: bytes = CLAVE, nonce: bytes = NONCE) -> bytes:
    """Cifra un texto (UTF-8) con ChaCha20 y devuelve el texto cifrado."""
    return crear_cifrador(clave, nonce).encrypt(texto.encode("utf-8"))


def descifrar(cifrado: bytes, clave: bytes = CLAVE, nonce: bytes = NONCE) -> str:
    """Descifra con ChaCha20 y devuelve el texto plano decodificado (UTF-8)."""
    return crear_cifrador(clave, nonce).decrypt(cifrado).decode("utf-8")


def analizar_tamanos_nonce(
    texto: str = TEXTO_PLANO, clave: bytes = CLAVE
) -> dict[int, dict[str, object]]:
    """Prueba nonces de 8, 12, 16 y 24 bytes.

    Para cada tamaño devuelve ``{"aceptado": bool, "cifrado_hex": str | None,
    "error": str | None}``. Los nonces de 12, 16 y 24 bytes se obtienen
    rellenando con ceros el nonce del laboratorio, solo para la comparación.
    """
    resultados: dict[int, dict[str, object]] = {}
    for tam in TAMANOS_NONCE_PRUEBA:
        nonce = NONCE.ljust(tam, b"\x00")
        try:
            cifrado = ChaCha20.new(key=clave, nonce=nonce).encrypt(texto.encode("utf-8"))
            resultados[tam] = {"aceptado": True, "cifrado_hex": cifrado.hex(), "error": None}
        except ValueError as exc:
            resultados[tam] = {"aceptado": False, "cifrado_hex": None, "error": str(exc)}
    return resultados


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte de dos secuencias de igual longitud."""
    if len(a) != len(b):
        raise ValueError("Las secuencias deben tener la misma longitud")
    return bytes(x ^ y for x, y in zip(a, b))


def demostrar_reutilizacion_nonce(
    p1: str = "Transferir 1000 euros a la cuenta ES11",
    p2: str = "Transferir 9999 euros a la cuenta ES99",
    clave: bytes = CLAVE,
    nonce: bytes = NONCE,
) -> dict[str, object]:
    """Demuestra que con clave y nonce repetidos C1 xor C2 == P1 xor P2.

    Solo con cadenas didácticas. Si se conoce P1, se recupera P2 sin la clave.
    """
    b1, b2 = p1.encode("utf-8"), p2.encode("utf-8")
    c1 = crear_cifrador(clave, nonce).encrypt(b1)
    c2 = crear_cifrador(clave, nonce).encrypt(b2)
    c1_xor_c2 = xor_bytes(c1, c2)
    p1_xor_p2 = xor_bytes(b1, b2)
    p2_recuperado = xor_bytes(c1_xor_c2, b1)  # conociendo P1
    return {
        "c1": c1,
        "c2": c2,
        "c1_xor_c2": c1_xor_c2,
        "p1_xor_p2": p1_xor_p2,
        "keystream_se_cancela": c1_xor_c2 == p1_xor_p2,
        "p2_recuperado": p2_recuperado.decode("utf-8"),
    }


def comparar_chacha20_poly1305(
    texto: str = "Pago de 100 euros a Ana", clave: bytes = CLAVE
) -> dict[str, object]:
    """Compara la maleabilidad de ChaCha20 con la integridad de ChaCha20-Poly1305.

    Se invierte un bit del texto cifrado: ChaCha20 lo descifra sin error (con
    el texto alterado) y ChaCha20-Poly1305 lanza ``ValueError`` al verificar.
    """
    datos = texto.encode("utf-8")

    # ChaCha20 simple: sin autenticación.
    cifrado = ChaCha20.new(key=clave, nonce=NONCE).encrypt(datos)
    alterado = bytearray(cifrado)
    alterado[9] ^= 0x01  # cambia un bit de forma silenciosa
    descifrado_alterado = ChaCha20.new(key=clave, nonce=NONCE).decrypt(bytes(alterado))

    # ChaCha20-Poly1305: nonce de 12 bytes y etiqueta de 16 bytes.
    nonce12 = get_random_bytes(12)
    cifrador = ChaCha20_Poly1305.new(key=clave, nonce=nonce12)
    cifrado_aead, etiqueta = cifrador.encrypt_and_digest(datos)
    legitimo = ChaCha20_Poly1305.new(key=clave, nonce=nonce12).decrypt_and_verify(
        cifrado_aead, etiqueta
    )
    aead_alterado = bytearray(cifrado_aead)
    aead_alterado[9] ^= 0x01
    try:
        ChaCha20_Poly1305.new(key=clave, nonce=nonce12).decrypt_and_verify(
            bytes(aead_alterado), etiqueta
        )
        error_aead = None
    except ValueError as exc:
        error_aead = str(exc)

    return {
        "chacha20_descifrado_alterado": descifrado_alterado.decode("utf-8", errors="replace"),
        "poly1305_legitimo": legitimo.decode("utf-8"),
        "tam_etiqueta": len(etiqueta),
        "tam_nonce_poly1305": len(nonce12),
        "poly1305_error": error_aead,
    }


def sincronizar_keystream(
    cifrado: bytes = CIFRADO_EXTRA,
    bytes_perdidos: int = BYTES_PERDIDOS,
    clave: bytes = CLAVE,
    nonce: bytes = NONCE,
) -> bytes:
    """Descifra un mensaje al que le faltan los primeros ``bytes_perdidos``.

    ``seek(n)`` avanza el keystream n bytes, de modo que el primer byte
    recibido se descifra con el byte n del keystream. Devuelve los bytes
    planos (sin decodificar, por si el corte parte un carácter UTF-8).
    """
    cifrador = crear_cifrador(clave, nonce)
    cifrador.seek(bytes_perdidos)
    return cifrador.decrypt(cifrado)


# --------------------------------------------------------------------------
# Programa principal
# --------------------------------------------------------------------------
def _titulo(texto: str) -> None:
    print("\n" + "=" * 70)
    print(texto)
    print("=" * 70)


def main() -> None:
    """Ejecuta secuencialmente la Parte 1, la Parte 2 y el EXTRA."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    _titulo("PARTE 1 - Cifrado con ChaCha20")
    datos = TEXTO_PLANO.encode("utf-8")
    cifrado = cifrar(TEXTO_PLANO)
    print(f"Texto plano  : {TEXTO_PLANO!r} ({len(datos)} bytes)")
    print(f"Clave        : {CLAVE.hex()} ({len(CLAVE)} bytes = {len(CLAVE) * 8} bits)")
    print(f"Nonce        : {NONCE.hex()} ({len(NONCE)} bytes = {len(NONCE) * 8} bits)")
    print(f"Cifrado bytes: {cifrado!r}")
    print(f"Cifrado hex  : {cifrado.hex()} ({len(cifrado)} bytes)")
    print(f"Coincide con el valor esperado: {cifrado.hex() == CIFRADO_ESPERADO_HEX}")

    _titulo("Preguntas 2 y 3 - Tamaños de nonce")
    print(f"Tamaño del nonce usado: {len(NONCE)} bytes ({len(NONCE) * 8} bits)")
    for tam, res in analizar_tamanos_nonce().items():
        if res["aceptado"]:
            print(f"  nonce {tam:>2} bytes: aceptado  -> {res['cifrado_hex']}")
        else:
            print(f"  nonce {tam:>2} bytes: RECHAZADO -> ValueError: {res['error']}")

    _titulo("Pregunta 5 - Reutilización de clave y nonce")
    r = demostrar_reutilizacion_nonce()
    print(f"C1 xor C2 : {r['c1_xor_c2'].hex()}")
    print(f"P1 xor P2 : {r['p1_xor_p2'].hex()}")
    print(f"El keystream se cancela (C1^C2 == P1^P2): {r['keystream_se_cancela']}")
    print(f"P2 recuperado conociendo P1: {r['p2_recuperado']!r}")

    _titulo("Pregunta 6 - ChaCha20 vs ChaCha20-Poly1305")
    c = comparar_chacha20_poly1305()
    print(f"ChaCha20 con un bit alterado descifra SIN error: {c['chacha20_descifrado_alterado']!r}")
    print(
        f"Poly1305 legítimo: {c['poly1305_legitimo']!r} "
        f"(nonce {c['tam_nonce_poly1305']} B, etiqueta {c['tam_etiqueta']} B)"
    )
    print(f"Poly1305 con un bit alterado -> ValueError: {c['poly1305_error']}")

    _titulo("PARTE 2 - Descifrado con ChaCha20")
    print(f"Cifrado (hex): {CIFRADO_PARTE2.hex()} ({len(CIFRADO_PARTE2)} bytes)")
    print(f"Texto plano  : {descifrar(CIFRADO_PARTE2)}")

    _titulo("EXTRA - Sincronización del keystream con seek()")
    print(f"Cifrado recibido: {len(CIFRADO_EXTRA)} bytes, perdidos: {BYTES_PERDIDOS}")
    sin_sync = crear_cifrador().decrypt(CIFRADO_EXTRA)
    print(f"Sin seek (desincronizado): {sin_sync!r}")
    print(f"Con seek({BYTES_PERDIDOS}): {sincronizar_keystream().decode('utf-8')}")


if __name__ == "__main__":
    main()
