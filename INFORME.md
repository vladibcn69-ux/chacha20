# Informe: Fundamentos de ChaCha20 – Introducción (PE 89.1, MF0489)

## Introducción

ChaCha20 es un cifrador de flujo diseñado por D. J. Bernstein. A partir de una
**clave de 32 bytes (256 bits)**, un **nonce** y un contador, genera un
*keystream* que se combina con el texto plano mediante XOR. Internamente trabaja
con una matriz de estado de 4×4 palabras de 4 bytes (64 bytes = 512 bits), de
la que sale cada bloque de keystream de 64 bytes. Ese tamaño de 512 bits es el
del **estado/bloque**, no el de la clave.

La práctica se implementa con PyCryptodome (`Crypto.Cipher.ChaCha20`) en
`src/chacha20_lab.py`; las pruebas están en `tests/test_chacha20_lab.py`.
Los fragmentos de salida de este informe proceden de la ejecución real del
programa (`python src/chacha20_lab.py`).

Parámetros de la práctica:

| Parámetro | Valor |
|-----------|-------|
| Texto plano | `Este es un mensaje secreto que quiero cifrar` (UTF-8, 44 bytes) |
| Clave (32 bytes) | `7ae87e22ca79571467182b1c2bf98006509e6a8838b447dfe4c5302c8d598019` |
| Nonce (8 bytes) | `d67f36c7e8692aa4` |

## Parte 1

### 1. ¿Cuál es el texto cifrado resultante?

```python
cifrador = ChaCha20.new(key=CLAVE, nonce=NONCE)
cifrado = cifrador.encrypt(TEXTO_PLANO.encode("utf-8"))
```

```
Cifrado bytes: b'Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb\x88\x18`W\xc3yQn\xad3\xec.\x08\x92\x9f\x92\xb8w\x8a\r'
Cifrado hex  : 4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d (44 bytes)
```

El texto cifrado mide 44 bytes, igual que el texto plano: un cifrador de flujo
no añade relleno. Se muestra en bytes y en hexadecimal; el hexadecimal es la
representación segura para copiar, porque la forma `bytes` contiene caracteres
no imprimibles que se corrompen fácilmente al copiar y pegar.

### 2. ¿Qué tamaño tiene el nonce que has utilizado?

8 bytes (64 bits): es el ChaCha20 original de Bernstein, con contador de 64 bits.

### 3. ¿Puedes utilizar un nonce de mayor tamaño (ej. 12 bytes o 16 bytes)?

Depende del tamaño. PyCryptodome acepta nonces de **8 bytes** (original,
contador de 64 bits), **12 bytes** (RFC 8439 / IETF, contador de 32 bits) y
**24 bytes** (XChaCha20). **16 bytes no se admiten**. Resultado de la ejecución
(los nonces de 12 y 24 bytes se forman rellenando con ceros el nonce original,
solo para esta comparación):

```
  nonce  8 bytes: aceptado  -> 4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d
  nonce 12 bytes: aceptado  -> 7194b0f38d5799f3044d8b358584d958b6b11a843fbfe881ed42a0448d9966d601aeb23ceb0692d3c75b19f7
  nonce 16 bytes: RECHAZADO -> ValueError: Nonce must be 8/12 bytes(ChaCha20) or 24 bytes (XChaCha20)
  nonce 24 bytes: aceptado  -> 565837446308300fdf7216b4227a5b10545caa7b9f7337649d151bacf21880954e4bc3bf46a2e70aa73b71fb
```

Con la misma clave y el mismo texto, cada tamaño de nonce produce un cifrado
distinto: el nonce forma parte de la entrada del estado inicial y, además, las
variantes difieren en la estructura (contador de 64 o 32 bits; en XChaCha20 se
deriva una subclave con HChaCha20 a partir de los primeros 16 bytes del nonce).
Por tanto, emisor y receptor deben usar **la misma variante**.

### 4. ¿Qué implicaciones de seguridad tiene utilizar un nonce de mayor tamaño?

- **Menor riesgo de colisión de nonces.** El nonce no es secreto, pero no debe
  repetirse nunca con la misma clave. Si se generan al azar, por la paradoja
  del cumpleaños una colisión se vuelve plausible tras ~2³² mensajes con 8
  bytes, ~2⁴⁸ con 12 bytes, y es despreciable con 24 bytes (~2⁹⁶). Por eso
  XChaCha20 (24 bytes) permite nonces aleatorios con seguridad.
- **Contador más corto con 12 bytes.** La variante IETF reparte los bits: 96
  de nonce y 32 de contador, de modo que un mismo (clave, nonce) cifra como
  máximo 2³² bloques × 64 B = 256 GiB. Con 8 bytes el contador es de 64 bits.
- **Un nonce mayor no sustituye a la clave ni es secreto**, y no corrige
  su reutilización: sigue siendo imprescindible que sea único por clave.
- **Compatibilidad:** hay que acordar la variante y transmitir el nonce
  completo junto al texto cifrado.

### 5. ¿Qué riesgos existen si se reutiliza la misma clave y el mismo nonce?

Se reutiliza el mismo keystream K. Si C1 = P1 ⊕ K y C2 = P2 ⊕ K, entonces
**C1 ⊕ C2 = P1 ⊕ P2**: el keystream se cancela y el atacante obtiene la XOR de
los dos textos planos sin conocer la clave. Si conoce o adivina uno (P1), recupera
el otro (P2 = C1 ⊕ C2 ⊕ P1) y también el keystream. Se pierde la
confidencialidad. Demostración con cadenas didácticas:

```
C1 xor C2 : 0000000000000000000000080909090000000000000000000000000000000000000000000808
P1 xor P2 : 0000000000000000000000080909090000000000000000000000000000000000000000000808
El keystream se cancela (C1^C2 == P1^P2): True
P2 recuperado conociendo P1: 'Transferir 9999 euros a la cuenta ES99'
```

### 6. Diferencias entre ChaCha20 y ChaCha20-Poly1305

- **ChaCha20** solo ofrece **confidencialidad**. No autentica: cambiar bits del
  texto cifrado cambia los mismos bits del plano y el receptor no lo detecta
  (maleabilidad).
- **ChaCha20-Poly1305** es un cifrado autenticado (AEAD): además de cifrar,
  calcula una **etiqueta de 16 bytes** (Poly1305) que da **integridad y
  autenticidad**, y admite datos asociados autenticados. Usa nonce de 12 bytes
  (24 bytes en XChaCha20-Poly1305). La reutilización de nonce también es
  catastrófica aquí.

```
ChaCha20 con un bit alterado descifra SIN error: 'Pago de 110 euros a Ana'
Poly1305 legítimo: 'Pago de 100 euros a Ana' (nonce 12 B, etiqueta 16 B)
Poly1305 con un bit alterado -> ValueError: MAC check failed
```

## Parte 2

Se descifran 51 bytes con la misma clave y nonce. Se comprueba
`len(cifrado) == 51`. El cifrado se define a partir de su hexadecimal
(`bytes.fromhex`) y se contrasta con el literal `bytes` mediante `assert`. El
hexadecimal es más fiable al copiar bytes con caracteres no imprimibles; además,
en el texto del enunciado el cifrado de esta parte aparece con las barras
duplicadas (`\\x83`), por lo que el literal no se puede copiar tal cual (daría
bytes distintos).

```
Cifrado (hex): 4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08928d8ebb258f1aa6c93d150f35aa (51 bytes)
Texto plano  : Este es un mensaje secreto que quiero que descifres
```

El descifrado es la misma operación que el cifrado (XOR con el mismo
keystream).

## EXTRA: sincronización del keystream

El receptor perdió los 8 primeros bytes del mensaje, de modo que recibe 42
bytes (se comprueba `len == 42`; el cifrado se define también desde su
hexadecimal y se contrasta con el literal). ChaCha20 genera el keystream en bloques
de 64 bytes y el flujo es **posicional**: el byte *i* del texto cifrado se
descifra con el byte *i* del keystream. Al faltar 8 bytes, el primer byte
recibido se combina con el byte 0 del keystream en lugar del byte 8, y todo el
descifrado queda desplazado y resulta ilegible.

La solución es `cipher.seek(8)`, que adelanta el keystream 8 bytes:

```python
cifrador = ChaCha20.new(key=CLAVE, nonce=NONCE)
cifrador.seek(8)
texto = cifrador.decrypt(cifrado_recibido)
```

```
Sin seek (desincronizado): b'\xad\xf9\x9f\x0e\xe0dU\xe2\xb0zZ\x17p`\x90\x13...'
Con seek(8): saje ha sufrido un error en la transmision
```

Limitación: solo funciona si el receptor **sabe cuántos bytes se perdieron**
(y si se pierden por el principio o hay un desplazamiento conocido). Los 8
primeros bytes del mensaje original no se pueden recuperar.

## Conclusiones

- ChaCha20 con clave de 32 bytes y nonce de 8 bytes reproduce el cifrado
  esperado de 44 bytes y se descifra con la misma clave y nonce.
- PyCryptodome admite nonces de 8, 12 y 24 bytes, no de 16; cada tamaño da un
  cifrado distinto, y un nonce mayor reduce el riesgo de colisión sin eximir
  de la unicidad.
- Reutilizar clave y nonce destruye la confidencialidad (C1 ⊕ C2 = P1 ⊕ P2).
- ChaCha20 no detecta alteraciones; ChaCha20-Poly1305 sí, mediante su etiqueta.
- `seek()` permite resincronizar el keystream cuando se conoce el número de
  bytes perdidos.

Autor: Volodymyr Osebchuk
