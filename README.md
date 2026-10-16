# Laboratorio ChaCha20 – Fundamentos (PE 89.1, MF0489)

## Objetivo

Cifrar y descifrar mensajes con ChaCha20 usando PyCryptodome, analizar el
tamaño y la seguridad del nonce, comparar ChaCha20 con ChaCha20-Poly1305 y
resincronizar el keystream con `seek()`.

## Requisitos

- Python 3.9 o superior
- [PyCryptodome](https://pycryptodome.org) (ver `requirements.txt`)

## Instalación

**Windows (PowerShell)**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Ejecución

```bash
python src/chacha20_lab.py
```

Muestra de forma secuencial la Parte 1 (cifrado, nonce, reutilización de nonce,
ChaCha20 frente a ChaCha20-Poly1305), la Parte 2 (descifrado) y el EXTRA
(sincronización del keystream).

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Estructura

```
chacha20/
├── README.md
├── INFORME.md               # informe con las respuestas razonadas
├── requirements.txt
├── .gitignore
├── src/
│   └── chacha20_lab.py      # funciones y programa principal
└── tests/
    └── test_chacha20_lab.py
```

## Resumen de respuestas

Detalle y salida de la ejecución en [INFORME.md](INFORME.md).

1. Texto cifrado (44 bytes, hex):
   `4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d`
2. Nonce utilizado: 8 bytes (64 bits).
3. Se admiten nonces de 8, 12 y 24 bytes (XChaCha20); 16 bytes lanza `ValueError`.
4. Un nonce mayor reduce el riesgo de colisión (clave de 32 bytes = 256 bits sin cambios), pero debe seguir siendo único por clave.
5. Reutilizar clave y nonce hace que C1 ⊕ C2 = P1 ⊕ P2 y revela información de los textos planos.
6. ChaCha20 solo da confidencialidad; ChaCha20-Poly1305 añade integridad y autenticidad (etiqueta de 16 bytes).
7. Parte 2: `Este es un mensaje secreto que quiero que descifres`.
8. EXTRA: con `seek(8)` se obtiene `saje ha sufrido un error en la transmision`.

## Autor

Volodymyr Osebchuk
