from __future__ import annotations

import hashlib
import hmac
import secrets

from .erros import ErroDecifragem

HASH = hashlib.sha256
TAMANHO_HASH = HASH().digest_size


def mgf1(semente: bytes, tamanho: int) -> bytes:
    saida = bytearray()
    contador = 0
    while len(saida) < tamanho:
        saida += HASH(semente + contador.to_bytes(4, "big")).digest()
        contador += 1
    return bytes(saida[:tamanho])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def tamanho_maximo_mensagem(k: int) -> int:
    return k - 2 * TAMANHO_HASH - 2


def codificar(mensagem: bytes, k: int, rotulo: bytes = b"") -> bytes:
    if len(mensagem) > tamanho_maximo_mensagem(k):
        raise ValueError("mensagem grande demais para um bloco OAEP")

    l_hash = HASH(rotulo).digest()
    ps = b"\x00" * (tamanho_maximo_mensagem(k) - len(mensagem))
    db = l_hash + ps + b"\x01" + mensagem

    semente = secrets.token_bytes(TAMANHO_HASH)
    db_mascarado = _xor(db, mgf1(semente, k - TAMANHO_HASH - 1))
    semente_mascarada = _xor(semente, mgf1(db_mascarado, TAMANHO_HASH))

    return b"\x00" + semente_mascarada + db_mascarado


def decodificar(em: bytes, k: int, rotulo: bytes = b"") -> bytes:
    if len(em) != k or k < 2 * TAMANHO_HASH + 2:
        raise ErroDecifragem("falha na decifragem")

    l_hash = HASH(rotulo).digest()
    y = em[0]
    semente_mascarada = em[1 : 1 + TAMANHO_HASH]
    db_mascarado = em[1 + TAMANHO_HASH :]

    semente = _xor(semente_mascarada, mgf1(db_mascarado, TAMANHO_HASH))
    db = _xor(db_mascarado, mgf1(semente, k - TAMANHO_HASH - 1))

    l_hash_recebido = db[:TAMANHO_HASH]
    resto = db[TAMANHO_HASH:]
    separador = resto.find(b"\x01")

    invalido = (
        y != 0
        or not hmac.compare_digest(l_hash, l_hash_recebido)
        or separador < 0
        or any(resto[:separador])
    )
    if invalido:
        raise ErroDecifragem("falha na decifragem")
    return resto[separador + 1 :]
