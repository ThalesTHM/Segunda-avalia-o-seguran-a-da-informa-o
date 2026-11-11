from __future__ import annotations

import base64
import binascii
import secrets

from . import oaep
from .aritmetica import inverso_modular, mdc
from .chaves import ChavePrivada, ChavePublica
from .erros import ErroDecifragem


def bytes_para_int(dados: bytes) -> int:
    return int.from_bytes(dados, "big")


def int_para_bytes(x: int, tamanho: int) -> bytes:
    return x.to_bytes(tamanho, "big")


def rsaep(chave: ChavePublica, m: int) -> int:
    if not 0 <= m < chave.n:
        raise ValueError("representante da mensagem fora do intervalo [0, n)")
    return pow(m, chave.e, chave.n)


def _rsadp_crt(chave: ChavePrivada, c: int) -> int:
    m1 = pow(c, chave.dp, chave.p)
    m2 = pow(c, chave.dq, chave.q)
    h = (chave.qinv * (m1 - m2)) % chave.p
    return m2 + h * chave.q


def rsadp(chave: ChavePrivada, c: int) -> int:
    if not 0 <= c < chave.n:
        raise ErroDecifragem("falha na decifragem")
    while True:
        r = secrets.randbelow(chave.n - 2) + 2
        if mdc(r, chave.n) == 1:
            break
    c_cego = (c * pow(r, chave.e, chave.n)) % chave.n
    m_cego = _rsadp_crt(chave, c_cego)
    return (m_cego * inverso_modular(r, chave.n)) % chave.n


def cifrar_bloco(chave: ChavePublica, bloco: bytes) -> bytes:
    k = chave.tamanho_bytes
    em = oaep.codificar(bloco, k)
    c = rsaep(chave, bytes_para_int(em))
    return int_para_bytes(c, k)


def decifrar_bloco(chave: ChavePrivada, cifrado: bytes) -> bytes:
    k = chave.tamanho_bytes
    if len(cifrado) != k:
        raise ErroDecifragem("falha na decifragem")
    m = rsadp(chave, bytes_para_int(cifrado))
    return oaep.decodificar(int_para_bytes(m, k), k)


def cifrar(chave: ChavePublica, mensagem: bytes) -> bytes:
    k = chave.tamanho_bytes
    limite = oaep.tamanho_maximo_mensagem(k)
    pedacos = [mensagem[i : i + limite] for i in range(0, len(mensagem), limite)]
    if not pedacos:
        pedacos = [b""]
    return b"".join(cifrar_bloco(chave, p) for p in pedacos)


def decifrar(chave: ChavePrivada, cifrado: bytes) -> bytes:
    k = chave.tamanho_bytes
    if not cifrado or len(cifrado) % k != 0:
        raise ErroDecifragem("falha na decifragem")
    blocos = [cifrado[i : i + k] for i in range(0, len(cifrado), k)]
    return b"".join(decifrar_bloco(chave, b) for b in blocos)


def cifrar_texto(chave: ChavePublica, texto: str) -> str:
    return base64.b64encode(cifrar(chave, texto.encode("utf-8"))).decode("ascii")


def decifrar_texto(chave: ChavePrivada, cifrado_b64: str) -> str:
    try:
        cifrado = base64.b64decode(cifrado_b64, validate=True)
    except (binascii.Error, ValueError) as erro:
        raise ErroDecifragem("texto cifrado não é Base64 válido") from erro
    try:
        return decifrar(chave, cifrado).decode("utf-8")
    except UnicodeDecodeError as erro:
        raise ErroDecifragem("falha na decifragem") from erro
