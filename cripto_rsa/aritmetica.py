from __future__ import annotations

import math
import secrets


def _crivo_de_eratostenes(limite: int) -> tuple[int, ...]:
    eh_primo = bytearray([1]) * (limite + 1)
    eh_primo[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limite) + 1):
        if eh_primo[i]:
            eh_primo[i * i :: i] = bytearray(len(range(i * i, limite + 1, i)))
    return tuple(i for i, primo in enumerate(eh_primo) if primo)


PRIMOS_PEQUENOS = _crivo_de_eratostenes(2000)


def euclides_estendido(a: int, b: int) -> tuple[int, int, int]:
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mdc(a: int, b: int) -> int:
    return euclides_estendido(a, b)[0]


def mmc(a: int, b: int) -> int:
    return a // mdc(a, b) * b


def inverso_modular(a: int, m: int) -> int:
    g, x, _ = euclides_estendido(a % m, m)
    if g != 1:
        raise ValueError(f"{a} não possui inverso módulo {m}")
    return x % m


def miller_rabin(n: int, rodadas: int = 40) -> bool:
    if n < 2:
        return False
    for p in PRIMOS_PEQUENOS:
        if n % p == 0:
            return n == p

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rodadas):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gerar_primo(bits: int) -> int:
    if bits < 16:
        raise ValueError("o primo precisa ter pelo menos 16 bits")
    while True:
        candidato = secrets.randbits(bits)
        candidato |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if miller_rabin(candidato):
            return candidato
