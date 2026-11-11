from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .aritmetica import gerar_primo, inverso_modular, mdc, mmc

E_PADRAO = 65537

TAMANHO_MINIMO_BITS = 1024


@dataclass(frozen=True)
class ChavePublica:
    n: int
    e: int

    @property
    def tamanho_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def para_dict(self) -> dict:
        return {"tipo": "publica", "n": f"{self.n:x}", "e": f"{self.e:x}"}


@dataclass(frozen=True)
class ChavePrivada:
    n: int
    e: int
    d: int = field(repr=False)
    p: int = field(repr=False)
    q: int = field(repr=False)
    dp: int = field(repr=False)
    dq: int = field(repr=False)
    qinv: int = field(repr=False)

    @property
    def publica(self) -> ChavePublica:
        return ChavePublica(self.n, self.e)

    @property
    def tamanho_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def validar(self) -> None:
        lambda_n = mmc(self.p - 1, self.q - 1)
        if (
            self.p * self.q != self.n
            or (self.e * self.d) % lambda_n != 1
            or self.dp != self.d % (self.p - 1)
            or self.dq != self.d % (self.q - 1)
            or (self.q * self.qinv) % self.p != 1
        ):
            raise ValueError("chave privada inconsistente")

    def para_dict(self) -> dict:
        dados = {"tipo": "privada"}
        for nome in ("n", "e", "d", "p", "q", "dp", "dq", "qinv"):
            dados[nome] = f"{getattr(self, nome):x}"
        return dados


def construir_chave_privada(p: int, q: int, e: int = E_PADRAO) -> ChavePrivada:
    if p == q:
        raise ValueError("p e q devem ser primos distintos")
    lambda_n = mmc(p - 1, q - 1)
    if mdc(e, lambda_n) != 1:
        raise ValueError("e não é coprimo com λ(n)")
    d = inverso_modular(e, lambda_n)
    return ChavePrivada(
        n=p * q,
        e=e,
        d=d,
        p=p,
        q=q,
        dp=d % (p - 1),
        dq=d % (q - 1),
        qinv=inverso_modular(q, p),
    )


def gerar_par_de_chaves(bits: int = 2048, e: int = E_PADRAO) -> ChavePrivada:
    if bits < TAMANHO_MINIMO_BITS:
        raise ValueError(f"use pelo menos {TAMANHO_MINIMO_BITS} bits")
    bits_p = bits // 2
    bits_q = bits - bits_p
    while True:
        p = gerar_primo(bits_p)
        q = gerar_primo(bits_q)
        if abs(p - q).bit_length() <= bits_p - 100:
            continue
        if mdc(e, mmc(p - 1, q - 1)) != 1:
            continue
        if p < q:
            p, q = q, p
        chave = construir_chave_privada(p, q, e)
        if chave.n.bit_length() == bits:
            return chave


def salvar_chave(chave: ChavePublica | ChavePrivada, caminho: str | Path) -> None:
    caminho = Path(caminho)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(json.dumps(chave.para_dict(), indent=2), encoding="utf-8")


def carregar_chave(caminho: str | Path) -> ChavePublica | ChavePrivada:
    dados = json.loads(Path(caminho).read_text(encoding="utf-8"))
    tipo = dados.get("tipo")
    if tipo == "publica":
        return ChavePublica(n=int(dados["n"], 16), e=int(dados["e"], 16))
    if tipo == "privada":
        valores = {
            nome: int(dados[nome], 16)
            for nome in ("n", "e", "d", "p", "q", "dp", "dq", "qinv")
        }
        chave = ChavePrivada(**valores)
        chave.validar()
        return chave
    raise ValueError(f"arquivo de chave inválido: tipo {tipo!r}")
