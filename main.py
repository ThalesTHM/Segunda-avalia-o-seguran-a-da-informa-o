from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path

from cripto_rsa import (
    ChavePrivada,
    ChavePublica,
    ErroDecifragem,
    carregar_chave,
    cifrar,
    cifrar_texto,
    decifrar,
    decifrar_texto,
    gerar_par_de_chaves,
    salvar_chave,
)
from cripto_rsa.oaep import tamanho_maximo_mensagem

MENSAGEM_PADRAO = "Segurança da Informação — 2ª avaliação: RSA-OAEP funcionando! 🔐"


def _resumir(texto: str, tamanho: int = 40) -> str:
    if len(texto) <= 2 * tamanho:
        return texto
    return f"{texto[:tamanho]}...{texto[-tamanho:]}  ({len(texto)} caracteres)"


def _linha(titulo: str) -> None:
    print(f"\n=== {titulo} " + "=" * max(0, 60 - len(titulo)))


def comando_demo(args: argparse.Namespace) -> int:
    mensagem = args.mensagem
    if mensagem is None:
        if sys.stdin.isatty():
            mensagem = input("Digite a mensagem a ser cifrada (Enter = exemplo): ")
        mensagem = mensagem or MENSAGEM_PADRAO

    _linha(f"1. Gerando par de chaves RSA de {args.bits} bits")
    inicio = time.perf_counter()
    privada = gerar_par_de_chaves(args.bits)
    publica = privada.publica
    print(f"Tempo: {time.perf_counter() - inicio:.2f} s")
    print(f"n (módulo, público) = {_resumir(f'{publica.n:x}')}")
    print(f"e (expoente público) = {publica.e}")
    print(f"d (expoente privado) = {_resumir(f'{privada.d:x}')}  [SECRETO]")

    _linha("2. Mensagem original")
    dados = mensagem.encode("utf-8")
    print(mensagem)
    limite = tamanho_maximo_mensagem(publica.tamanho_bytes)
    print(f"{len(dados)} bytes em UTF-8 (cada bloco OAEP comporta até {limite} bytes)")

    _linha("3. Cifrando com a chave PÚBLICA")
    cifrado = cifrar(publica, dados)
    cifrado_b64 = base64.b64encode(cifrado).decode("ascii")
    blocos = len(cifrado) // publica.tamanho_bytes
    print(f"{blocos} bloco(s) de {publica.tamanho_bytes} bytes")
    print(f"Base64: {_resumir(cifrado_b64)}")

    segundo = base64.b64encode(cifrar(publica, dados)).decode("ascii")
    print(f"Cifrando de novo a MESMA mensagem: {_resumir(segundo, 20)}")
    print(f"Os textos cifrados são diferentes? {cifrado_b64 != segundo}  (OAEP é aleatório)")

    _linha("4. Decifrando com a chave PRIVADA")
    recuperada = decifrar(privada, cifrado).decode("utf-8")
    print(recuperada)

    _linha("5. Verificação")
    if recuperada == mensagem:
        print("SUCESSO: a mensagem decifrada é idêntica à original.")
    else:
        print("ERRO: a mensagem decifrada é diferente da original!")
        return 1

    adulterado = bytearray(cifrado)
    adulterado[-1] ^= 0x01
    try:
        decifrar(privada, bytes(adulterado))
        print("ERRO: texto cifrado adulterado foi aceito!")
        return 1
    except ErroDecifragem:
        print("Texto cifrado com 1 bit alterado foi REJEITADO, como esperado.")
    return 0


def comando_gerar_chaves(args: argparse.Namespace) -> int:
    pasta = Path(args.pasta)
    print(f"Gerando chaves de {args.bits} bits...")
    privada = gerar_par_de_chaves(args.bits)
    salvar_chave(privada.publica, pasta / "publica.json")
    salvar_chave(privada, pasta / "privada.json")
    print(f"Chave pública:  {pasta / 'publica.json'}  (pode ser compartilhada)")
    print(f"Chave privada:  {pasta / 'privada.json'}  (NÃO compartilhe!)")
    return 0


def _ler_entrada(texto: str | None, arquivo: str | None) -> str:
    if arquivo:
        return Path(arquivo).read_text(encoding="utf-8")
    if texto is not None:
        return texto
    return sys.stdin.read()


def _escrever_saida(conteudo: str, arquivo: str | None) -> None:
    if arquivo:
        Path(arquivo).write_text(conteudo, encoding="utf-8")
        print(f"Resultado salvo em {arquivo}")
    else:
        print(conteudo)


def comando_cifrar(args: argparse.Namespace) -> int:
    chave = carregar_chave(args.chave)
    if not isinstance(chave, ChavePublica):
        chave = chave.publica
    mensagem = _ler_entrada(args.mensagem, args.arquivo)
    _escrever_saida(cifrar_texto(chave, mensagem), args.saida)
    return 0


def comando_decifrar(args: argparse.Namespace) -> int:
    chave = carregar_chave(args.chave)
    if not isinstance(chave, ChavePrivada):
        print("Erro: para decifrar é preciso a chave PRIVADA.", file=sys.stderr)
        return 2
    cifrado = _ler_entrada(args.cifrado, args.arquivo).strip()
    try:
        _escrever_saida(decifrar_texto(chave, cifrado), args.saida)
    except ErroDecifragem:
        print("Erro: não foi possível decifrar (chave errada ou dados corrompidos).",
              file=sys.stderr)
        return 1
    return 0


def criar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cifragem e decifragem com RSA-OAEP (criptografia assimétrica)."
    )
    sub = parser.add_subparsers(dest="comando")

    demo = sub.add_parser("demo", help="demonstração completa: gera chaves, cifra e decifra")
    demo.add_argument("-m", "--mensagem", help="mensagem a ser cifrada")
    demo.add_argument("--bits", type=int, default=2048, help="tamanho da chave (padrão 2048)")
    demo.set_defaults(func=comando_demo)

    gerar = sub.add_parser("gerar-chaves", help="gera e salva um par de chaves")
    gerar.add_argument("--bits", type=int, default=2048)
    gerar.add_argument("--pasta", default="chaves", help="pasta de destino (padrão: chaves)")
    gerar.set_defaults(func=comando_gerar_chaves)

    cif = sub.add_parser("cifrar", help="cifra uma mensagem com a chave pública")
    cif.add_argument("--chave", required=True, help="arquivo da chave pública")
    origem = cif.add_mutually_exclusive_group()
    origem.add_argument("-m", "--mensagem", help="texto a cifrar")
    origem.add_argument("-a", "--arquivo", help="arquivo de texto a cifrar")
    cif.add_argument("-s", "--saida", help="arquivo onde salvar o resultado (Base64)")
    cif.set_defaults(func=comando_cifrar)

    dec = sub.add_parser("decifrar", help="decifra uma mensagem com a chave privada")
    dec.add_argument("--chave", required=True, help="arquivo da chave privada")
    origem = dec.add_mutually_exclusive_group()
    origem.add_argument("-c", "--cifrado", help="texto cifrado em Base64")
    origem.add_argument("-a", "--arquivo", help="arquivo com o texto cifrado em Base64")
    dec.add_argument("-s", "--saida", help="arquivo onde salvar a mensagem decifrada")
    dec.set_defaults(func=comando_decifrar)

    return parser


def main(argv: list[str] | None = None) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8")

    args = criar_parser().parse_args(argv)
    if args.comando is None:
        args = criar_parser().parse_args(["demo", *(argv or sys.argv[1:])])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
