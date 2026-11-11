import base64
import tempfile
import unittest
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
from cripto_rsa import oaep
from cripto_rsa.aritmetica import (
    euclides_estendido,
    gerar_primo,
    inverso_modular,
    miller_rabin,
    mmc,
)
from cripto_rsa.chaves import construir_chave_privada
from cripto_rsa.rsa import rsadp, rsaep


class TestAritmetica(unittest.TestCase):
    def test_euclides_estendido(self):
        for a, b in [(240, 46), (17, 3120), (65537, 2**64), (7, 7)]:
            g, x, y = euclides_estendido(a, b)
            self.assertEqual(a * x + b * y, g)

    def test_inverso_modular(self):
        self.assertEqual(inverso_modular(17, 3120), 2753)
        self.assertEqual((65537 * inverso_modular(65537, 2**61 - 2)) % (2**61 - 2), 1)
        with self.assertRaises(ValueError):
            inverso_modular(6, 9)

    def test_miller_rabin_primos(self):
        for p in [2, 3, 5, 7919, 104729, 2**61 - 1, 2**127 - 1]:
            self.assertTrue(miller_rabin(p), p)

    def test_miller_rabin_compostos(self):
        for n in [0, 1, 4, 561, 1105, 8911, 3215031751, (2**61 - 1) * (2**31 - 1)]:
            self.assertFalse(miller_rabin(n), n)

    def test_gerar_primo(self):
        p = gerar_primo(256)
        self.assertEqual(p.bit_length(), 256)
        self.assertTrue(miller_rabin(p))


class TestExemploLivroTexto(unittest.TestCase):
    def test_primitivas(self):
        chave = construir_chave_privada(61, 53, e=17)
        self.assertEqual(chave.n, 3233)
        self.assertEqual(mmc(60, 52), 780)
        self.assertEqual(chave.d, 413)
        c = rsaep(chave.publica, 65)
        self.assertEqual(c, 2790)
        self.assertEqual(rsadp(chave, c), 65)

    def test_todas_as_mensagens(self):
        chave = construir_chave_privada(61, 53, e=17)
        for m in range(chave.n):
            self.assertEqual(rsadp(chave, rsaep(chave.publica, m)), m)


class TestRSAOAEP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.privada = gerar_par_de_chaves(1024)
        cls.publica = cls.privada.publica

    def test_propriedades_da_chave(self):
        k = self.privada
        self.assertEqual(k.n.bit_length(), 1024)
        self.assertEqual(k.p * k.q, k.n)
        self.assertEqual((k.e * k.d) % mmc(k.p - 1, k.q - 1), 1)
        k.validar()

    def test_ida_e_volta(self):
        mensagens = [
            b"",
            b"a",
            "Olá, mundo! Ação, coração, pão. 🔐🚀".encode("utf-8"),
            bytes(range(256)),
            b"x" * 1000,
        ]
        for m in mensagens:
            with self.subTest(tamanho=len(m)):
                self.assertEqual(decifrar(self.privada, cifrar(self.publica, m)), m)

    def test_tamanho_exato_do_bloco(self):
        limite = oaep.tamanho_maximo_mensagem(self.publica.tamanho_bytes)
        for tamanho in (limite - 1, limite, limite + 1, 2 * limite):
            m = b"\xff" * tamanho
            c = cifrar(self.publica, m)
            blocos_esperados = max(1, -(-tamanho // limite))
            self.assertEqual(len(c), blocos_esperados * self.publica.tamanho_bytes)
            self.assertEqual(decifrar(self.privada, c), m)

    def test_texto_base64(self):
        texto = "Segurança da Informação"
        cifrado = cifrar_texto(self.publica, texto)
        base64.b64decode(cifrado, validate=True)
        self.assertEqual(decifrar_texto(self.privada, cifrado), texto)

    def test_cifragem_e_aleatoria(self):
        m = b"mesma mensagem"
        self.assertNotEqual(cifrar(self.publica, m), cifrar(self.publica, m))

    def test_texto_cifrado_nao_contem_a_mensagem(self):
        m = b"SEGREDO" * 10
        self.assertNotIn(b"SEGREDO", cifrar(self.publica, m))

    def test_adulteracao_e_detectada(self):
        c = bytearray(cifrar(self.publica, b"transferir R$ 100"))
        for posicao in (0, len(c) // 2, len(c) - 1):
            alterado = bytearray(c)
            alterado[posicao] ^= 0x01
            with self.subTest(posicao=posicao), self.assertRaises(ErroDecifragem):
                decifrar(self.privada, bytes(alterado))

    def test_chave_errada_falha(self):
        outra = gerar_par_de_chaves(1024)
        c = cifrar(self.publica, b"para o dono certo")
        with self.assertRaises(ErroDecifragem):
            decifrar(outra, c)

    def test_entradas_invalidas(self):
        for invalido in (b"", b"\x00" * 10, b"\x00" * (self.publica.tamanho_bytes + 1)):
            with self.assertRaises(ErroDecifragem):
                decifrar(self.privada, invalido)
        with self.assertRaises(ErroDecifragem):
            decifrar_texto(self.privada, "isto não é base64!!")

    def test_salvar_e_carregar(self):
        with tempfile.TemporaryDirectory() as pasta:
            salvar_chave(self.publica, Path(pasta) / "pub.json")
            salvar_chave(self.privada, Path(pasta) / "priv.json")
            pub = carregar_chave(Path(pasta) / "pub.json")
            priv = carregar_chave(Path(pasta) / "priv.json")
        self.assertIsInstance(pub, ChavePublica)
        self.assertIsInstance(priv, ChavePrivada)
        self.assertEqual(pub, self.publica)
        self.assertEqual(priv, self.privada)
        self.assertEqual(decifrar(priv, cifrar(pub, b"ok")), b"ok")

    def test_repr_nao_vaza_segredos(self):
        texto = repr(self.privada)
        self.assertNotIn(str(self.privada.d), texto)
        self.assertNotIn(str(self.privada.p), texto)

    def test_tamanho_minimo(self):
        with self.assertRaises(ValueError):
            gerar_par_de_chaves(512)


class TestOAEP(unittest.TestCase):
    def test_mgf1_tamanho(self):
        self.assertEqual(len(oaep.mgf1(b"semente", 100)), 100)
        self.assertEqual(oaep.mgf1(b"s", 10), oaep.mgf1(b"s", 40)[:10])

    def test_codificar_decodificar(self):
        k = 128
        em = oaep.codificar(b"teste", k)
        self.assertEqual(len(em), k)
        self.assertEqual(em[0], 0)
        self.assertEqual(oaep.decodificar(em, k), b"teste")

    def test_rotulo_diferente_falha(self):
        em = oaep.codificar(b"teste", 128, rotulo=b"A")
        with self.assertRaises(ErroDecifragem):
            oaep.decodificar(em, 128, rotulo=b"B")

    def test_mensagem_grande_demais(self):
        with self.assertRaises(ValueError):
            oaep.codificar(b"x" * 63, 128)


if __name__ == "__main__":
    unittest.main()
