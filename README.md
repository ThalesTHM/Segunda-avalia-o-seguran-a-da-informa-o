# RSA-OAEP em Python: criptografia assimétrica

Trabalho da **2ª avaliação de Segurança da Informação**. O programa:

1. **cifra** uma mensagem qualquer usando **RSA** (criptografia assimétrica) com preenchimento **OAEP**;
2. **decifra** a mensagem cifrada e recupera exatamente o texto original.

O algoritmo foi implementado **do zero, em Python puro** (sem bibliotecas de criptografia), seguindo a especificação oficial [RFC 8017 (PKCS #1 v2.2)](https://www.rfc-editor.org/rfc/rfc8017). Assim cada etapa do RSA fica visível no código.

📊 **Apresentação:** [`apresentacao.pdf`](apresentacao.pdf). Também está disponível em HTML: abra [`apresentacao.html`](apresentacao.html) no navegador e use as setas ← → para navegar.

## Integrantes

- Thales Henrique
- _(integrante 2)_
- _(integrante 3)_
- _(integrante 4)_

## Como executar

Requisito: **Python 3.10 ou mais recente**. Não precisa instalar nada.

### Demonstração completa (gera as chaves, cifra e decifra)

```bash
python main.py demo --mensagem "Olá, turma! Mensagem secreta 🔐"
```

Exemplo de saída:

```
=== 1. Gerando par de chaves RSA de 2048 bits ===================
Tempo: 0.40 s
n (módulo, público) = c9a6519bb1b9450ec91bd04874a2a484415f007f...  (512 caracteres)
e (expoente público) = 65537
d (expoente privado) = 3e137c45f0c537142126f5cc8853554ffd8bd06c...  [SECRETO]

=== 2. Mensagem original ========================================
Olá, turma! Mensagem secreta 🔐
34 bytes em UTF-8 (cada bloco OAEP comporta até 190 bytes)

=== 3. Cifrando com a chave PÚBLICA =============================
1 bloco(s) de 256 bytes
Base64: PSGRh4mxa/wj5d5uh/Bc3e2V7mfyqkOEuhDIK8nK...  (344 caracteres)
Cifrando de novo a MESMA mensagem: CYr0zJLTVKD2/kO5xLpF...
Os textos cifrados são diferentes? True  (OAEP é aleatório)

=== 4. Decifrando com a chave PRIVADA ===========================
Olá, turma! Mensagem secreta 🔐

=== 5. Verificação ==============================================
SUCESSO: a mensagem decifrada é idêntica à original.
Texto cifrado com 1 bit alterado foi REJEITADO, como esperado.
```

Sem argumentos (`python main.py`), o programa pede a mensagem no terminal.

### Uso separado (como numa comunicação real)

```bash
# 1. Bob gera seu par de chaves
python main.py gerar-chaves --bits 2048 --pasta chaves

# 2. Alice cifra uma mensagem com a chave PÚBLICA de Bob
python main.py cifrar --chave chaves/publica.json -m "Encontro às 15h" -s cifrado.txt

# 3. Só Bob, com a chave PRIVADA, consegue decifrar
python main.py decifrar --chave chaves/privada.json -a cifrado.txt
```

Use `python main.py <comando> --help` para ver todas as opções.

### Testes automatizados

```bash
python -m unittest discover -s tests -v
```

São 23 testes. Eles cobrem a aritmética (Euclides, inverso modular, Miller-Rabin com números de Carmichael), o exemplo clássico com p = 61 e q = 53, a ida e volta de mensagens de vários tamanhos (vazia, acentos/emoji, várias vezes maior que um bloco), a aleatoriedade do OAEP, a detecção de adulteração, a chave errada, as entradas inválidas e o salvamento e carregamento das chaves.

## Estrutura do projeto

```
├── main.py                 # interface de linha de comando (demo, gerar-chaves, cifrar, decifrar)
├── cripto_rsa/
│   ├── aritmetica.py       # Euclides estendido, inverso modular, Miller-Rabin, geração de primos
│   ├── chaves.py           # geração, validação, salvamento e carregamento das chaves
│   ├── oaep.py             # preenchimento OAEP com SHA-256 e MGF1 (RFC 8017 §7.1)
│   ├── rsa.py              # primitivas RSA, CRT, blinding, cifragem em blocos, Base64
│   └── erros.py            # exceção ErroDecifragem
├── tests/test_rsa.py       # testes automatizados (unittest)
├── apresentacao.pdf        # apresentação em PDF
└── apresentacao.html       # apresentação explicando o código
```

## Como o RSA funciona

**Geração das chaves** (`chaves.py`)

1. Sorteiam-se dois primos grandes e distintos, `p` e `q`, de 1024 bits cada (teste de Miller-Rabin).
2. Calcula-se `n = p · q`, o módulo de 2048 bits.
3. Calcula-se `λ(n) = mmc(p − 1, q − 1)`, a função de Carmichael.
4. Escolhe-se `e = 65537`, coprimo com `λ(n)`.
5. Calcula-se `d = e⁻¹ mod λ(n)` com o algoritmo de Euclides estendido.

A **chave pública** é `(n, e)` e a **chave privada** é `d` (junto com `p`, `q` e os valores do CRT).

**Cifragem:** `c = mᵉ mod n`. **Decifragem:** `m = cᵈ mod n`.

Funciona porque `e · d ≡ 1 (mod λ(n))`, o que implica `(mᵉ)ᵈ ≡ m (mod n)`. A segurança vem da dificuldade de **fatorar `n`**: sem `p` e `q` não se calcula `λ(n)` e, portanto, não se descobre `d`.

**Fluxo completo de uma mensagem**

```
texto → UTF-8 → blocos de até 190 bytes → OAEP (semente aleatória + SHA-256)
      → inteiro m → c = mᵉ mod n → bytes → Base64
```

## Decisões de segurança

| Decisão | Por quê |
|---|---|
| **OAEP** em vez de RSA "puro" | O RSA de livro-texto é determinístico (a mesma mensagem gera sempre o mesmo texto cifrado) e maleável. O OAEP adiciona aleatoriedade e uma verificação de integridade. |
| Módulo `secrets` | O módulo `random` é previsível. O `secrets` usa o gerador seguro do sistema operacional. |
| Chaves de **2048 bits** (mínimo 1024) | O NIST recomenda pelo menos 2048 bits. |
| `e = 65537` | É o valor padrão: torna a cifragem rápida e evita os ataques contra `e = 3`. |
| `p` e `q` "distantes" | Primos próximos permitem fatorar `n` pelo método de Fermat. |
| Miller-Rabin com 40 rodadas | A chance de aceitar um número composto é menor que 4⁻⁴⁰. |
| **CRT** na decifragem | A decifragem fica cerca de 3 vezes mais rápida. |
| **Blinding** na decifragem | O tempo de cálculo deixa de depender do texto cifrado, o que dificulta ataques de temporização. |
| Erro de decifragem genérico | Não revela qual verificação falhou, o que mitiga o ataque de Manger. |
| `repr=False` nos campos secretos | A chave privada não aparece por acidente em `print` ou em logs. |
| `.gitignore` bloqueia `chaves/` | A chave privada nunca vai parar no repositório. |

## Limitações (trabalho didático)

- Python puro **não garante tempo constante**. Em produção, use bibliotecas auditadas, como [`cryptography`](https://cryptography.io).
- Na prática, o RSA não é usado para cifrar mensagens longas. Usa-se **criptografia híbrida**: o RSA cifra apenas uma chave AES, e o AES cifra os dados. Aqui a mensagem é dividida em blocos RSA porque o objetivo do trabalho é usar o algoritmo assimétrico diretamente.
- A chave privada é salva em JSON **sem proteção por senha**.

## Referências

- RIVEST, R.; SHAMIR, A.; ADLEMAN, L. *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems*. Communications of the ACM, 1978.
- MORIARTY, K. et al. **RFC 8017**: PKCS #1: RSA Cryptography Specifications, versão 2.2. IETF, 2016.
- BELLARE, M.; ROGAWAY, P. *Optimal Asymmetric Encryption*. EUROCRYPT, 1994.
- NIST **SP 800-57**, Parte 1 rev. 5: Recommendation for Key Management.
- STALLINGS, W. *Criptografia e Segurança de Redes*. Pearson.
