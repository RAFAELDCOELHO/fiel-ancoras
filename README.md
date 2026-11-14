# fiel-ancoras

Âncoras públicas de um arquivo de dados com prova.

Um sistema privado guarda, com sha256, cada versão baixada de arquivos públicos de dados abertos do setor elétrico brasileiro, num livro-razão encadeado por hash: cada linha carrega o sha da anterior. A **cabeça** da cadeia é o sha da última linha. Ela muda se qualquer linha anterior for alterada, apagada ou reordenada.

Este repositório publica só essas cabeças, uma linha por publicação, em `ancoras.tsv`:

| coluna | significado |
|---|---|
| `data_utc` | quando a cabeça foi registrada |
| `head` | sha256 da última linha do livro-razão (64 hex) |
| `n_linhas` | número de linhas do livro-razão naquele momento |
| `raiz` | desde 2026-11-13 (a partir da âncora das 20:40 BRT): a raiz da árvore de Merkle (RFC 6962, SHA-256) das primeiras `n_linhas` linhas do livro-razão (64 hex). As linhas anteriores, de 3 colunas, ficam como estão. |

Nada aqui revela dado ou cliente: um sha256 não permite reconstruir o conteúdo. O único código publicado é o verificador (`produto_verifica.py`), para que qualquer pessoa confira as âncoras sem confiar em quem as publica.

**Para que serve.** Quem receber o arquivo no futuro pode conferir, com um verificador que usa só a biblioteca padrão do Python, que a linha `n_linhas` do livro-razão tem exatamente o sha publicado aqui naquela data. Isso prova que o arquivo existia naquela forma e não foi refeito depois. O horário de cada commit neste repositório público é o registro de quando a cabeça se tornou pública.

**Nota de honestidade.** As três primeiras linhas (de 2026-11-11T01:38Z a 10:31Z) foram registradas antes, num repositório privado. A publicação aqui começa em 2026-11-11, e a prova pública de cada linha vale a partir do commit que a trouxe a este repositório.

**Árvore de Merkle.** Desde 2026-11-13, cada âncora traz também a raiz de uma árvore de Merkle no formato do Certificate Transparency (RFC 6962), com uma folha por linha do livro-razão:
- folha = SHA-256(0x00 ‖ os 32 bytes do sha da linha);
- nó = SHA-256(0x01 ‖ esquerda ‖ direita).

Com ela, um terceiro confere duas coisas sem baixar o livro-razão, só com o Python 3.9 ou mais novo, a biblioteca padrão e este repositório:
- **Inclusão:** um registro está na árvore publicada. Basta o registro, um caminho de cerca de log₂(n) hashes e esta tabela:
  `python3 produto_verifica.py --verificar-inclusao prova.json --ancoras ancoras.tsv`
- **Consistência:** a árvore de uma âncora estende a de uma âncora anterior, sem nenhuma linha antiga reescrita:
  `python3 produto_verifica.py --verificar-consistencia prova.json --ancoras ancoras.tsv`

As provas (`prova.json`) são geradas por quem tem o livro-razão, com `--prova-inclusao N` e `--prova-consistencia M N`. O verificador foi testado contra os vetores públicos do projeto transparency-dev/merkle (RFC 6962/9162).

## Testemunha independente: OpenTimestamps

A partir da âncora de 14/11/2026, cada linha de `ancoras.tsv` tem dois arquivos em `ots/`, com o nome dado pelo `data_utc` sem os `:` (exemplo: `ots/2026-11-14T234004Z.txt`):

- `<nome>.txt`: a linha da âncora, exatamente como está em `ancoras.tsv`, seguida de uma quebra de linha;
- `<nome>.txt.ots`: o carimbo [OpenTimestamps](https://opentimestamps.org) desse arquivo.

Só o sha256 do `.txt` saiu daqui, enviado a quatro calendários públicos: `a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`, `a.pool.eternitywall.com` e `ots.btc.catallaxy.com`. O carimbo só é aceito se pelo menos dois responderem. No dia seguinte, o job troca a promessa dos calendários pelo atestado do Bitcoin, quando ele já existe.

O carimbo prova que a linha (o head do ledger, o número de linhas e a raiz Merkle) já existia no instante do bloco do Bitcoin indicado no `.ots`. Ele não prova o `data_utc`, que continua sendo uma declaração nossa. As linhas anteriores a 14/11/2026 não têm carimbo. Uma linha carimbada com atraso, num dia em que os calendários falharam, prova só a data do carimbo.

### Como conferir, sem confiar em nós

Use o cliente oficial, sem instalar nada global:

```sh
grep -F "$(cat ots/2026-11-14T234004Z.txt)" ancoras.tsv   # a linha está na tabela
uvx --from opentimestamps-client==0.8.0 ots info   ots/2026-11-14T234004Z.txt.ots
uvx --from opentimestamps-client==0.8.0 ots verify ots/2026-11-14T234004Z.txt.ots
```

O `ots info` mostra o que o carimbo contém:
- antes do upgrade, só `PendingAttestation('<calendário>')`, que é uma promessa do calendário e sozinha não prova nada;
- depois do upgrade, `BitcoinBlockHeaderAttestation(<altura>)`.

O limite, declarado: o `ots verify` completo exige um nó Bitcoin seu (`bitcoind` com RPC), porque confere a raiz Merkle do bloco no cabeçalho que o nó tem. Com `--no-bitcoin`, o `verify` sempre termina com falha; isso não é um "ok parcial". Sem nó, você pode pegar a altura do bloco que o `ots info` mostra e comparar a raiz Merkle num explorador de blocos, mas aí confia nesse explorador.

Para ligar a linha ao ledger, use o verificador deste repositório (`produto_verifica.py`), com as provas de inclusão e de consistência descritas acima.
