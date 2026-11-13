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
