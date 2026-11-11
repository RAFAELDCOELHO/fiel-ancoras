# fiel-ancoras

Âncoras públicas de um arquivo de dados com prova.

Um sistema privado guarda, com sha256, cada versão baixada de arquivos públicos de dados abertos do setor elétrico brasileiro, num livro-razão encadeado por hash: cada linha carrega o sha da anterior. A **cabeça** da cadeia é o sha da última linha. Ela muda se qualquer linha anterior for alterada, apagada ou reordenada.

Este repositório publica só essas cabeças, uma linha por publicação, em `ancoras.tsv`:

| coluna | significado |
|---|---|
| `data_utc` | quando a cabeça foi registrada |
| `head` | sha256 da última linha do livro-razão (64 hex) |
| `n_linhas` | número de linhas do livro-razão naquele momento |

Nada aqui revela dado, cliente ou código: um sha256 não permite reconstruir o conteúdo.

**Para que serve.** Quem receber o arquivo no futuro pode conferir, com um verificador que usa só a biblioteca padrão do Python, que a linha `n_linhas` do livro-razão tem exatamente o sha publicado aqui naquela data. Isso prova que o arquivo existia naquela forma e não foi refeito depois. O horário de cada commit neste repositório público é o registro de quando a cabeça se tornou pública.

**Nota de honestidade.** As três primeiras linhas (de 2026-11-11T01:38Z a 10:31Z) foram registradas antes, num repositório privado. A publicação aqui começa em 2026-11-11, e a prova pública de cada linha vale a partir do commit que a trouxe a este repositório.
