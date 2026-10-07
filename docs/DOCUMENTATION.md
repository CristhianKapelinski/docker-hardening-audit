# Documentação interna

Para a avaliação do artefato, o [`README.md`](../README.md) é o único arquivo necessário; este é complementar.

Como o código está organizado, o que cada módulo decide, e o que fazer para estendê-lo.

## O caminho de uma auditoria

Uma execução de `dhaudit scan Dockerfile` passa por cinco etapas, nesta ordem.

1. `parser.parse_file` transforma o texto em `Dockerfile`, uma lista de `Stage`, cada um com suas `Instruction` já com as continuações de linha unidas.
2. `aggregate.check_backends` verifica o digest de cada imagem de backend. Backend que não passa é marcado indisponível, e a auditoria segue com os outros.
3. Cada backend disponível roda e devolve `BackendOutput`; `normalize` traduz a saída própria dele para linhas de um formato comum.
4. `backends.native.check` roda as checagens nativas sobre o documento já parseado.
5. `aggregate._merge` mapeia cada linha para uma propriedade da política, aplica a arbitragem, e deduplica: uma propriedade que falha num arquivo é UMA violação carregando a evidência de cada fonte.

## Módulos

| módulo | responsabilidade |
|---|---|
| `model.py` | tipos de dados: `Severity`, `Finding`, `OutOfPolicy`, `Instruction`, `Stage`, `Dockerfile`, `ImageConfig` |
| `parser.py` | Dockerfile para estágios, sem dependência externa; conta heredoc que não parseia |
| `policy.py` | as 14 propriedades, o mapa `código do backend -> propriedade`, e a justificativa de cada checagem nativa |
| `backends/__init__.py` | digests pinados, lista de versões comprometidas, verificação antes de rodar |
| `backends/hadolint.py` | roda hadolint por stdin; propaga erro de parse |
| `backends/trivy.py` | roda `trivy config`; tenta offline com cache quente e cai para online quando o cache está frio |
| `backends/dockle.py` | roda dockle sobre imagem construída (opt-in, precisa do socket) |
| `backends/native.py` | as sete checagens de lacuna e a arbitragem do `ARG` sem default |
| `aggregate.py` | orquestra, normaliza, deduplica, arbitra; modo replay |
| `evaluate.py` | métricas sobre o corpus rotulado, nas cinco configurações |
| `report.py` | tabela, JSON e SARIF |
| `cli.py` | subcomandos e o contrato de código de saída |

## Árvore do repositório

```
src/dhaudit/            código da ferramenta (um módulo por responsabilidade, tabela acima)
corpus/
  dockerfiles/          23 Dockerfiles rotulados: 14 com defeito, 9 corretos
  dockerfiles_no_ignore/ o caso de .dockerignore ausente, que exige diretório próprio
  image_configs/        dois exemplos de docker inspect, um com defeito e um correto
  labels.json           gabarito: as propriedades esperadas por arquivo
  raw/                  corrida de referência: saída bruta de hadolint e trivy
expected/values.json    os números publicados no README, alvo da comparação
scripts/                pull_backends, minimal_test, reproduce, collect_backends, dogfood, verify_all
tests/                  68 testes, sem rede e sem docker
docs/                   ABOUT, USAGE, COVERAGE e este arquivo
Dockerfile              imagem da ferramenta, auditada pela própria ferramenta
.github/workflows/      pipeline de testes e reprodução, o mesmo conjunto do scripts/verify_all.sh
CITATION.cff            referência legível por ferramenta
```

## Decisões que o código carrega

**O estágio final é o que importa.** Rodar como root, deixar cache do apt ou instalar sudo num estágio de build não chega na imagem publicada. As checagens que dependem disso olham `Dockerfile.final_stage`, e o usuário efetivo é resolvido subindo a cadeia de alias (`FROM base` herda o `USER` de `base`), em `native._effective_user`.

**Silêncio de backend não é resultado limpo.** `BackendOutput.parse_failed` distingue "não achou nada" de "não conseguiu ler", e o relatório imprime as duas coisas de forma diferente. O mesmo vale para o parser próprio: `Dockerfile.parse_errors` carrega `FROM` sem imagem e ausência de `FROM`, e o agregador os põe em `result.errors`, o que leva o código de saída para 2. Sem isso, um arquivo binário passado como Dockerfile voltava como "0 violações", indistinguível de um Dockerfile endurecido.

**Comando não é texto.** As checagens de `curl | sh` e de permissão 777 não são regex sobre a linha crua: `native.split_command` separa os comandos de um `RUN` respeitando aspas, e `_executable` descarta o que é argumento de `echo`/`printf`. Sem isso, `RUN echo "não rode: curl x | sh"` era reportado como download executado, um falso positivo que uma revisão adversarial produziu em menos de um minuto.

**A severidade é da política, não do backend.** Os três scanners usam vocabulários diferentes de severidade para a mesma coisa. Quem decide o peso de uma propriedade é `policy.PROPERTIES`, então dois backends discordando de severidade não muda o relatório.

**Degradar, nunca recusar.** Backend indisponível, digest divergente ou docker ausente reduzem a cobertura e são reportados; não abortam a execução. O caso em que a recusa é correta é a versão comprometida conhecida (`KNOWN_COMPROMISED`), e ali a recusa é só daquele backend.

## Estender

**Nova propriedade:** acrescente um `Property` em `policy.PROPERTIES`. Se algum backend já a responde, mapeie o código em `BACKEND_MAP`; se não, escreva a checagem em `backends/native.py`, registre a justificativa em `NATIVE_JUSTIFICATION` e acrescente um caso ao corpus com o rótulo correspondente. O teste `test_every_dockerfile_property_is_answered_by_someone` falha enquanto a propriedade não tiver quem responda.

**Novo backend:** crie `backends/<nome>.py` com `run(...) -> BackendOutput` e `normalize(output) -> list[dict]`, acrescente o digest em `PINNED` e mapeie os códigos em `BACKEND_MAP`. As linhas normalizadas precisam ter as chaves `source`, `source_id`, `path`, `line`, `severity` e `message`.

**Atualizar um backend:** troque a versão e o digest em `PINNED`, rode `./scripts/collect_backends.sh corpus/raw` para regravar a corrida de referência, e rode `./scripts/reproduce.sh`. Se um número mudar, a saída aponta qual, e aí a tabela publicada no README e em `expected/values.json` precisa ser atualizada junto, com a mudança explicada.

## Testes

`python3 -m pytest tests/ -q` roda 68 testes, sem rede e sem docker. Cada checagem nativa tem controle positivo e negativo, a arbitragem tem teste próprio, a consistência da política é verificada (nenhum mapeamento aponta para propriedade inexistente), o contrato de código de saída da CLI é testado, e a reivindicação do corpus está gateada em `tests/test_evaluate.py`, não só no script de reprodução.

Onze desses testes nasceram de uma revisão adversarial do artefato feita por outro modelo de IA, que executou os comandos do README e tentou quebrar a ferramenta. Eles cobrem `FROM` sem imagem, arquivo sem nenhum `FROM`, o código de saída de entrada inválida, e os dois falsos positivos de texto dentro de `echo`.
