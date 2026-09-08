# dhaudit: auditoria de hardening de imagens Docker

`dhaudit` audita o hardening de imagens Docker orquestrando os scanners que já existem — hadolint, trivy e dockle —, traduzindo a saída dos três para uma política única de 14 propriedades, deduplicando o que dois deles dizem sobre a mesma linha, e escrevendo código próprio **somente** nas lacunas que uma medição mostrou existir. Sobre um corpus rotulado de 24 Dockerfiles, hadolint responde a **4 das 12** propriedades de Dockerfile e o trivy a **6**; a união dos dois chega a **7**, com recall **0,593** e um falso positivo. O agregado chega a **12 de 12**, com precisão **1,000** e recall **0,963**.

**Para a avaliação deste artefato, este README é o único arquivo que você precisa ler.** Os outros documentos são complementares: [`docs/COVERAGE.md`](docs/COVERAGE.md) traz a medição de cobertura que decidiu o desenho, e [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md) descreve a arquitetura módulo a módulo.

## Estrutura do readme.md

| Seção | Descrição |
|---|---|
| [Problema, motivação e objetivo](#problema-motivação-e-objetivo) | o que a ferramenta resolve e por que ela não é mais um linter |
| [Funcionalidades](#funcionalidades) | o que ela faz |
| [Selos considerados](#selos-considerados) | Disponível, Funcional, Sustentável e Reprodutível |
| [Informações básicas](#informações-básicas) | ambiente de execução, hardware e software |
| [Dependências](#dependências) | o que é preciso ter, e os digests pinados |
| [Preocupações com segurança](#preocupações-com-segurança) | o que a execução faz na máquina do avaliador |
| [Instalação](#instalação) | dois comandos |
| [Teste mínimo](#teste-mínimo) | um comando, com a saída esperada |
| [Experimentos](#experimentos) | as três reivindicações e como reproduzir cada uma |
| [Exemplos de uso](#exemplos-de-uso) | os formatos de saída e o uso em pipeline |
| [Estrutura do repositório](#estrutura-do-repositório) | onde cada coisa está |
| [Testes](#testes) | como rodar a suíte |
| [Limitações conhecidas](#limitações-conhecidas) | o que a ferramenta não faz |
| [Referências](#referências) | scanners, benchmark e o incidente de supply chain citado |
| [LICENSE](#license) | MIT |

## Problema, motivação e objetivo

Uma imagem Docker mal configurada é hoje um dos caminhos mais curtos entre um repositório e um comprometimento: container que roda como root transforma escape em root no host, segredo escrito no `ENV` viaja com cada `docker pull`, e base image em tag mutável deixa o conteúdo do build mudar sem que o Dockerfile mude. Esse último ponto não é hipotético: em março de 2026 um atacante publicou um release malicioso do próprio trivy e imagens maliciosas dele no Docker Hub (CVE-2026-33634), e quem executava a tag flutuante rodou o artefato do atacante.

Ferramentas para isso existem e são boas. O problema é outro: **elas não respondem às mesmas perguntas, e nenhuma responde a todas.** Quem quer saber "esta imagem está endurecida?" precisa rodar três scanners, ler três formatos, traduzir três vocabulários de severidade, descobrir na prática que dois deles reportam a mesma coisa duas vezes, que um deles acusa como segredo um `ARG` que não vaza nada, e que nenhum deles olha se existe `.dockerignore`.

O objetivo do `dhaudit` é fechar essa distância sem reescrever o que já funciona: uma política explícita de hardening, um relatório único com a evidência de cada scanner, e código próprio apenas onde a medição de `docs/COVERAGE.md` provou que não havia cobertura.

## Funcionalidades

- Audita **Dockerfile** (estático) e **imagem construída** (via dockle, ou via um `docker inspect` já salvo em JSON).
- Orquestra hadolint, trivy e dockle a partir de **imagens pinadas por digest**, e **verifica o digest antes de executar**; um backend que não confere é reportado e a auditoria segue com os outros.
- Recusa-se a rodar versão de backend em lista de comprometidas conhecidas (`trivy` 0.69.4, 0.69.5 e 0.69.6).
- Mapeia os códigos dos scanners para **14 propriedades de hardening**, deduplicando por propriedade e arquivo e mantendo a evidência de cada fonte.
- **Arbitra falso positivo conhecido**: `ARG SECRET` sem valor default é reportado por hadolint e por trivy, e removido com a razão registrada na saída.
- Distingue "não encontrou nada" de **"não conseguiu ler o arquivo"** — hadolint falha o parse em heredoc do BuildKit, e esse silêncio não é resultado limpo.
- Sete checagens nativas nas lacunas medidas: digest, `curl | sh`, `ADD` remoto, permissão 777, portas sensíveis além da 22, sudo instalado e `.dockerignore` ausente.
- Saída em **tabela, JSON e SARIF**, com contrato de código de saída para pipeline (`--fail-on`, `--min-severity`).
- **Modo replay**: recomputa tudo a partir de saída de backend já gravada, sem docker e sem rede.

## Selos considerados

Os selos considerados são: **Disponíveis**, **Funcionais**, **Sustentáveis** e **Reprodutíveis**.

- **Disponível (SeloD).** Repositório público no GitLab, licença MIT, e este README com as seções mínimas exigidas.
- **Funcional (SeloF).** O [teste mínimo](#teste-mínimo) é um comando, roda sem rede e sem docker, e exercita o caminho real (parser, mapeamento, arbitragem, relatório e código de saída), não `--help`.
- **Sustentável (SeloS).** Código em `src/` com uma responsabilidade por módulo, docstrings dizendo qual decisão cada módulo carrega, tipagem nas funções públicas, 68 testes sem rede, um pipeline declarado em `.gitlab-ci.yml` que roda testes e reprodução (ver a ressalva abaixo), e `docs/DOCUMENTATION.md` explicando como acrescentar propriedade ou backend.
> **Ressalva sobre o CI.** O pipeline está declarado em `.gitlab-ci.yml` e roda os testes, o teste mínimo e a reprodução. No GitLab, porém, o pipeline público deste projeto aparece como `failed` **sem executar nenhum job**: a conta é gratuita e os runners compartilhados exigem verificação de identidade para liberar minutos de CI. Os runners aparecem como disponíveis pela API e o YAML não tem erro (`yaml_errors: null`), mas não consegui confirmar a causa exata sem acesso administrativo. Enquanto isso, o mesmo conjunto que o CI roda é reproduzível localmente em menos de um segundo com `./scripts/verify_all.sh`.

- **Reprodutível (SeloR).** `./scripts/reproduce.sh` recomputa a tabela publicada a partir da corrida de referência versionada e compara valor por valor com `expected/values.json`, imprimindo `obtido · esperado · ok` e terminando em `RESULT: OK`. O modo `--live` roda os scanners de novo, nas imagens pinadas.

## Informações básicas

Máquina de referência das medidas de tempo abaixo: AMD Ryzen 5 8600G, 32 GB de RAM, Ubuntu 24.04, Python 3.12.3, Docker 29.4.1.

| Modo | Requisitos | Disco (cumulativo) | Tempo |
|---|---|---|---|
| clone do repositório | git | 1,2 MB | ~2 s |
| teste mínimo e reprodução offline | Python 3.10 a 3.13, nada mais | 1,2 MB | 0,07 s e 0,04 s |
| suíte de testes | Python + pytest | 1,2 MB | 0,2 s |
| auditoria ao vivo e `reproduce.sh --live` | Docker, e as três imagens de backend | +290 MB de imagens e +3,1 MB de cache do trivy | ~2 min na primeira vez, ~25 s depois |

Os valores de disco e de tempo acima foram medidos com `du -sh` e `/usr/bin/time` nesta máquina, não estimados. As imagens de backend somam 287 MB (hadolint 64 MB, trivy 190 MB, dockle 33 MB) e são removidas com `docker image rm`.

Não é preciso GPU. Nenhum caminho exige privilégio de root na máquina do avaliador; o caminho de imagem construída (`dhaudit image`) precisa de acesso ao socket do Docker, e é opcional.

## Dependências

O tool não tem dependência de runtime: só a biblioteca padrão do Python.

| Dependência | Versão | Para quê | Obrigatória |
|---|---|---|---|
| Python | 3.10 a 3.13 (testado em 3.12.3) | rodar o `dhaudit` | sim |
| pytest | 8.x | rodar a suíte | só para testes |
| Docker | 20.10 ou mais novo (testado em 29.4.1) | rodar os backends ao vivo | só no caminho ao vivo |

Os backends são imagens pinadas por digest, e a verificação de digest acontece antes de cada execução:

| Backend | Imagem | Digest |
|---|---|---|
| hadolint | `hadolint/hadolint:v2.15.1-alpine` | `sha256:a1d49ae1a4e83c1dbad26b8c1ad7588c8bd1e04f4866b34ad3cac50335198552` |
| trivy | `aquasec/trivy:0.74.0` | `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` |
| dockle | `goodwithtech/dockle:v0.4.15` | `sha256:eade932f793742de0aa8755406c7677cd7696f8675b6180926f7eeffa7abe6b9` |

A escolha das versões foi conferida contra as advisories de cada projeto em 8 de setembro de 2026. O trivy 0.74.0 está acima das correções de `GHSA-mcj4-mphf-j9ff` (0.71.1), `GHSA-q3fv-x8vg-qqm4` (0.71.0) e `GHSA-8rc5-4fr6-64pw` (0.72.0), e fora da janela do comprometimento de março de 2026 (`GHSA-69fq-xp46-6x23` / CVE-2026-33634), cujas versões maliciosas estão bloqueadas no código.

## Preocupações com segurança

- A análise é **estática e local**: o `dhaudit` lê arquivos e roda contêineres de scanner; não constrói a imagem auditada nem executa nada dela.
- Os contêineres de hadolint rodam com `--network none`, e o do trivy também quando o cache de checks já está quente.
- Nenhuma credencial é necessária, e nenhum dado sai da máquina. Os Dockerfiles do corpus apontam para hosts `*.invalid`, reservados pela RFC 2606, então nada neles resolve.
- Os "segredos" do corpus são valores de exemplo (`hunter2-prod`, `ghp_exampletokenvalue123456`); não há credencial real no repositório.
- O caminho `dhaudit image` monta `/var/run/docker.sock` no contêiner do dockle, o que equivale a dar acesso ao daemon. É opt-in, e nenhum outro caminho precisa dele.

## Instalação

```bash
git clone https://gitlab.com/cristhianavila.aluno/docker-hardening-audit.git && cd docker-hardening-audit
```

Nada mais é preciso para o teste mínimo e para a reprodução: os scripts usam `PYTHONPATH=src` e apenas a biblioteca padrão. Para instalar o comando `dhaudit` no PATH, em ambiente virtual (~15 s):

```bash
python3 -m venv .venv && . .venv/bin/activate && python3 -m pip install --quiet '.[dev]'
```

Para o caminho ao vivo, baixe as três imagens de backend (287 MB, ~2 min):

```bash
./scripts/pull_backends.sh
```

## Teste mínimo

Um comando, sem rede e sem docker, 0,07 s:

```bash
./scripts/minimal_test.sh
```

Ele audita um Dockerfile com defeito e um correto, e confere o código de saída dos dois. O começo da saída esperada:

```
=== 1. arquivo com defeito: corpus/dockerfiles/vuln_13_legacy_stack.Dockerfile
HARD-01  CRITICAL  corpus/dockerfiles/vuln_13_legacy_stack.Dockerfile:1  [native, trivy]
    The image does not run as root
      - native:NAT-USER line 1: the final stage never sets USER, so the image runs as the base image user
      - trivy:DS-0002 line 1: Image user should not be 'root'
    fix: create an unprivileged account and switch to it with `USER` in the final stage
```

e o fim:

```
=== 2. arquivo correto: corpus/dockerfiles/hardened_02_multistage.Dockerfile
dhaudit 1.0.0: 0 violation(s) in 1 file(s)
critical=0  high=0  medium=0  low=0
backends: hadolint (replay), trivy (replay), native
exit code: 0 (esperado 0: nenhuma violacao)

RESULT: OK
```

## Experimentos

As três reivindicações do artefato. A **#1 é a principal**.

### Reivindicação #1

**Descrição.** Sobre o corpus rotulado de 24 Dockerfiles, o agregado cobre 12 das 12 propriedades de Dockerfile com precisão 1,000 e recall 0,963, contra 7 propriedades e recall 0,593 da união de hadolint e trivy.

**Execução** (0,04 s, sem rede e sem docker):

```bash
./scripts/reproduce.sh
```

**Recursos esperados.** ~50 MB de RAM, nenhum disco adicional.

**Resultado esperado.** A tabela abaixo, recomputada a partir de `corpus/raw/`, seguida da comparação valor por valor com `expected/values.json` e de `RESULT: OK`.

```
configuration   TP  FP  FN  precision   recall     F1  properties
-----------------------------------------------------------------
hadolint         8   1  19      0.889    0.296  0.444           4
trivy           14   1  13      0.933    0.519  0.667           6
union           16   1  11      0.941    0.593  0.727           7
native          16   0  11      1.000    0.593  0.744           8
dhaudit         26   0   1      1.000    0.963  0.981          12
```

**Como ler essa tabela.** A política de 14 propriedades foi definida DEPOIS de medir onde hadolint e trivy falham, e as checagens nativas foram escritas exatamente para as lacunas medidas. Então a comparação diz "quanto de uma política de hardening explícita cada configuração cobre", e não "o agregado é melhor que os scanners": a política foi construída em cima das lacunas deles. O que a tabela sustenta é que rodar os dois scanners e somar a saída deixa 5 das 12 propriedades sem resposta, e que a diferença é preenchível com pouco código.

O único falso negativo do agregado é `vuln_15_heredoc_pipe.Dockerfile`, e ele é uma limitação declarada: o `curl | sh` está dentro de um heredoc do BuildKit, que nenhuma das configurações lê. O único falso positivo de hadolint e de trivy é o `ARG` sem valor default de `hardened_05`, removido pela arbitragem.

Para refazer a medição rodando os scanners de novo, em vez de reler a corrida de referência (~2 min, precisa de docker):

```bash
./scripts/reproduce.sh --live
```

### Reivindicação #2

**Descrição.** O próprio `Dockerfile` deste repositório passa na auditoria da ferramenta, com os backends de verdade, sem nenhuma violação MEDIUM ou acima.

**Execução** (~25 s, precisa de docker e das imagens de backend):

```bash
./scripts/dogfood.sh
```

**Recursos esperados.** 287 MB de disco para as imagens de backend, ~300 MB de RAM.

**Resultado esperado.**

```
dhaudit 1.0.0: 0 violation(s) in 1 file(s)
critical=0  high=0  medium=0  low=0
backends: hadolint, trivy, native
out of policy: 1 backend finding(s) (hadolint:DL3066); see the json output for the detail
RESULT: OK (nenhuma violacao MEDIUM ou acima no proprio Dockerfile)
```

A única descoberta LOW que a ferramenta faz no próprio Dockerfile é HARD-09, ausência de `HEALTHCHECK`, e ela não se aplica a uma imagem de CLI de uma execução só: não há serviço para sondar. Está declarado em comentário no próprio Dockerfile, e é por isso que o comando roda com `--min-severity medium`.

### Reivindicação #3

**Descrição.** A verificação de digest recusa um backend cuja imagem local não corresponde ao digest pinado, e recusa por nome as versões comprometidas do incidente de março de 2026, sem precisar de rede.

**Execução** (~1 s):

```bash
PYTHONPATH=src python3 -m pytest tests/test_backends.py tests/test_policy.py -v
```

**Resultado esperado.** 9 testes passando, entre eles `test_a_compromised_version_is_refused_before_docker_is_touched` e `test_no_pinned_backend_is_a_known_compromised_release`.

Para ver a verificação contra o estado real da máquina:

```bash
PYTHONPATH=src python3 -m dhaudit.cli backends
```

## Exemplos de uso

Auditar um Dockerfile com os backends ao vivo:

```bash
PYTHONPATH=src python3 -m dhaudit.cli scan Dockerfile
```

Auditar um diretório inteiro, falhando o pipeline só em CRITICAL:

```bash
PYTHONPATH=src python3 -m dhaudit.cli scan . --fail-on critical
```

Gerar SARIF para a interface de code scanning do GitLab ou do GitHub:

```bash
PYTHONPATH=src python3 -m dhaudit.cli scan corpus/dockerfiles --format sarif --output report.sarif
```

Auditar uma imagem já construída, sem docker, a partir de um `docker inspect` salvo:

```bash
docker inspect minha-imagem:tag > /tmp/config.json
PYTHONPATH=src python3 -m dhaudit.cli scan /tmp/config.json
```

Ver a política e quem responde a cada propriedade:

```bash
PYTHONPATH=src python3 -m dhaudit.cli policy
```

Códigos de saída: `0` nenhuma violação no limiar, `1` violação no limiar de `--fail-on` (padrão `high`), `2` erro de uso ou de entrada. O `2` tem precedência sobre o `1`: um alvo que não pôde ser lido, um JSON inválido ou um arquivo sem nenhum `FROM` não foram auditados, e devolver `0` ou `1` diria ao pipeline que foram.

## Estrutura do repositório

```
src/dhaudit/            código da ferramenta
  model.py              tipos de dados
  parser.py             Dockerfile -> estágios
  policy.py             as 14 propriedades e o mapa código-do-backend -> propriedade
  aggregate.py          orquestração, normalização, dedup e arbitragem
  evaluate.py           métricas sobre o corpus rotulado
  report.py             tabela, JSON e SARIF
  cli.py                subcomandos e código de saída
  backends/             um módulo por scanner, mais as checagens nativas
corpus/
  dockerfiles/          23 Dockerfiles rotulados (14 com defeito, 9 corretos)
  dockerfiles_no_ignore/ o caso de .dockerignore ausente, que precisa de diretório próprio
  image_configs/        dois exemplos de docker inspect, um com defeito e um correto
  labels.json           gabarito: as propriedades esperadas por arquivo
  raw/                  corrida de referência: saída bruta de hadolint e trivy
expected/values.json    os números publicados neste README, alvo da comparação
scripts/                pull_backends, minimal_test, reproduce, collect_backends, dogfood, verify_all
tests/                  68 testes, sem rede e sem docker
docs/                   COVERAGE.md (a medição) e DOCUMENTATION.md (a arquitetura)
```

## Testes

```bash
PYTHONPATH=src python3 -m pytest tests/ -q
```

68 testes, menos de 1 s, sem rede e sem docker. Cada checagem nativa tem controle positivo e negativo; a arbitragem, a consistência da política, o contrato de código de saída da CLI, as entradas malformadas e a reivindicação #1 têm testes próprios.

## Limitações conhecidas

- **Heredoc do BuildKit não é analisado.** O corpo de `RUN <<EOF ... EOF` é contado e ignorado; o parser diz quantos ficaram de fora, e o relatório imprime a nota. É o único falso negativo da reivindicação #1.
- **Segredo passado por `--build-arg` na linha de comando não é visível** na análise estática, por definição: ele não está no Dockerfile.
- **A política é opinativa.** A pinagem de versão de pacote de sistema (`DL3008`, `DL3018`) ficou fora dela de propósito, com a razão em `docs/COVERAGE.md`; quem discorda pode mapear o código em `policy.BACKEND_MAP`.
- **O corpus é sintético.** Os 24 arquivos foram escritos para exercitar as propriedades, incluindo controles negativos difíceis e um controle adversarial contra as próprias checagens nativas (`hardened_09`, que menciona `curl | sh` e `chmod 777` dentro de `echo` sem executar nenhum dos dois). A tabela da reivindicação #1 mede cobertura de política, não prevalência.
- **A análise de comando não é um shell.** As checagens nativas separam os comandos de um `RUN` respeitando aspas e descartam o que é argumento de `echo`/`printf`, o que mata a classe de falso positivo mais comum. O que elas não fazem é resolver variável, `eval`, alias ou script chamado por caminho: `RUN $INSTALL` com `ENV INSTALL="curl x | sh"` passa.
- **Só hadolint e trivy entram na medição.** O dockle avalia imagem construída, não Dockerfile, então ele fica fora do corpus e é exercitado pelo caminho `dhaudit image`.
- **Vulnerabilidade de pacote não é escopo.** Quem responde isso é `trivy image`; aqui a pergunta é configuração e hardening.

## Referências

- hadolint, linter de Dockerfile: <https://github.com/hadolint/hadolint>
- trivy, scanner de configuração e vulnerabilidade: <https://github.com/aquasecurity/trivy>
- dockle, verificador de imagem em cima do CIS Docker Benchmark: <https://github.com/goodwithtech/dockle>
- CIS Docker Benchmark: <https://www.cisecurity.org/benchmark/docker>
- Docker, boas práticas de escrita de Dockerfile: <https://docs.docker.com/build/building/best-practices/>
- OWASP Docker Security Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- GHSA-69fq-xp46-6x23 / CVE-2026-33634, comprometimento da cadeia de distribuição do trivy: <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23>
- Requisitos de avaliação de artefatos do SBSeg 2026: <https://doc-artefatos.github.io/sbseg2026/>

## LICENSE

MIT. Ver [`LICENSE`](LICENSE).
