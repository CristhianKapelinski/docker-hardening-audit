# Cobertura medida dos backends

Este documento registra a medição que decidiu o desenho da ferramenta. Nada aqui foi lido na documentação dos scanners: os números vêm de rodar hadolint v2.15.1 e trivy 0.74.0 sobre os 24 Dockerfiles de `corpus/`, com a saída bruta versionada em `corpus/raw/`.

A pergunta era direta: se hadolint, trivy e dockle já existem, o que falta para responder às 12 propriedades de hardening da política? A resposta define onde há código nativo neste repositório e onde não há.

## O que cada configuração detecta

Cada configuração é avaliada contra o gabarito de `corpus/labels.json`, que lista, por arquivo, as propriedades que uma auditoria correta precisa reportar e nenhuma outra. As cinco configurações são computadas a partir da MESMA saída bruta, então a comparação não depende de qual dia cada scanner rodou.

| configuração | TP | FP | FN | precisão | recall | F1 | propriedades cobertas |
|---|---:|---:|---:|---:|---:|---:|---:|
| hadolint | 8 | 1 | 19 | 0,889 | 0,296 | 0,444 | 4 de 12 |
| trivy | 14 | 1 | 13 | 0,933 | 0,519 | 0,667 | 6 de 12 |
| união dos dois | 16 | 1 | 11 | 0,941 | 0,593 | 0,727 | 7 de 12 |
| só as checagens nativas | 16 | 0 | 11 | 1,000 | 0,593 | 0,744 | 8 de 12 |
| dhaudit (agregado) | 26 | 0 | 1 | 1,000 | 0,963 | 0,981 | 12 de 12 |

## Propriedade por propriedade

| propriedade | hadolint | trivy | nativo | por que existe código nativo |
|---|---|---|---|---|
| HARD-01 não-root | — | `DS-0002` | `NAT-USER` | resolve o usuário pela cadeia de alias entre estágios, e cobre o caso de o trivy não estar disponível |
| HARD-02 base pinada por digest | `DL3007` | `DS-0001` | `NAT-DIGEST` | os dois só disparam em `:latest`; `python:3.12-slim` passa |
| HARD-03 sem segredo em ENV/ARG | `DL3064` | `DS-0031` | arbitragem | os dois acusam `ARG API_TOKEN` sem valor default, que não vaza nada |
| HARD-04 sem `curl \| sh` | — | — | `NAT-PIPE` | nenhum dos dois tem checagem; `DL4006` é sobre `pipefail`, não sobre download não verificado |
| HARD-05 cache do apt | `DL3009`, `DL3015` | `DS-0029` | — | coberto; não há código nativo |
| HARD-06 sem `ADD` remoto | — | — | `NAT-ADD-REMOTE` | nenhum dos dois tem checagem |
| HARD-07 sem permissão 777 | — | — | `NAT-WORLD-WRITABLE` | nenhum dos dois tem checagem |
| HARD-08 sem porta sensível | — | `DS-0004` | `NAT-PORT` | `DS-0004` cobre só a porta 22; 5432, 6379 e 27017 passam |
| HARD-09 healthcheck | — | `DS-0026` | — | coberto; não há código nativo |
| HARD-10 sem sudo | `DL3004` | — | `NAT-SUDO` | `DL3004` dispara em `RUN sudo`, não em instalar o pacote sudo |
| HARD-11 dependência pinada | `DL3013`, `DL3016` | — | — | coberto; não há código nativo |
| HARD-12 `.dockerignore` | — | — | `NAT-DOCKERIGNORE` | é um fato do diretório, que nenhum dos dois olha |

Três checagens nativas foram **escritas e depois removidas** quando esta medição mostrou que hadolint e trivy já as cobrem: higiene do apt, healthcheck e pinagem de dependência. O repositório não tem código para elas.

## Dois achados que mudaram o desenho

**hadolint falha ao ler heredoc do BuildKit.** Em `vuln_15_heredoc_pipe.Dockerfile` ele retorna apenas `DL1000` ("unexpected 'W'"), que é erro de parse, e nenhuma outra descoberta. Um agregador que trate "nenhuma descoberta" como "arquivo limpo" classifica esse arquivo como correto. Por isso o `hadolint.py` propaga `parse_failed` e o relatório imprime a linha `! hadolint could not parse ...`: o silêncio de um backend não é resultado limpo.

**Ruído fora da política.** Sobre os 24 arquivos, `DL3025` (usar notação JSON em CMD) e `DL3066` (uid não numérico) disparam dezenas de vezes, inclusive em arquivos que estão corretos pela política. Eles não são erros do hadolint, apenas respondem a outra pergunta. O agregador os classifica como fora da política, conta e guarda no JSON, mas não os mistura com violação de hardening.

## O corpus tem controle adversarial contra as próprias checagens nativas

Uma revisão adversarial do artefato, feita por outro modelo de IA, produziu dois falsos positivos em menos de um minuto: `RUN echo "não rode: curl x | sh"` disparava HARD-04, e `RUN echo "antes usava chmod 777" > NOTES` disparava HARD-07, porque as checagens eram regex sobre a linha crua. A crítica de método era mais séria que os dois bugs: o corpus tinha controles negativos difíceis para os backends, e nenhum contra as regras nativas — escritas pela mesma pessoa que escreveu o corpus.

As checagens foram reescritas para separar comandos respeitando aspas e descartar argumento de `echo`/`printf` (`native.split_command`), e o caso entrou no corpus como `hardened_09_text_mentions_commands.Dockerfile`, com rótulo vazio. Nele, hadolint reporta só código fora da política (`DL3025`, `DL3059`, `DL3066`), o trivy não reporta nada, e as checagens nativas não reportam nada. Antes da correção, o agregado teria dois falsos positivos nesse arquivo.

## Uma decisão de política que a medição forçou

`DL3008` (pinar versão em `apt-get install`), `DL3018` (apk) e `DL3028` (gem) ficaram **fora** da política, enquanto `DL3013` (pip) e `DL3016` (npm) ficaram dentro. Debian e Ubuntu removem versões superadas do repositório, então um Dockerfile que pina `apt-get install curl=7.88.1-10` para de compilar em poucas semanas; e o digest exigido por HARD-02 já congela o snapshot de pacotes que aquele build vê. Índices de linguagem não têm essa restrição: guardam todas as versões, e lock file é prática normal.

Sem essa separação, `hardened_01_python.Dockerfile` seria contado como violação por instalar `ca-certificates` sem versão, o que na prática ninguém faz.

## Como refazer a medição

```bash
./scripts/collect_backends.sh corpus/live
PYTHONPATH=src python3 -m dhaudit.cli evaluate --replay corpus/live
```

A primeira linha regrava a saída bruta dos backends a partir das imagens pinadas por digest; a segunda recomputa a tabela. A versão versionada em `corpus/raw/` é a corrida de referência, e é dela que sai a tabela publicada no README.
