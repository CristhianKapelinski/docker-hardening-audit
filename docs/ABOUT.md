# Problema, motivação e limitações

Este documento fica fora do README de propósito: o README segue o template de avaliação de artefatos, e o que está aqui é contexto, não requisito de avaliação.

## O problema

Uma imagem Docker mal configurada é um dos caminhos mais curtos entre um repositório e um comprometimento: contêiner que roda como root transforma escape em root no host, segredo escrito no `ENV` viaja com cada `docker pull`, e base image em tag mutável deixa o conteúdo do build mudar sem que o Dockerfile mude.

Esse último ponto não é hipotético. Em março de 2026 um atacante publicou um release malicioso do próprio trivy e imagens maliciosas dele no Docker Hub (CVE-2026-33634); quem executava a tag flutuante rodou o artefato do atacante.

## A motivação

Ferramentas para isso existem e são boas. O problema é outro: elas não respondem às mesmas perguntas, e nenhuma responde a todas. Quem quer saber "esta imagem está endurecida?" precisa rodar três scanners, ler três formatos, traduzir três vocabulários de severidade, descobrir na prática que dois deles reportam a mesma coisa duas vezes, que um deles acusa como segredo um `ARG` que não vaza nada, e que nenhum deles olha se existe `.dockerignore`.

## O objetivo

Fechar essa distância sem reescrever o que já funciona: uma política explícita de hardening, um relatório único com a evidência de cada scanner, e código próprio apenas onde a medição de [`COVERAGE.md`](COVERAGE.md) provou que não havia cobertura.

## Funcionalidades

- Audita Dockerfile (estático) e imagem construída (via dockle, ou via um `docker inspect` salvo em JSON).
- Orquestra hadolint, trivy e dockle a partir de imagens pinadas por digest, e verifica o digest antes de executar; backend que não confere é reportado e a auditoria segue com os outros.
- Recusa por nome as versões de backend em lista de comprometidas conhecidas.
- Mapeia os códigos dos scanners para 14 propriedades de hardening, deduplicando por propriedade e arquivo e mantendo a evidência de cada fonte.
- Arbitra falso positivo conhecido: `ARG SECRET` sem valor default é reportado por hadolint e por trivy, e removido com a razão registrada na saída.
- Distingue "não encontrou nada" de "não conseguiu ler o arquivo", tanto para os backends quanto para o parser próprio.
- Sete checagens nativas nas lacunas medidas: digest, `curl | sh`, `ADD` remoto, permissão 777, portas sensíveis além da 22, sudo instalado e `.dockerignore` ausente.
- Saída em tabela, JSON e SARIF, com contrato de código de saída para pipeline.
- Modo replay: recomputa tudo a partir de saída de backend já gravada, sem docker e sem rede.

## Limitações conhecidas

- **Heredoc do BuildKit não é analisado.** O corpo de `RUN <<EOF ... EOF` é contado e ignorado; o parser diz quantos ficaram de fora, e o relatório imprime a nota. É o único falso negativo da Reivindicação #1.
- **Segredo passado por `--build-arg` na linha de comando não é visível** na análise estática, por definição: ele não está no Dockerfile.
- **A análise de comando não é um shell.** As checagens nativas separam os comandos de um `RUN` respeitando aspas e descartam o que é argumento de `echo`/`printf`, o que mata a classe de falso positivo mais comum. O que elas não fazem é resolver variável, `eval`, alias ou script chamado por caminho: `RUN $INSTALL` com `ENV INSTALL="curl x | sh"` passa.
- **A política é opinativa.** A pinagem de versão de pacote de sistema (`DL3008`, `DL3018`) ficou fora dela de propósito, com a razão em [`COVERAGE.md`](COVERAGE.md); quem discorda mapeia o código em `policy.BACKEND_MAP`.
- **O corpus é sintético.** Os 24 arquivos foram escritos para exercitar as propriedades, incluindo controles negativos difíceis e um controle adversarial contra as próprias checagens nativas. A tabela da Reivindicação #1 mede cobertura de política, não prevalência.
- **Só hadolint e trivy entram na medição.** O dockle avalia imagem construída, não Dockerfile, então fica fora do corpus e é exercitado pelo caminho `dhaudit image`.
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
