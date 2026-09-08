# Uso

Os comandos que a avaliação exige estão no README. Aqui ficam os demais.

## Auditar

Um Dockerfile, com os backends ao vivo:

```bash
PYTHONPATH=src python3 -m dhaudit.cli scan Dockerfile
```

Um diretório inteiro, falhando o pipeline só em CRITICAL:

```bash
PYTHONPATH=src python3 -m dhaudit.cli scan . --fail-on critical
```

Sem docker, relendo a saída de backend já gravada:

```bash
PYTHONPATH=src python3 -m dhaudit.cli scan corpus/dockerfiles --replay corpus/raw
```

Uma imagem já construída, a partir de um `docker inspect` salvo (não usa docker):

```bash
docker inspect minha-imagem:tag > /tmp/config.json
PYTHONPATH=src python3 -m dhaudit.cli scan /tmp/config.json
```

Uma imagem local, com o dockle (precisa do socket do docker):

```bash
PYTHONPATH=src python3 -m dhaudit.cli image minha-imagem:tag
```

## Formatos de saída

```bash
PYTHONPATH=src python3 -m dhaudit.cli scan corpus/dockerfiles --format json --replay corpus/raw
PYTHONPATH=src python3 -m dhaudit.cli scan corpus/dockerfiles --format sarif --output report.sarif --replay corpus/raw
```

O JSON traz, além das violações: os backends que rodaram, os achados fora da política, os que a arbitragem removeu com a razão, e os arquivos que um backend não conseguiu parsear.

## Códigos de saída

| Código | Significado |
|---|---|
| 0 | nenhuma violação no limiar de `--fail-on` |
| 1 | violação no limiar (padrão `high`) |
| 2 | erro de uso ou de entrada |

O `2` tem precedência sobre o `1`: um alvo que não pôde ser lido, um JSON inválido ou um arquivo sem nenhum `FROM` não foram auditados, e devolver `0` ou `1` diria ao pipeline que foram.

## Inspecionar a política e os backends

```bash
PYTHONPATH=src python3 -m dhaudit.cli policy
PYTHONPATH=src python3 -m dhaudit.cli backends
```

## Testes

```bash
PYTHONPATH=src python3 -m pytest tests/ -q
```

68 testes, menos de 1 s, sem rede e sem docker. Cada checagem nativa tem controle positivo e negativo; a arbitragem, a consistência da política, o contrato de código de saída, as entradas malformadas e a Reivindicação #1 têm testes próprios.

Para rodar de uma vez o mesmo conjunto que o pipeline de CI declara:

```bash
./scripts/verify_all.sh
```
