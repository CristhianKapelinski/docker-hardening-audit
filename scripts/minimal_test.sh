#!/usr/bin/env bash
# Teste minimo: audita dois Dockerfiles do corpus, um com defeito e um correto,
# sem instalar nada e sem rede. Usa a saida dos backends ja' versionada em
# corpus/raw/ (a "corrida de referencia"), por isso roda em qualquer maquina.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

echo "=== 1. arquivo com defeito: corpus/dockerfiles/vuln_13_legacy_stack.Dockerfile"
set +e
python3 -m dhaudit.cli scan corpus/dockerfiles/vuln_13_legacy_stack.Dockerfile \
  --replay corpus/raw --min-severity medium
code=$?
set -e
echo "exit code: $code (esperado 1: ha' violacao HIGH ou acima)"
[ "$code" -eq 1 ] || { echo "FALHOU: exit code inesperado"; exit 1; }

echo
echo "=== 2. arquivo correto: corpus/dockerfiles/hardened_02_multistage.Dockerfile"
python3 -m dhaudit.cli scan corpus/dockerfiles/hardened_02_multistage.Dockerfile --replay corpus/raw
echo "exit code: 0 (esperado 0: nenhuma violacao)"

echo
echo "RESULT: OK"
