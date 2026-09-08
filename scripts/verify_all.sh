#!/usr/bin/env bash
# Roda exatamente o que o pipeline de CI roda: testes, teste minimo e a
# reproducao da Reivindicacao #1. Sem rede e sem docker.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

echo "== testes"
python3 -m pytest tests/ -q

echo
echo "== teste minimo"
./scripts/minimal_test.sh | tail -3

echo
echo "== reivindicacao #1"
./scripts/reproduce.sh | tail -3
