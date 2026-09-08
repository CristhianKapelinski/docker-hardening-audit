#!/usr/bin/env bash
# Reproduz a Reivindicacao #1: a tabela de deteccao sobre o corpus rotulado.
#
# Modo padrao (offline): recomputa as metricas a partir da saida dos backends
# versionada em corpus/raw/, sem docker e sem rede, e compara com os valores
# publicados em expected/values.json.
#
# Modo --live: roda hadolint e trivy de novo, nas imagens pinadas por digest,
# escreve a saida em corpus/live/ e recomputa a partir dela. Precisa de docker.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src

MODE="${1:-offline}"
REPLAY="corpus/raw"

if [ "$MODE" = "--live" ] || [ "$MODE" = "live" ]; then
  echo "== verificando os backends pinados"
  python3 -m dhaudit.cli backends || { echo "backend indisponivel; use o modo offline"; exit 1; }
  echo "== rodando os backends sobre o corpus (grava em corpus/live/)"
  ./scripts/collect_backends.sh corpus/live
  REPLAY="corpus/live"
fi

echo "== avaliando o corpus (replay: $REPLAY)"
python3 -m dhaudit.cli evaluate --labels corpus/labels.json --replay "$REPLAY" --expected expected/values.json
