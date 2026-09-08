#!/usr/bin/env bash
# Audita o proprio Dockerfile deste repositorio, com os backends de verdade.
# Precisa de docker. Aceita a unica descoberta LOW esperada (HARD-09), que nao
# se aplica a uma imagem de CLI de uma execucao so'.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
python3 -m dhaudit.cli scan Dockerfile --min-severity medium --fail-on medium
echo "RESULT: OK (nenhuma violacao MEDIUM ou acima no proprio Dockerfile)"
