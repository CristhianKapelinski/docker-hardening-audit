#!/usr/bin/env bash
# Baixa as tres imagens de backend pinadas por digest e confere a verificacao.
# Puxar por digest guarda a imagem SEM tag, entao ela nao aparece em
# `docker images`; quem confirma que esta' la' e' `dhaudit backends`.
set -euo pipefail
cd "$(dirname "$0")/.."

HADOLINT="hadolint/hadolint:v2.15.1-alpine@sha256:a1d49ae1a4e83c1dbad26b8c1ad7588c8bd1e04f4866b34ad3cac50335198552"
TRIVY="aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
DOCKLE="goodwithtech/dockle:v0.4.15@sha256:eade932f793742de0aa8755406c7677cd7696f8675b6180926f7eeffa7abe6b9"

for image in "$HADOLINT" "$TRIVY" "$DOCKLE"; do
  echo "baixando ${image%%@*}"
  docker pull -q "$image" >/dev/null
done

echo
PYTHONPATH=src python3 -m dhaudit.cli backends
