#!/usr/bin/env bash
# Roda hadolint e trivy sobre o corpus e grava a saida bruta de cada um.
# E' o que produz a "corrida de referencia" (corpus/raw/), que deixa a avaliacao
# rodar offline depois. Precisa de docker; as imagens sao pinadas por digest.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-corpus/raw}"
HADOLINT="hadolint/hadolint:v2.15.1-alpine@sha256:a1d49ae1a4e83c1dbad26b8c1ad7588c8bd1e04f4866b34ad3cac50335198552"
TRIVY="aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
CACHE="${DHAUDIT_TRIVY_CACHE:-$HOME/.cache/dhaudit-trivy}"

mkdir -p "$OUT/hadolint" "$OUT/trivy" "$CACHE"

for dir in corpus/dockerfiles corpus/dockerfiles_no_ignore; do
  for file in "$dir"/*.Dockerfile; do
    name="$(basename "$file")"
    docker run --rm -i --network none "$HADOLINT" \
      hadolint -f json --no-color - < "$file" > "$OUT/hadolint/$name.json" 2>/dev/null || true
    docker run --rm -v "$CACHE:/root/.cache" -v "$PWD/$dir:/scan:ro" "$TRIVY" \
      config --quiet --format json "/scan/$name" > "$OUT/trivy/$name.json" 2>/dev/null || true
  done
done

echo "saida bruta em $OUT ($(ls "$OUT/hadolint" | wc -l) arquivos por backend)"
