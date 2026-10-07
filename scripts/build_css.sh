#!/usr/bin/env bash
set -e
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -f "./tailwindcss" ]; then
    TAILWIND_BIN="./tailwindcss"
elif command -v tailwindcss >/dev/null 2>&1; then
    TAILWIND_BIN="tailwindcss"
elif command -v npx >/dev/null 2>&1; then
    TAILWIND_BIN="npx tailwindcss"
else
    echo "Erro: tailwindcss CLI não encontrado." >&2
    exit 1
fi

echo "Compilando Tailwind CSS estático..."
$TAILWIND_BIN -i ./frontend/src/input.css -o ./frontend/public/css/tailwind.min.css --minify
echo "Concluído com sucesso! Arquivo gerado em frontend/public/css/tailwind.min.css"
