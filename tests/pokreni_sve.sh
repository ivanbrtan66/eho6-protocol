#!/usr/bin/env bash
# Svi MASKA testovi. Bez pip-a, bez mreze prema internetu (sidra su na loopbacku).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
PY="${PYTHON:-python3}"
echo "Python: $($PY --version)"
$PY -m unittest discover -s tests -t . -p 'test_*.py' "$@"
