#!/usr/bin/env bash

set -e
set -x

mypy src/fastapi_swagger2
ruff src/fastapi_swagger2 tests scripts
black src/fastapi_swagger2 tests --check
isort src/fastapi_swagger2 tests scripts --check-only
