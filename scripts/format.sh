#!/bin/sh -e
set -x

ruff src/fastapi_swagger2 tests scripts --fix
black src/fastapi_swagger2 tests scripts
isort src/fastapi_swagger2 tests scripts
