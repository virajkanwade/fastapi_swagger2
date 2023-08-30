# fastapi_swagger2
<p align="center">
Swagger2 support for FastAPI
</p>
<p align="center">
<a href="https://pypi.org/project/fastapi_swagger2" target="_blank">
    <img src="https://img.shields.io/pypi/v/fastapi_swagger2?color=%2334D058&label=pypi%20package" alt="Package version">
</a>
<a href="https://pypi.org/project/fastapi_swagger2" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/fastapi_swagger2.svg?color=%2334D058" alt="Supported Python versions">
</a>
</p>

---

_Reason behind this library:_

Few API GW services like Google Cloud API GW still support only Swagger 2.0 spec. Since FastAPI only supports OAS3, it is a challenge. Converting from OAS3 to Swagger 2.0 requires some manual steps which would hinder CI/CD.

---

## Requirements

Python 3.8+

* 0.0.3 - FastAPI >= 0.79.0, <= 0.98.0
* 0.1.1 - FastAPI >= 0.99.0, <= 0.99.1
* 0.2.1 - FastAPI >= 0.100.0

## Installation

<div class="termy">

```console
$ pip install fastapi_swagger2
```

</div>

## Example

```Python
from typing import Union

from fastapi import FastAPI
from fastapi_swagger2 import FastAPISwagger2

app = FastAPI()
FastAPISwagger2(app)


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}
```

This adds following endpoints:
* http://localhost:8000/swagger2.json
* http://localhost:8000/swagger2/docs
* http://localhost:8000/swagger2/redoc

## Development

```console
$ pip install "/path/to/fastapi_swagger2/repo[test,all]"
```
