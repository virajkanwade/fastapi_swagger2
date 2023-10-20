from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

from fastapi._compat import _model_rebuild
from fastapi.logger import logger
from pydantic import AnyUrl, BaseModel, Field

try:
    import email_validator  # type: ignore

    assert email_validator  # make autoflake ignore the unused import
    from pydantic import EmailStr
except ImportError:  # pragma: no cover

    class EmailStr(str):  # type: ignore
        @classmethod
        def __get_validators__(cls) -> Iterable[Callable[..., Any]]:
            yield cls.validate

        @classmethod
        def validate(cls, v: Any) -> str:
            logger.warning(
                "email-validator not installed, email fields will be treated as str.\n"
                "To install, run: pip install email-validator"
            )
            return str(v)


class Contact(BaseModel):
    name: Optional[str] = None
    url: Optional[AnyUrl] = None
    email: Optional[EmailStr] = None

    model_config = {"extra": "allow"}


class License(BaseModel):
    name: str
    url: Optional[AnyUrl] = None

    model_config = {"extra": "allow"}


class Info(BaseModel):
    title: str
    description: Optional[str] = None
    termsOfService: Optional[str] = None
    contact: Optional[Contact] = None
    license: Optional[License] = None
    version: str

    model_config = {"extra": "allow"}


# class URLHost(Field)
"""
The host (name or ip) serving the API. This MUST be the host only and does not include the scheme nor sub-paths. It
MAY include a port. If the host is not included, the host serving the documentation is to be used (including the port)
"""

# class URLBasePath(Field)
"""
The base path on which the API is served, which is relative to the host. If it is not included, the API is served
directly under the host. The value MUST start with a leading slash (/).
"""


class URLSchemeEnum(Enum):
    http = "http"
    https = "https"
    ws = "ws"
    wss = "wss"


class ExternalDocumentation(BaseModel):
    description: Optional[str] = None
    url: AnyUrl

    model_config = {"extra": "allow"}


class Reference(BaseModel):
    ref: str = Field(alias="$ref")


class XML(BaseModel):
    name: Optional[str] = None
    namespace: Optional[str] = None
    prefix: Optional[str] = None
    attribute: Optional[bool] = None
    wrapped: Optional[bool] = None

    model_config = {"extra": "allow"}


class Schema(BaseModel):
    ref: Optional[str] = Field(default=None, alias="$ref")
    format: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None

    default: Optional[Any] = None
    multipleOf: Optional[float] = None
    maximum: Optional[float] = None
    exclusiveMaximum: Optional[bool] = None
    minimum: Optional[float] = None
    exclusiveMinimum: Optional[bool] = None
    maxLength: Optional[int] = Field(default=None, ge=0)
    minLength: Optional[int] = Field(default=None, ge=0)
    pattern: Optional[str] = None
    maxItems: Optional[int] = Field(default=None, ge=0)
    minItems: Optional[int] = Field(default=None, ge=0)
    uniqueItems: Optional[bool] = None
    maxProperties: Optional[int] = Field(default=None, ge=0)
    minProperties: Optional[int] = Field(default=None, ge=0)
    required: Optional[List[str]] = None
    enum: Optional[List[Any]] = None
    type_: Optional[str] = Field(default=None, alias="type")

    items: Optional[Union["Schema", List["Schema"]]] = None
    allOf: Optional[List["Schema"]] = None
    properties: Optional[Dict[str, "Schema"]] = None
    additionalProperties: Optional[Union["Schema", Reference, bool]] = None

    discriminator: Optional[str] = None
    readOnly: Optional[bool] = None
    xml: Optional[XML] = None
    externalDocs: Optional[ExternalDocumentation] = None
    example: Optional[Any] = None

    class Config:
        extra: str = "allow"


class _Schema2(BaseModel):
    type: Optional[str] = None
    format: Optional[str] = None
    items: Optional[Union["Schema", List["Schema"]]] = None
    collectionFormat: Optional[str] = None
    default: Optional[Any] = None
    maximum: Optional[float] = None
    exclusiveMaximum: Optional[bool] = None
    minimum: Optional[float] = None
    exclusiveMinimum: Optional[bool] = None
    maxLength: Optional[int] = Field(default=None, ge=0)
    minLength: Optional[int] = Field(default=None, ge=0)
    pattern: Optional[str] = None
    maxItems: Optional[int] = Field(default=None, ge=0)
    minItems: Optional[int] = Field(default=None, ge=0)
    uniqueItems: Optional[bool] = None
    enum: Optional[List[Any]] = None
    multipleOf: Optional[float] = None

    class Config:
        extra: str = "allow"


class ParameterSchema(_Schema2):
    allowEmptyValue: bool = False

    class Config:
        extra: str = "allow"


class ParameterInType(Enum):
    query = "query"
    header = "header"
    path = "path"
    formData = "formData"
    body = "body"


class ParameterBase(BaseModel):
    name: str
    in_: ParameterInType = Field(alias="in")
    description: Optional[str] = None
    required: Optional[bool] = None

    model_config = {"extra": "allow"}


class ParameterBody(ParameterBase):
    schema_: Optional[Union[Schema, ParameterSchema]] = Field(
        default=None, alias="schema"
    )


class ParameterNotBody(ParameterBase, ParameterSchema):
    pass

    model_config = {"extra": "allow"}


class Header(_Schema2):
    pass


class Response(BaseModel):
    description: str
    schema_: Optional[Schema] = Field(default=None, alias="schema")
    headers: Optional[Dict[str, Union[Header, Reference]]] = None
    examples: Optional[Any] = None  # XXX

    model_config = {"extra": "allow"}


class Operation(BaseModel):
    tags: Optional[List[str]] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    externalDocs: Optional[ExternalDocumentation] = None
    operationId: Optional[str] = None
    consumes: Optional[List[str]] = None  # XXX
    produces: Optional[List[str]] = None  # XXX
    parameters: Optional[List[Union[ParameterBody, ParameterNotBody]]] = None
    # Using Any for Specification Extensions
    responses: Dict[str, Union[Response, Any]]
    schemes: Optional[List[URLSchemeEnum]] = None
    deprecated: Optional[bool] = None
    security: Optional[List[Dict[str, List[str]]]] = None

    model_config = {"extra": "allow"}


class PathItem(BaseModel):
    ref: Optional[str] = Field(default=None, alias="$ref")
    get: Optional[Operation] = None
    put: Optional[Operation] = None
    post: Optional[Operation] = None
    delete: Optional[Operation] = None
    options: Optional[Operation] = None
    head: Optional[Operation] = None
    patch: Optional[Operation] = None
    parameters: Optional[List[Union[ParameterBody, ParameterNotBody]]] = None

    model_config = {"extra": "allow"}


class SecuritySchemeType(Enum):
    apiKey = "apiKey"
    basic = "basic"
    oauth2 = "oauth2"


class SecurityBase(BaseModel):
    type_: SecuritySchemeType = Field(alias="type")
    description: Optional[str] = None

    model_config = {"extra": "allow"}


class BasicAuth(SecurityBase):
    pass


class APIKeyIn(Enum):
    query = "query"
    header = "header"


class APIKey(SecurityBase):
    type_: SecuritySchemeType = Field(default=SecuritySchemeType.apiKey, alias="type")
    in_: APIKeyIn = Field(alias="in")
    name: str


class OAuth2FlowIn(Enum):
    implicit = "implicit"
    password = "password"
    application = "application"
    accessCode = "accessCode"


class OAuth2FlowBase(SecurityBase):
    flow: OAuth2FlowIn
    scopes: Dict[str, str] = {}

    model_config = {"extra": "allow"}


class OAuth2Implicit(OAuth2FlowBase):
    authorizationUrl: str


class OAuth2Password(OAuth2FlowBase):
    tokenUrl: str


class OAuth2Application(OAuth2FlowBase):
    tokenUrl: str


class OAuth2AccessCode(OAuth2FlowBase):
    authorizationUrl: str
    tokenUrl: str


SecurityScheme = Union[
    BasicAuth,
    APIKey,
    OAuth2Implicit,
    OAuth2Password,
    OAuth2Application,
    OAuth2AccessCode,
]


class Tag(BaseModel):
    name: str
    description: Optional[str] = None
    externalDocs: Optional[ExternalDocumentation] = None

    model_config = {"extra": "allow"}


class Swagger2(BaseModel):
    swagger: str
    info: Info
    host: Optional[str] = None  # URLHost
    basePath: Optional[str] = None  # URLBasePath
    schemes: Optional[List[URLSchemeEnum]] = None
    consumes: Optional[List[str]] = None
    produces: Optional[List[str]] = None
    paths: Dict[str, Union[PathItem, Any]]
    definitions: Optional[Dict[str, Union[Schema, Reference]]] = None
    parameters: Optional[
        Dict[str, Union[ParameterBody, ParameterNotBody, Reference]]
    ] = None
    responses: Optional[Dict[str, Union[Response, Reference]]] = None
    securityDefinitions: Optional[Dict[str, Union[SecurityScheme, Reference]]] = None
    security: Optional[List[Dict[str, List[str]]]] = None
    tags: Optional[List[Tag]] = None
    externalDocs: Optional[ExternalDocumentation] = None

    model_config = {"extra": "allow"}


_model_rebuild(Schema)
_model_rebuild(Operation)
# _model_rebuild(Encoding)
