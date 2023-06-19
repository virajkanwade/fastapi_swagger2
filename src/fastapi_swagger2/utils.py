import http.client
import inspect
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Type, Union, cast
from urllib.parse import ParseResult, urlparse

from fastapi import routing
from fastapi.datastructures import DefaultPlaceholder
from fastapi.dependencies.models import Dependant
from fastapi.dependencies.utils import get_flat_dependant, get_flat_params
from fastapi.encoders import jsonable_encoder
from fastapi.logger import logger
from fastapi.openapi.constants import METHODS_WITH_BODY
from fastapi.openapi.utils import (
    get_flat_models_from_routes,
    get_openapi_operation_metadata,
    status_code_ranges,
)
from fastapi.params import Body, Param
from fastapi.responses import Response
from fastapi.utils import deep_dict_update, is_body_allowed_for_status_code
from pydantic import BaseModel
from pydantic.fields import ModelField, Undefined
from pydantic.schema import field_schema, get_model_name_map, model_process_schema
from pydantic.utils import lenient_issubclass
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

from fastapi_swagger2.constants import REF_PREFIX
from fastapi_swagger2.models import Swagger2

validation_error_definition = {
    "title": "ValidationError",
    "type": "object",
    "properties": {
        "loc": {
            "title": "Location",
            "type": "array",
            "items": {"type": "string"},
        },
        "msg": {"title": "Message", "type": "string"},
        "type": {"title": "Error Type", "type": "string"},
    },
    "required": ["loc", "msg", "type"],
}

validation_error_response_definition = {
    "title": "HTTPValidationError",
    "type": "object",
    "properties": {
        "detail": {
            "title": "Detail",
            "type": "array",
            "items": {"$ref": REF_PREFIX + "ValidationError"},
        }
    },
}


def get_model_definitions(
    *,
    flat_models: Set[Union[Type[BaseModel], Type[Enum]]],
    model_name_map: Dict[Union[Type[BaseModel], Type[Enum]], str],
) -> Dict[str, Any]:
    definitions: Dict[str, Dict[str, Any]] = {}
    for model in flat_models:
        m_schema, m_definitions, m_nested_models = model_process_schema(
            model, model_name_map=model_name_map, ref_prefix=REF_PREFIX
        )
        definitions.update(m_definitions)
        model_name = model_name_map[model]
        if "description" in m_schema:
            m_schema["description"] = m_schema["description"].split("\f")[0]
        definitions[model_name] = m_schema
    return definitions


def get_swagger2_security_definitions(
    flat_dependant: Dependant,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    def _map_oauth2_flow(flow_key: str, flow: Dict[str, Any]) -> Dict[str, Any]:
        security_definition = {
            "type": "oauth2",
            "flow": flow_key,
            "scopes": flow["scopes"],
        }
        if "authorizationUrl" in flow:
            security_definition.update({"authorizationUrl": flow["authorizationUrl"]})
        if "tokenUrl" in flow:
            security_definition.update({"tokenUrl": flow["tokenUrl"]})

        return security_definition

    oauth2_flows_keys_map = {
        "implicit": "implicit",
        "password": "password",
        "clientCredentials": "application",
        "authorizationCode": "accessCode",
    }
    security_definitions = {}
    operation_security = []
    for security_requirement in flat_dependant.security_requirements:
        # fastapi.security.* which gets model from fastapi.openapi.models
        security_definition = jsonable_encoder(
            security_requirement.security_scheme.model,
            by_alias=True,
            exclude_none=True,
        )
        if security_definition["type"] == "http":
            if security_definition.get("scheme", "basic") == "basic":
                security_definition = {"type": "basic"}
            else:
                logger.warning(
                    f"fastapi_swagger2: Unable to handle security_definition: {security_definition}"
                )
        elif security_definition["type"] == "apiKey":
            pass
        elif security_definition["type"] == "oauth2":
            _security_definition = security_definition
            flows = security_definition["flows"]
            flows_keys = list(flows.keys())
            if len(flows_keys) >= 1:
                flow_key_3 = flows_keys[0]
                flow = flows[flow_key_3]
                security_definition = _map_oauth2_flow(
                    oauth2_flows_keys_map[flow_key_3], flow
                )

                for i in range(1, len(flows_keys)):
                    flow_key_3 = flows_keys[i]
                    flow = flows[flow_key_3]
                    flow_key_2 = oauth2_flows_keys_map[flow_key_3]
                    security_definition_1 = _map_oauth2_flow(flow_key_2, flow)
                    security_name = security_requirement.security_scheme.scheme_name
                    _security_name = security_name + "_" + flow_key_2
                    security_definitions[_security_name] = security_definition_1
                    operation_security.append(
                        {_security_name: security_requirement.scopes}
                    )
        else:
            logger.warning(
                f"fastapi_swagger2: Unable to handle security_definition: {security_definition}"
            )
        security_name = security_requirement.security_scheme.scheme_name
        security_definitions[security_name] = security_definition
        operation_security.append({security_name: security_requirement.scopes})
    return security_definitions, operation_security


def get_swagger2_operation_parameters(
    *,
    all_route_params: Sequence[ModelField],
    model_name_map: Dict[Union[Type[BaseModel], Type[Enum]], str],
) -> List[Dict[str, Any]]:
    parameters = []
    for param in all_route_params:
        field_info = param.field_info
        field_info = cast(Param, field_info)
        if not field_info.include_in_schema:
            continue
        parameter: Dict[str, Any] = {
            "name": param.alias,
            "in": field_info.in_.value,
            "required": param.required,
        }
        schema: Dict[str, Any] = field_schema(
            param, model_name_map=model_name_map, ref_prefix=REF_PREFIX
        )[0]
        if field_info.in_.value == "body":
            parameter["schema"] = schema
        else:
            parameter.update({k: v for (k, v) in schema.items() if k != "title"})
        if field_info.description:
            parameter["description"] = field_info.description
        if field_info.examples:
            parameter["examples"] = jsonable_encoder(field_info.examples)
        elif field_info.example != Undefined:
            parameter["example"] = jsonable_encoder(field_info.example)
        if field_info.deprecated:
            parameter["deprecated"] = field_info.deprecated
        parameters.append(parameter)
    return parameters


def get_swagger2_operation_request_body(
    *,
    body_field: Optional[ModelField],
    model_name_map: Dict[Union[Type[BaseModel], Type[Enum]], str],
) -> Optional[Dict[str, Any]]:
    if not body_field:
        return None
    assert isinstance(body_field, ModelField)
    body_schema, _, _ = field_schema(
        body_field, model_name_map=model_name_map, ref_prefix=REF_PREFIX
    )
    field_info = cast(Body, body_field.field_info)
    # request_media_type = field_info.media_type
    required = body_field.required
    request_body_oai: Dict[str, Any] = {}
    request_body_oai["name"] = body_field.alias
    request_body_oai["in"] = "body"
    if required:
        request_body_oai["required"] = required

    request_media_content: Dict[str, Any] = {"schema": body_schema}
    if field_info.examples:
        request_media_content["examples"] = jsonable_encoder(field_info.examples)
    elif field_info.example != Undefined:
        request_media_content["example"] = jsonable_encoder(field_info.example)
    # request_body_oai["content"] = {request_media_type: request_media_content}
    request_body_oai.update(request_media_content)
    return request_body_oai


def get_swagger2_path(
    *, route: routing.APIRoute, model_name_map: Dict[type, str], operation_ids: Set[str]
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    path: Dict[str, Any] = {}
    security_schemes: Dict[str, Any] = {}
    definitions: Dict[str, Any] = {}
    assert route.methods is not None, "Methods must be a list"

    if isinstance(route.response_class, DefaultPlaceholder):
        current_response_class: Type[Response] = route.response_class.value
    else:
        current_response_class = route.response_class
    assert current_response_class, "A response class is needed to generate Swagger"

    route_response_media_type: Optional[str] = current_response_class.media_type
    if route.include_in_schema:
        for method in route.methods:
            operation = get_openapi_operation_metadata(
                route=route, method=method, operation_ids=operation_ids
            )

            parameters: List[Dict[str, Any]] = []
            flat_dependant = get_flat_dependant(route.dependant, skip_repeats=True)
            (
                security_definitions,
                operation_security,
            ) = get_swagger2_security_definitions(flat_dependant=flat_dependant)

            if operation_security:
                operation.setdefault("security", []).extend(operation_security)

            if security_definitions:
                security_schemes.update(security_definitions)

            all_route_params = get_flat_params(route.dependant)
            operation_parameters = get_swagger2_operation_parameters(
                all_route_params=all_route_params, model_name_map=model_name_map
            )
            parameters.extend(operation_parameters)
            if parameters:
                all_parameters = {
                    (param["in"], param["name"]): param for param in parameters
                }
                required_parameters = {
                    (param["in"], param["name"]): param
                    for param in parameters
                    if param.get("required")
                }
                # Make sure required definitions of the same parameter take precedence
                # over non-required definitions
                all_parameters.update(required_parameters)

                if method in METHODS_WITH_BODY:
                    request_body_oai = get_swagger2_operation_request_body(
                        body_field=route.body_field, model_name_map=model_name_map
                    )
                    if request_body_oai:
                        all_parameters.update({("body", "body"): request_body_oai})

                operation["parameters"] = list(all_parameters.values())

            if route.callbacks:
                callbacks = {}
                for callback in route.callbacks:
                    if isinstance(callback, routing.APIRoute):
                        (
                            cb_path,
                            cb_security_schemes,
                            cb_definitions,
                        ) = get_swagger2_path(
                            route=callback,
                            model_name_map=model_name_map,
                            operation_ids=operation_ids,
                        )
                        callbacks[callback.name] = {callback.path: cb_path}
                operation["callbacks"] = callbacks

            if route.status_code is not None:
                status_code = str(route.status_code)
            else:
                # It would probably make more sense for all response classes to have an
                # explicit default status_code, and to extract it from them, instead of
                # doing this inspection tricks, that would probably be in the future
                # TODO: probably make status_code a default class attribute for all
                # responses in Starlette
                response_signature = inspect.signature(current_response_class.__init__)
                status_code_param = response_signature.parameters.get("status_code")
                if status_code_param is not None:
                    if isinstance(status_code_param.default, int):
                        status_code = str(status_code_param.default)
            operation.setdefault("responses", {}).setdefault(status_code, {})[
                "description"
            ] = route.response_description

            if route_response_media_type and is_body_allowed_for_status_code(
                route.status_code
            ):
                response_schema = {"type": "string"}
                if lenient_issubclass(current_response_class, JSONResponse):
                    if route.response_field:
                        response_schema, _, _ = field_schema(
                            route.response_field,
                            model_name_map=model_name_map,
                            ref_prefix=REF_PREFIX,
                        )
                    else:
                        response_schema = {}
                operation.setdefault("responses", {}).setdefault(status_code, {})[
                    "schema"
                ] = response_schema
                operation.setdefault("produces", []).append(route_response_media_type)

            if route.responses:
                operation_responses = operation.setdefault("responses", {})
                for (
                    additional_status_code,
                    additional_response,
                ) in route.responses.items():
                    process_response = additional_response.copy()
                    process_response.pop("model", None)
                    status_code_key = str(additional_status_code).upper()
                    if status_code_key == "DEFAULT":
                        status_code_key = "default"
                    openapi_response = operation_responses.setdefault(
                        status_code_key, {}
                    )
                    assert isinstance(
                        process_response, dict
                    ), "An additional response must be a dict"
                    field = route.response_fields.get(additional_status_code)
                    additional_field_schema: Optional[Dict[str, Any]] = None
                    if field:
                        additional_field_schema, _, _ = field_schema(
                            field, model_name_map=model_name_map, ref_prefix=REF_PREFIX
                        )
                        # media_type = route_response_media_type or "application/json"
                        additional_schema = process_response.setdefault("schema", {})
                        deep_dict_update(additional_schema, additional_field_schema)
                    status_text: Optional[str] = status_code_ranges.get(
                        str(additional_status_code).upper()
                    ) or http.client.responses.get(int(additional_status_code))
                    description = (
                        process_response.get("description")
                        or openapi_response.get("description")
                        or status_text
                        or "Additional Response"
                    )
                    deep_dict_update(openapi_response, process_response)
                    openapi_response["description"] = description

            http422 = str(HTTP_422_UNPROCESSABLE_ENTITY)
            if (all_route_params or route.body_field) and not any(
                status in operation["responses"]
                for status in [http422, "4XX", "default"]
            ):
                operation["responses"][http422] = {
                    "description": "Validation Error",
                    "schema": {"$ref": REF_PREFIX + "HTTPValidationError"},
                }
                if "ValidationError" not in definitions:
                    definitions.update(
                        {
                            "ValidationError": validation_error_definition,
                            "HTTPValidationError": validation_error_response_definition,
                        }
                    )
            if route.openapi_extra:
                deep_dict_update(operation, route.openapi_extra)
            path[method.lower()] = operation

    return path, security_schemes, definitions


def get_swagger2(
    *,
    title: str,
    version: str,
    swagger2_version: str = "2.0",
    description: Optional[str] = None,
    routes: Sequence[BaseRoute],
    tags: Optional[List[Dict[str, Any]]] = None,
    server: Optional[str] = None,
    terms_of_service: Optional[str] = None,
    contact: Optional[Dict[str, Union[str, Any]]] = None,
    license_info: Optional[Dict[str, Union[str, Any]]] = None,
) -> Dict[str, Any]:
    info: Dict[str, Any] = {"title": title, "version": version}
    if description:
        info["description"] = description
    if terms_of_service:
        info["termsOfService"] = terms_of_service
    if contact:
        info["contact"] = contact
    if license_info:
        info["license"] = license_info

    output: Dict[str, Any] = {"swagger": swagger2_version, "info": info}

    if server:
        pr: ParseResult = urlparse(server)
        output["host"] = pr.netloc
        output["basePath"] = pr.path or "/"
        output.setdefault("schemes", []).append(pr.scheme)

    paths: Dict[str, Dict[str, Any]] = {}
    operation_ids: Set[str] = set()

    flat_models = get_flat_models_from_routes(routes)
    model_name_map = get_model_name_map(flat_models)
    definitions = get_model_definitions(
        flat_models=flat_models, model_name_map=model_name_map
    )

    for route in routes:
        if isinstance(route, routing.APIRoute):
            result = get_swagger2_path(
                route=route, model_name_map=model_name_map, operation_ids=operation_ids
            )
            if result:
                path, security_schemes, path_definitions = result

                if path:
                    paths.setdefault(route.path_format, {}).update(path)

                if security_schemes:
                    output.setdefault("securityDefinitions", {}).update(
                        security_schemes
                    )

                if path_definitions:
                    definitions.update(path_definitions)

    output["paths"] = paths

    if definitions:
        output["definitions"] = {k: definitions[k] for k in sorted(definitions)}

    if tags:
        output["tags"] = tags

    return jsonable_encoder(Swagger2(**output), by_alias=True, exclude_none=True)  # type: ignore
