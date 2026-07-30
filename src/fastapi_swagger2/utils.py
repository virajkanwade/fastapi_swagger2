import http.client
import inspect
from collections.abc import Sequence
from typing import Any, cast

from fastapi import routing
from fastapi._compat import (
    ModelField,
    get_definitions,
    get_flat_models_from_fields,
    get_model_name_map,
    get_schema_from_model_field,
    lenient_issubclass,
)
from fastapi.datastructures import DefaultPlaceholder
from fastapi.dependencies.models import (
    Dependant,
    _get_oauth_scopes,
    _get_security_dependencies,
    _get_security_scheme,
)
from fastapi.dependencies.utils import (
    get_flat_dependant,
    get_flat_params,
)
from fastapi.encoders import jsonable_encoder
from fastapi.logger import logger
from fastapi.openapi.constants import METHODS_WITH_BODY
from fastapi.openapi.utils import (
    _get_api_route_for_openapi,
    _get_flat_fields_from_params,
    _get_openapi_operation_parameters,
    get_fields_from_routes,
    get_openapi_operation_metadata,
    get_openapi_operation_request_body,
    status_code_ranges,
    validation_error_response_definition,
)
from fastapi.responses import Response
from fastapi.types import ModelNameMap
from fastapi.utils import deep_dict_update, is_body_allowed_for_status_code
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute
from typing_extensions import Literal

from .models import Swagger2

validation_error_definition = {
    "title": "ValidationError",
    "type": "object",
    "properties": {
        "loc": {
            "title": "Location",
            "type": "array",
            "items": {"type": "string", "description": "Location path (string or integer)"},
        },
        "msg": {"title": "Message", "type": "string"},
        "type": {"title": "Error Type", "type": "string"},
    },
    "required": ["loc", "msg", "type"],
}


def _process_definitions_properties(definition: dict[str, Any]) -> dict[str, Any]:
    properties = definition.get("properties", [])
    for p in properties:
        if "anyOf" not in properties[p]:
            continue

        any_of = properties[p].pop("anyOf")

        if not any_of:  # Handle empty case first
            properties[p]["type"] = "string"
            logger.warning("fastapi_swagger2: Empty anyOf in definitions, defaulting to string type.")
            continue

        if len(any_of) == 1:
            # Single item - just use it directly
            properties[p].update(any_of[0])
            continue

        if len(any_of) == 2:
            # Handle the 2-item case (type + null)
            null_item = {"type": "null"}
            if null_item in any_of:
                other_item = any_of[0] if any_of[1] == null_item else any_of[1]

                if "$ref" in other_item:
                    properties[p]["allOf"] = [other_item]
                else:
                    properties[p].update(other_item)

                properties[p]["x-nullable"] = True
                continue

        # Fallback for complex anyOf cases (len > 2)
        properties[p]["type"] = "string"
        logger.warning(f"fastapi_swagger2: Unable to handle anyOf in definitions {any_of}, defaulting to string type.")

    return definition


def _convert_refs_to_swagger2(obj: Any) -> Any:
    """Recursively convert all $ref from OpenAPI 3.0 to Swagger 2.0 format"""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k == "$ref" and isinstance(v, str):
                # Convert #/components/schemas/Model to #/definitions/Model
                result[k] = v.replace("#/components/schemas/", "#/definitions/")
            else:
                result[k] = _convert_refs_to_swagger2(v)
        return result
    elif isinstance(obj, list):
        return [_convert_refs_to_swagger2(item) for item in obj]
    else:
        return obj


def _resolve_parameter_refs(output: dict[str, Any], definitions: dict[str, Any]) -> dict[str, Any]:
    """Resolve $ref in parameters by inlining the referenced schema properties"""
    if "paths" in output:
        for path_data in output["paths"].values():
            for operation in path_data.values():
                if isinstance(operation, dict) and "parameters" in operation:
                    for param in operation["parameters"]:
                        if param.get("in") == "body":
                            continue

                        ref_name = None

                        # Handle direct $ref (Pydantic v2)
                        if "$ref" in param:
                            ref_name = param.pop("$ref").split("/")[-1]

                        # Handle allOf with $ref (Pydantic v1)
                        elif "allOf" in param:
                            all_of = param.pop("allOf")
                            if all_of and "$ref" in all_of[0]:
                                ref_name = all_of[0]["$ref"].split("/")[-1]

                        # Apply the resolved definition
                        if ref_name and ref_name in definitions:
                            definition = definitions[ref_name]
                            param.update({k: v for k, v in definition.items() if k != "title"})

    return output


def _map_oauth2_flow(flow_key: str, flow: dict[str, Any]) -> dict[str, Any]:
    security_definition = {
        "type": "oauth2",
        "flow": flow_key,
        "scopes": flow["scopes"],
    }

    security_definition.update({k: v for k, v in flow.items() if k in ["authorizationUrl", "tokenUrl"]})

    return security_definition


def _flatten_parameter_schemas(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert OpenAPI 3.0 parameter format to Swagger 2.0 format"""
    for param in parameters:
        if "schema" in param and param.get("in") != "body":
            schema = param.pop("schema")
            param.update({k: v for k, v in schema.items() if k != "title"})

    return parameters


def _flatten_headers_schema(process_response: dict[str, Any]) -> dict[str, Any]:
    """Flatten OpenAPI 3.0 header schema to Swagger 2.0 format"""
    if "headers" in process_response:
        for header_info in process_response["headers"].values():
            schema = header_info.pop("schema", None)
            if schema:
                header_info.update(schema)

    return process_response


def _convert_request_body_to_body_param(request_body: dict[str, Any], body_field: ModelField) -> dict[str, Any]:
    """Convert OpenAPI 3.0 requestBody to Swagger 2.0 body parameter"""
    # Extract schema from content
    content = request_body["content"]
    media_type = next(iter(content.keys()))  # Get first media type
    schema = content[media_type]["schema"]

    body_param = {
        "name": body_field.alias,
        "in": "body",
        "required": request_body.get("required", False),
    }

    if "$ref" in schema:
        body_param["schema"] = {"$ref": schema["$ref"]}
        body_param.update({k: v for (k, v) in schema.items() if k != "$ref"})
    else:
        body_param["schema"] = schema

    # Add example if present
    if "example" in content[media_type]:
        body_param["example"] = content[media_type]["example"]

    return body_param


def get_swagger2_security_definitions(
    flat_dependant: Dependant,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    oauth2_flows_keys_map = {
        "implicit": "implicit",
        "password": "password",
        "clientCredentials": "application",
        "authorizationCode": "accessCode",
    }

    security_definitions = {}
    # Use a dict to merge scopes for same security scheme
    operation_security_dict: dict[str, list[str]] = {}
    for security_dependency in _get_security_dependencies(dependant=flat_dependant):
        security_scheme = _get_security_scheme(dependant=security_dependency)
        security_definition = jsonable_encoder(
            security_scheme.model,
            by_alias=True,
            exclude_none=True,
        )

        # swagger2 logic - start
        if security_definition["type"] == "apiKey":
            ...
        elif security_definition["type"] == "http":
            if security_definition.get("scheme", "basic") == "basic":
                security_definition = {"type": "basic"}
            elif security_definition.get("scheme") == "bearer":
                security_definition = {"type": "apiKey", "name": "Authorization", "in": "header"}
            else:
                logger.warning(f"fastapi_swagger2: Unable to handle security_definition: {security_definition}")
                continue
        elif security_definition["type"] == "oauth2":
            flows = security_definition["flows"]

            if not flows:
                continue

            security_name = security_scheme.scheme_name

            for flow_key, flow_data in flows.items():
                swagger2_flow_key = oauth2_flows_keys_map.get(flow_key)
                if not swagger2_flow_key:
                    logger.warning(f"fastapi_swagger2: Unsupported OAuth2 flow '{flow_key}', skipping")
                    continue

                mapped_security = _map_oauth2_flow(swagger2_flow_key, flow_data)

                suffixed_name = f"{security_name}_{swagger2_flow_key}"
                security_definitions[suffixed_name] = mapped_security
                for scope in _get_oauth_scopes(dependant=security_dependency):
                    if scope not in operation_security_dict.setdefault(suffixed_name, []):
                        operation_security_dict[suffixed_name].append(scope)

            continue
        # swagger2 logic - end

        security_name = security_scheme.scheme_name
        security_definitions[security_name] = security_definition
        # Merge scopes for the same security scheme
        if security_name not in operation_security_dict:
            operation_security_dict[security_name] = []
        for scope in _get_oauth_scopes(dependant=security_dependency):
            if scope not in operation_security_dict[security_name]:
                operation_security_dict[security_name].append(scope)
    operation_security = [{name: scopes} for name, scopes in operation_security_dict.items()]
    return security_definitions, operation_security


def get_swagger2_path(
    *,
    route: routing._APIRouteLike,
    operation_ids: set[str],
    model_name_map: ModelNameMap,
    field_mapping: dict[tuple[ModelField, Literal["validation", "serialization"]], dict[str, Any]],
    separate_input_output_schemas: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    path: dict[str, Any] = {}
    security_schemes: dict[str, Any] = {}
    definitions: dict[str, Any] = {}
    assert route.methods is not None, "Methods must be a list"

    if isinstance(route.response_class, DefaultPlaceholder):
        current_response_class: type[Response] = route.response_class.value
    else:
        current_response_class = route.response_class
    assert current_response_class, "A response class is needed to generate Swagger2"

    route_response_media_type: str | None = current_response_class.media_type

    if route.include_in_schema:
        flat_dependant = get_flat_dependant(route.dependant, skip_repeats=True)
        all_route_params = [
            field
            for fields in (
                flat_dependant.path_params,
                flat_dependant.query_params,
                flat_dependant.header_params,
                flat_dependant.cookie_params,
            )
            for field in _get_flat_fields_from_params(fields)
        ]
        for method in route.methods:
            operation = get_openapi_operation_metadata(route=route, method=method, operation_ids=operation_ids)

            parameters: list[dict[str, Any]] = []
            all_parameters = {}

            security_definitions, operation_security = get_swagger2_security_definitions(flat_dependant=flat_dependant)

            if operation_security:
                operation.setdefault("security", []).extend(operation_security)

            if security_definitions:
                security_schemes.update(security_definitions)

            operation_parameters = _get_openapi_operation_parameters(
                flat_dependant=flat_dependant,
                model_name_map=model_name_map,
                field_mapping=field_mapping,
                separate_input_output_schemas=separate_input_output_schemas,
            )

            operation_parameters = _flatten_parameter_schemas(operation_parameters)

            parameters.extend(operation_parameters)

            if parameters:
                all_parameters = {(param["in"], param["name"]): param for param in parameters}
                required_parameters = {
                    (param["in"], param["name"]): param for param in parameters if param.get("required")
                }
                # Make sure required definitions of the same parameter take precedence
                # over non-required definitions
                all_parameters.update(required_parameters)

            if method in METHODS_WITH_BODY:
                request_body_oai = get_openapi_operation_request_body(
                    body_field=route.body_field,
                    model_name_map=model_name_map,
                    field_mapping=field_mapping,
                    separate_input_output_schemas=separate_input_output_schemas,
                )
                if request_body_oai:
                    if route.body_field:
                        body_param = _convert_request_body_to_body_param(request_body_oai, route.body_field)
                    else:
                        # Use request_body_oai as-is if no body_field (shouldn't normally happen)
                        body_param = request_body_oai
                    all_parameters.update({("body", "body"): body_param})

            if all_parameters:
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
                            route=cast(routing._APIRouteLike, callback),
                            operation_ids=operation_ids,
                            model_name_map=model_name_map,
                            field_mapping=field_mapping,
                            separate_input_output_schemas=separate_input_output_schemas,
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

            operation.setdefault("responses", {}).setdefault(status_code, {})["description"] = (
                route.response_description
            )

            if route_response_media_type and is_body_allowed_for_status_code(route.status_code):
                response_schema = {"type": "string"}
                if lenient_issubclass(current_response_class, JSONResponse):
                    if route.response_field:
                        response_schema = get_schema_from_model_field(
                            field=route.response_field,
                            model_name_map=model_name_map,
                            field_mapping=field_mapping,
                            separate_input_output_schemas=separate_input_output_schemas,
                        )
                    else:
                        response_schema = {}
                operation.setdefault("responses", {}).setdefault(status_code, {})["schema"] = response_schema
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
                    swagger2_response = operation_responses.setdefault(status_code_key, {})
                    assert isinstance(process_response, dict), "An additional response must be a dict"

                    process_response = _flatten_headers_schema(process_response)

                    field = route.response_fields.get(additional_status_code)
                    additional_field_schema: dict[str, Any] | None = None
                    if field:
                        additional_field_schema = get_schema_from_model_field(
                            field=field,
                            model_name_map=model_name_map,
                            field_mapping=field_mapping,
                            separate_input_output_schemas=separate_input_output_schemas,
                        )
                        media_type = route_response_media_type or "application/json"
                        additional_schema = process_response.setdefault("schema", {})
                        if media_type not in operation.setdefault("produces", []):
                            operation["produces"].append(media_type)
                        deep_dict_update(additional_schema, additional_field_schema)
                    status_text: str | None = status_code_ranges.get(
                        str(additional_status_code).upper()
                    ) or http.client.responses.get(int(additional_status_code))
                    description = (
                        process_response.get("description")
                        or swagger2_response.get("description")
                        or status_text
                        or "Additional Response"
                    )
                    deep_dict_update(swagger2_response, process_response)
                    swagger2_response["description"] = description

            http422 = "422"
            all_route_params = get_flat_params(route.dependant)
            if (all_route_params or route.body_field) and not any(
                status in operation["responses"] for status in [http422, "4XX", "default"]
            ):
                operation["responses"][http422] = {
                    "description": "Validation Error",
                    "schema": {"$ref": "#/definitions/HTTPValidationError"},
                }
                media_type = "application/json"
                if media_type not in operation.setdefault("produces", []):
                    operation["produces"].append(media_type)
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
    summary: str | None = None,
    description: str | None = None,
    routes: Sequence[BaseRoute | routing.RouteContext],
    webhooks: Sequence[BaseRoute | routing.RouteContext] | None = None,
    tags: list[dict[str, Any]] | None = None,
    servers: list[dict[str, str | Any]] | None = None,
    terms_of_service: str | None = None,
    contact: dict[str, str | Any] | None = None,
    license_info: dict[str, str | Any] | None = None,
    separate_input_output_schemas: bool = True,
    external_docs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    info: dict[str, Any] = {"title": title, "version": version}
    if summary:
        info["summary"] = summary
    if description:
        info["description"] = description
    if terms_of_service:
        info["termsOfService"] = terms_of_service
    if contact:
        info["contact"] = contact
    if license_info:
        info["license"] = license_info
    output: dict[str, Any] = {"swagger": swagger2_version, "info": info}
    if servers:
        output["servers"] = servers

    paths: dict[str, dict[str, Any]] = {}
    webhook_paths: dict[str, dict[str, Any]] = {}
    operation_ids: set[str] = set()

    all_fields = get_fields_from_routes(list(routes) + list(webhooks or []))
    flat_models = get_flat_models_from_fields(all_fields, known_models=set())
    model_name_map = get_model_name_map(flat_models)
    field_mapping, definitions = get_definitions(
        fields=all_fields,
        model_name_map=model_name_map,
        separate_input_output_schemas=separate_input_output_schemas,
    )

    for route_context in routing.iter_route_contexts(routes):
        api_route = _get_api_route_for_openapi(route_context)
        if api_route is not None:
            result = get_swagger2_path(
                route=api_route,
                operation_ids=operation_ids,
                model_name_map=model_name_map,
                field_mapping=field_mapping,
                separate_input_output_schemas=separate_input_output_schemas,
            )
            if result:
                path, security_schemes, path_definitions = result

                if path:
                    paths.setdefault(api_route.path_format, {}).update(path)

                if security_schemes:
                    output.setdefault("securityDefinitions", {}).update(security_schemes)

                if path_definitions:
                    definitions.update(path_definitions)

    if definitions:
        output["definitions"] = {k: _process_definitions_properties(definitions[k]) for k in sorted(definitions)}
    output["paths"] = paths
    if webhook_paths:
        output["webhooks"] = webhook_paths
    if tags:
        output["tags"] = tags
    if external_docs:
        output["externalDocs"] = external_docs

    output = _convert_refs_to_swagger2(output)

    output = _resolve_parameter_refs(output, definitions)

    return jsonable_encoder(Swagger2(**output), by_alias=True, exclude_none=True)
