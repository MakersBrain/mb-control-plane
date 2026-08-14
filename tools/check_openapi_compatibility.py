#!/usr/bin/env python3
"""Reject unclassified breaking changes to the released public API contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def load(path: str) -> dict:
    with Path(path).open() as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: OpenAPI root must be an object")
    return value


def parameters(operation: dict) -> dict[tuple[str, str], dict]:
    return {
        (parameter.get("in", ""), parameter.get("name", "")): parameter
        for parameter in operation.get("parameters", [])
        if isinstance(parameter, dict)
    }


def compare_schema(path: str, old: object, new: object, errors: list[str]) -> None:
    if not isinstance(old, dict) or not isinstance(new, dict):
        return
    old_types = old.get("type")
    new_types = new.get("type")
    if old_types is not None and new_types is not None and old_types != new_types:
        errors.append(f"{path}: schema type changed from {old_types!r} to {new_types!r}")
    old_properties = old.get("properties", {})
    new_properties = new.get("properties", {})
    if isinstance(old_properties, dict) and isinstance(new_properties, dict):
        for name, schema in old_properties.items():
            if name not in new_properties:
                errors.append(f"{path}: response/schema property {name!r} was removed")
            else:
                compare_schema(f"{path}.{name}", schema, new_properties[name], errors)
    old_required = set(old.get("required", []))
    new_required = set(new.get("required", []))
    if not old_required.issuperset(new_required):
        errors.append(f"{path}: new required properties were added: {sorted(new_required-old_required)}")


def compare(old: dict, new: dict) -> list[str]:
    errors: list[str] = []
    old_paths = old.get("paths", {})
    new_paths = new.get("paths", {})
    for path, old_item in old_paths.items():
        if path not in new_paths:
            errors.append(f"public path removed: {path}")
            continue
        for method, old_operation in old_item.items():
            if method not in HTTP_METHODS:
                continue
            new_operation = new_paths[path].get(method)
            if new_operation is None:
                errors.append(f"public operation removed: {method.upper()} {path}")
                continue
            old_parameters = parameters(old_operation)
            new_parameters = parameters(new_operation)
            for key, parameter in new_parameters.items():
                if parameter.get("required") and key not in old_parameters:
                    errors.append(f"{method.upper()} {path}: new required {key[0]} parameter {key[1]}")
            old_responses = old_operation.get("responses", {})
            new_responses = new_operation.get("responses", {})
            for status, response in old_responses.items():
                if status.startswith("2") and status not in new_responses:
                    errors.append(f"{method.upper()} {path}: successful response {status} was removed")
                    continue
                old_schema = response.get("content", {}).get("application/json", {}).get("schema", {})
                new_schema = new_responses.get(status, {}).get("content", {}).get("application/json", {}).get("schema", {})
                compare_schema(f"{method.upper()} {path} {status}", old_schema, new_schema, errors)
    old_schemas = old.get("components", {}).get("schemas", {})
    new_schemas = new.get("components", {}).get("schemas", {})
    for name, schema in old_schemas.items():
        if name not in new_schemas:
            errors.append(f"component schema removed: {name}")
        else:
            compare_schema(f"components.schemas.{name}", schema, new_schemas[name], errors)
    return errors


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_openapi_compatibility.py BASELINE CURRENT", file=sys.stderr)
        return 2
    errors = compare(load(sys.argv[1]), load(sys.argv[2]))
    for error in errors:
        print(f"breaking OpenAPI change: {error}", file=sys.stderr)
    if errors:
        print("classify the break by publishing a new API version; do not overwrite the v1 baseline", file=sys.stderr)
        return 1
    print("public OpenAPI is backward compatible with the released baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
