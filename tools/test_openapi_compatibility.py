#!/usr/bin/env python3
import copy
import unittest

from check_openapi_compatibility import compare


class CompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = {
            "paths": {
                "/v1/fixture": {
                    "get": {
                        "parameters": [],
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/Fixture"}
                                    }
                                }
                            }
                        },
                    }
                }
            },
            "components": {
                "schemas": {
                    "Fixture": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string"},
                            "label": {"type": ["string", "null"]},
                        },
                    }
                }
            },
        }

    def test_response_field_removal_is_breaking(self) -> None:
        current = copy.deepcopy(self.contract)
        del current["components"]["schemas"]["Fixture"]["properties"]["label"]
        self.assertTrue(compare(self.contract, current))

    def test_response_field_type_change_is_breaking(self) -> None:
        current = copy.deepcopy(self.contract)
        current["components"]["schemas"]["Fixture"]["properties"]["id"]["type"] = "integer"
        self.assertTrue(compare(self.contract, current))

    def test_optional_response_field_addition_is_compatible(self) -> None:
        current = copy.deepcopy(self.contract)
        current["components"]["schemas"]["Fixture"]["properties"]["detail"] = {
            "type": "string"
        }
        self.assertEqual(compare(self.contract, current), [])

    def test_new_required_request_parameter_is_breaking(self) -> None:
        current = copy.deepcopy(self.contract)
        current["paths"]["/v1/fixture"]["get"]["parameters"].append(
            {"in": "query", "name": "cursor", "required": True}
        )
        self.assertTrue(compare(self.contract, current))


if __name__ == "__main__":
    unittest.main()
