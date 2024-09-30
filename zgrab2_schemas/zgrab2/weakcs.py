# zschema sub-schema for zgrab2's banner module
# Registers zgrab2-banner globally, and banner with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

# modules/weakcs/scanner.go - Results
weakcs_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "weak_protocol": Boolean(),
                "weak_ciphersuite": Boolean(),
                "protocol_version": String(),
                "weak_supported_cipher_list": ListOf(String()),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-weakcs", weakcs_scan_response)

zgrab2.register_scan_response_type("weakcs", weakcs_scan_response)
