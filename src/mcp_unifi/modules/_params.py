"""Reusable length-bounded string parameter types for tool signatures.

FastMCP derives each tool's JSON input schema from its function signature, so
annotating a parameter as ``Annotated[str, Field(max_length=N)]`` publishes a
``maxLength`` constraint in the tool's input schema. That bounds free-text and
secret inputs before they reach the UniFi controller: an unbounded ``name`` or
``passphrase`` would otherwise be forwarded verbatim, and a multi-kilobyte
value could trigger upstream truncation or errors. The docstring-derived
parameter description is preserved alongside the constraint.

Bounds are deliberately generous (they only reject clearly-junk oversized
input), so they never break a legitimate call. Identifier-style params
(``*_id``, ``mac``, ``controller``) are intentionally not bounded here: they are
structurally validated downstream (registry lookup, path resolution) and are not
free text stored on the controller.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

# Short human labels stored on the controller (network/WLAN/rule/profile names,
# network purpose). Generous cap well above any real UniFi name length.
BoundedName = Annotated[str, Field(max_length=128)]

# WLAN SSID. 802.11 caps the SSID element at 32 octets.
BoundedSsid = Annotated[str, Field(max_length=32)]

# Secrets: WPA passphrases, Dynamic DNS passwords. WPA2-PSK maxes at 63 chars;
# the headroom covers WPA3/enterprise-style longer secrets.
BoundedSecret = Annotated[str, Field(max_length=128)]

# Hostnames, FQDNs, DNS records, and provider update URLs. DNS names cap at 253.
BoundedHostname = Annotated[str, Field(max_length=253)]

# General short free text (reasons, provider logins, schedule expressions).
BoundedText = Annotated[str, Field(max_length=256)]

# A declared desired-state YAML spec passed to the drift auditor. Large by
# design, but still bounded so a runaway blob is rejected at the schema.
BoundedYaml = Annotated[str, Field(max_length=200_000)]

# A full config-backup JSON blob passed to the restore tool. Bounded high.
BoundedJson = Annotated[str, Field(max_length=5_000_000)]

__all__ = [
    "BoundedHostname",
    "BoundedJson",
    "BoundedName",
    "BoundedSecret",
    "BoundedSsid",
    "BoundedText",
    "BoundedYaml",
]
