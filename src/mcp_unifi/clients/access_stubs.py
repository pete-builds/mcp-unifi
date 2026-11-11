"""Realistic stub responses for the UniFi Access API.

Used when ``stub_mode=True``. Payload shapes mirror what UniFi Access returns
for the ``/proxy/access/api/v2`` endpoints exercised by the Access MCP tools.

Each :class:`AccessStubState` instance is fully independent so tests and
controllers in stub mode have isolated state, matching the per-controller
pattern used by :class:`StubState` and :class:`ProtectStubState`.
"""

from __future__ import annotations

import copy
import time
import uuid
from collections import defaultdict, deque

from mcp_unifi.clients.ids import path_segment
from mcp_unifi.models import UniFiRecord


def _oid() -> str:
    """24-character hex string in the shape of a Mongo ObjectId."""
    return uuid.uuid4().hex[:24]


def _ts_ms() -> int:
    """Current epoch milliseconds (Access uses ms timestamps everywhere)."""
    return int(time.time() * 1000)


# Stable IDs used across the seeded fixtures so tests that look up by ID
# (e.g. tests/access/test_credentials.py) can rely on cross-reference shape
# without first calling list_*.
_USER_ALICE_ID = "11111111111111111111aaaa"
_USER_BOB_ID = "22222222222222222222bbbb"
_USER_CAROL_ID = "33333333333333333333cccc"


def _seed_users() -> list[UniFiRecord]:
    return [
        {
            "id": _USER_ALICE_ID,
            "first_name": "Alice",
            "last_name": "Admin",
            "full_name": "Alice Admin",
            "email": "alice@example.com",
            "status": "active",
            "employee_number": "E001",
            "credential_ids": [],
        },
        {
            "id": _USER_BOB_ID,
            "first_name": "Bob",
            "last_name": "Builder",
            "full_name": "Bob Builder",
            "email": "bob@example.com",
            "status": "active",
            "employee_number": "E002",
            "credential_ids": [],
        },
        {
            "id": _USER_CAROL_ID,
            "first_name": "Carol",
            "last_name": "Contractor",
            "full_name": "Carol Contractor",
            "email": "carol@example.com",
            "status": "active",
            "employee_number": "E003",
            "credential_ids": [],
        },
    ]


def _seed_doors() -> list[UniFiRecord]:
    now = _ts_ms()
    return [
        {
            "id": _oid(),
            "name": "Main Entrance",
            "type": "door",
            "location": "Lobby",
            "hub_id": "",  # populated in __init__ after the hub seeds
            "locked": True,
            "online": True,
            "last_activity": now - 60_000,
            "door_position_status": "closed",
            "lock_status": "locked",
        },
        {
            "id": _oid(),
            "name": "Server Room",
            "type": "door",
            "location": "Basement",
            "hub_id": "",
            "locked": True,
            "online": True,
            "last_activity": now - 3_600_000,
            "door_position_status": "closed",
            "lock_status": "locked",
        },
    ]


def _seed_door_groups(doors: list[UniFiRecord]) -> list[UniFiRecord]:
    return [
        {
            "id": _oid(),
            "name": "All Doors",
            "door_ids": [d["id"] for d in doors],
            "description": "Default group containing every door.",
        }
    ]


def _seed_devices(doors: list[UniFiRecord]) -> tuple[list[UniFiRecord], str]:
    """Return ``(devices, hub_id)``. ``hub_id`` is back-filled onto each door."""
    hub_id = _oid()
    reader1_id = _oid()
    reader2_id = _oid()
    devices: list[UniFiRecord] = [
        {
            "id": hub_id,
            "type": "hub",
            "model": "UAH",
            "name": "Main Hub",
            "mac": "f4:e2:c6:00:0a:01",
            "ip": "192.168.1.20",
            "online": True,
            "firmware_version": "1.10.42",
            "status": "online",
        },
        {
            "id": reader1_id,
            "type": "reader",
            "model": "UA-G2-Pro",
            "name": "Main Entrance Reader",
            "mac": "f4:e2:c6:00:0a:02",
            "ip": "192.168.1.21",
            "online": True,
            "firmware_version": "1.5.7",
            "status": "online",
            "door_id": doors[0]["id"],
            "hub_id": hub_id,
        },
        {
            "id": reader2_id,
            "type": "reader",
            "model": "UA-G2",
            "name": "Server Room Reader",
            "mac": "f4:e2:c6:00:0a:03",
            "ip": "192.168.1.22",
            "online": True,
            "firmware_version": "1.5.7",
            "status": "online",
            "door_id": doors[1]["id"],
            "hub_id": hub_id,
        },
    ]
    return devices, hub_id


def _seed_credentials() -> list[UniFiRecord]:
    """Three credentials of mixed types with deterministic expiry windows.

    The first credential expires in 5 days (well inside the 30-day default
    that ``audit_expiring_credentials`` surfaces), the second in 90 days, the
    third has no expiry. Tests rely on the 5-day gap to assert filter shape.
    """
    now = _ts_ms()
    day_ms = 86_400 * 1000
    return [
        {
            "id": _oid(),
            "type": "nfc",
            "label": "Alice NFC Card",
            "user_id": _USER_ALICE_ID,
            "status": "active",
            "issued_at": now - 30 * day_ms,
            "expires_at": now + 5 * day_ms,
            "card_id": "0123456789",
        },
        {
            "id": _oid(),
            "type": "pin",
            "label": "Bob PIN",
            "user_id": _USER_BOB_ID,
            "status": "active",
            "issued_at": now - 60 * day_ms,
            "expires_at": now + 90 * day_ms,
            "pin_length": 6,
        },
        {
            "id": _oid(),
            "type": "mobile",
            "label": "Carol Mobile Credential",
            "user_id": _USER_CAROL_ID,
            "status": "active",
            "issued_at": now - 7 * day_ms,
            "expires_at": None,
            "device_label": "iPhone 16 Pro",
        },
    ]


def _seed_visitors(host_user_id: str) -> list[UniFiRecord]:
    now = _ts_ms()
    return [
        {
            "id": _oid(),
            "first_name": "Dave",
            "last_name": "Delivery",
            "full_name": "Dave Delivery",
            "email": "dave@example.com",
            "host_user_id": host_user_id,
            "valid_from": now - 3_600_000,
            "valid_until": now + 3_600_000,
            "status": "active",
            "pass_code": "ACC-VISIT-001",
            "purpose": "Package delivery",
        }
    ]


def _seed_access_policies(door_group_id: str) -> list[UniFiRecord]:
    return [
        {
            "id": _oid(),
            "name": "Business Hours — All Users",
            "type": "schedule",
            "schedule": {
                "name": "Business Hours",
                "monday": "08:00-18:00",
                "tuesday": "08:00-18:00",
                "wednesday": "08:00-18:00",
                "thursday": "08:00-18:00",
                "friday": "08:00-18:00",
                "saturday": "closed",
                "sunday": "closed",
            },
            "door_group_ids": [door_group_id],
            "user_ids": [_USER_ALICE_ID, _USER_BOB_ID, _USER_CAROL_ID],
            "credential_types": ["nfc", "pin", "mobile"],
            "active": True,
        }
    ]


def _seed_events(
    doors: list[UniFiRecord],
    users: list[UniFiRecord],
    credentials: list[UniFiRecord],
) -> list[UniFiRecord]:
    """50 deterministic events spread across the last 24h.

    Three quarters are ``granted`` (typical badge-ins), the remaining quarter
    are ``denied`` (expired credential, off-hours, unknown PIN). The mix is
    deterministic so ``list_failed_access_attempts`` test assertions are
    stable across runs.
    """
    now = _ts_ms()
    window_ms = 24 * 3600 * 1000
    events: list[UniFiRecord] = []
    for i in range(50):
        # Spread across the last 24h, with a tiny jitter so timestamps don't
        # tie. Deterministic: index drives both timestamp and outcome.
        ts = now - (window_ms * i // 50) - (i * 137 % 5000)
        door = doors[i % len(doors)]
        user = users[i % len(users)]
        cred = credentials[i % len(credentials)]
        granted = (i % 4) != 0  # 1 in 4 is denied
        event_id = _oid()
        events.append(
            {
                "id": event_id,
                "type": "access",
                "result": "granted" if granted else "denied",
                "timestamp": ts,
                "door_id": door["id"],
                "door_name": door["name"],
                "user_id": user["id"],
                "user_name": user["full_name"],
                "credential_id": cred["id"],
                "credential_type": cred["type"],
                "reason": "" if granted else ["expired", "off-hours", "unknown_pin"][i % 3],
            }
        )
    # Sort newest first to match the wire-level Access API behaviour.
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events


def _seed_system_info() -> UniFiRecord:
    return {
        "version": "2.6.42",
        "release_channel": "stable",
        "license": {
            "type": "free",
            "doors_used": 2,
            "doors_max": 10,
            "users_used": 3,
            "users_max": 100,
        },
        "controller_id": _oid(),
        "uptime_seconds": 432_000,
    }


class AccessStubState:
    """In-memory mock Access state.

    A fresh instance always starts from seeded data: 2 doors, 1 door group,
    1 access policy, 3 credentials, 1 visitor, 50 events, 1 hub, 2 readers,
    3 users. Per-controller isolation matches the Network and Protect
    stub-state pattern.
    """

    def __init__(self) -> None:
        self.users: list[UniFiRecord] = _seed_users()
        self.doors: list[UniFiRecord] = _seed_doors()
        self.devices, hub_id = _seed_devices(self.doors)
        # Back-fill each door's hub_id now that the hub has been seeded.
        for door in self.doors:
            door["hub_id"] = hub_id
        self.door_groups: list[UniFiRecord] = _seed_door_groups(self.doors)
        self.access_policies: list[UniFiRecord] = _seed_access_policies(self.door_groups[0]["id"])
        self.credentials: list[UniFiRecord] = _seed_credentials()
        # Wire user.credential_ids so list_access_users reflects the
        # cross-reference the real API surfaces.
        for cred in self.credentials:
            for user in self.users:
                if user["id"] == cred["user_id"]:
                    user["credential_ids"].append(cred["id"])
        self.visitors: list[UniFiRecord] = _seed_visitors(self.users[0]["id"])
        self.events: list[UniFiRecord] = _seed_events(self.doors, self.users, self.credentials)
        self.system_info: UniFiRecord = _seed_system_info()

        self._failure_queue: dict[str, deque[BaseException]] = defaultdict(deque)

    # ----- Failure injection ---------------------------------------------
    def fail_next(self, method_name: str, exception: BaseException) -> None:
        """Queue an exception to be raised on the next call to ``method_name``.

        Mirrors :meth:`StubState.fail_next` so future composite tests follow
        the same pattern. v0.10 has no composites yet, so this is unused by
        the shipping tools but kept for parity.
        """
        self._failure_queue[method_name].append(exception)

    def _check_failure(self, method_name: str) -> None:
        queue = self._failure_queue.get(method_name)
        if queue:
            raise queue.popleft()

    # ----- Doors ----------------------------------------------------------
    # Every read hands back a copy, so a caller that edits a returned record
    # cannot edit the stub's state through it (the real client returns freshly
    # parsed JSON). Every id and filter value goes through ``path_segment``
    # first, as it does in :class:`AccessClient`, so a tool that forwards a
    # malformed id fails here the way it would against a console. An unknown
    # but well-formed id is "not found": ``None``.
    def _lookup(self, records: list[UniFiRecord], record_id: str, name: str) -> UniFiRecord | None:
        path_segment(record_id, name)
        for record in records:
            if record.get("id") == record_id:
                return copy.deepcopy(record)
        return None

    def list_doors(self) -> list[UniFiRecord]:
        self._check_failure("list_doors")
        return copy.deepcopy(self.doors)

    def get_door(self, door_id: str) -> UniFiRecord | None:
        self._check_failure("get_door")
        return self._lookup(self.doors, door_id, "door_id")

    def list_door_groups(self) -> list[UniFiRecord]:
        self._check_failure("list_door_groups")
        return copy.deepcopy(self.door_groups)

    # ----- Policies -------------------------------------------------------
    def list_access_policies(self) -> list[UniFiRecord]:
        self._check_failure("list_access_policies")
        return copy.deepcopy(self.access_policies)

    def get_access_policy(self, policy_id: str) -> UniFiRecord | None:
        self._check_failure("get_access_policy")
        return self._lookup(self.access_policies, policy_id, "policy_id")

    # ----- Credentials ----------------------------------------------------
    def list_credentials(self) -> list[UniFiRecord]:
        self._check_failure("list_credentials")
        return copy.deepcopy(self.credentials)

    def get_credential(self, credential_id: str) -> UniFiRecord | None:
        self._check_failure("get_credential")
        return self._lookup(self.credentials, credential_id, "credential_id")

    # ----- Visitors -------------------------------------------------------
    def list_visitors(self) -> list[UniFiRecord]:
        self._check_failure("list_visitors")
        return copy.deepcopy(self.visitors)

    def get_visitor(self, visitor_id: str) -> UniFiRecord | None:
        self._check_failure("get_visitor")
        return self._lookup(self.visitors, visitor_id, "visitor_id")

    # ----- Events ---------------------------------------------------------
    def list_events(
        self,
        start_ms: int,
        end_ms: int,
        limit: int,
        result: str = "",
        door_id: str = "",
    ) -> list[UniFiRecord]:
        self._check_failure("list_events")
        if result:
            path_segment(result, "result")
        if door_id:
            path_segment(door_id, "door_id")
        out: list[UniFiRecord] = []
        for evt in self.events:
            ts = evt.get("timestamp", 0)
            if ts < start_ms or ts > end_ms:
                continue
            if result and evt.get("result") != result:
                continue
            if door_id and evt.get("door_id") != door_id:
                continue
            out.append(evt)
        out.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
        return copy.deepcopy(out[:limit])

    # ----- Devices --------------------------------------------------------
    def list_devices(self) -> list[UniFiRecord]:
        self._check_failure("list_devices")
        return copy.deepcopy(self.devices)

    def get_device(self, device_id: str) -> UniFiRecord | None:
        self._check_failure("get_device")
        return self._lookup(self.devices, device_id, "device_id")

    # ----- System ---------------------------------------------------------
    def get_system_info(self) -> UniFiRecord:
        self._check_failure("get_system_info")
        return copy.deepcopy(self.system_info)

    def list_users(self) -> list[UniFiRecord]:
        self._check_failure("list_users")
        return copy.deepcopy(self.users)


def make_access_stub_state() -> AccessStubState:
    """Return a fresh seeded :class:`AccessStubState`.

    Mirrors :func:`make_protect_stub_state` from the Protect stubs.
    """
    return AccessStubState()


__all__ = ["AccessStubState", "make_access_stub_state"]
