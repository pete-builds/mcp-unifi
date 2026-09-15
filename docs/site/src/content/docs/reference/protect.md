---
draft: false
title: Protect Tools
description: Reference for the Protect module tool surface.
---

The Protect module covers UniFi Protect cameras: list / get / configure cameras, fetch motion and smart-detection events, pull snapshots and thumbnails, list recordings, and a `provision_camera` composite that configures recording mode + sensitivity + privacy mask in one call with rollback.

## Enabling

The Protect module is **opt-in**. Set:

```bash
MCP_UNIFI_MODULES_ENABLED=network,protect
```

If you only want Protect (no Network):

```bash
MCP_UNIFI_MODULES_ENABLED=protect
```

When the env var is unset, only Network is loaded.

## Conventions

Every tool accepts an optional `controller: str = "default"` parameter. Every destructive tool also accepts `dry_run: bool = False`.

The Protect tool surface is intentionally narrow: no live RTSP, no two-way audio, no chime / message tools (yet). Phase 3 ships 11 primitives plus 1 composite to give the LLM a small, safe vocabulary.

## Read-only

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_cameras` | read | — | List every camera bonded to the Protect controller. Includes `id`, `name`, `model`, `mac`, `host`, `state`, `isConnected`, `isDoorbell`, plus nested `recordingSettings`, `motionSettings`, `privacyMask`, and `stats`. |
| `get_camera` | read | — | Fetch a single camera's full record by ID. |
| `list_motion_events` | read | — | List motion events in the last `hours_back` hours. Filter by `camera_id` or pass empty string for all cameras. |
| `list_smart_detections` | read | — | List smart-detection events (`person`, `vehicle`, `animal`, `package`). Filter by `detection_type` and optional `camera_id`. |
| `get_snapshot` | read | — | Fetch a current JPEG snapshot from a camera, base64-encoded. Returns `{"camera_id", "format": "jpeg", "data": "<base64>", "size_bytes"}`. |
| `get_event_thumbnail` | read | — | Fetch the JPEG thumbnail for a Protect event, base64-encoded. Same shape as `get_snapshot`. |
| `list_recordings` | read | — | List Protect recordings for one camera over the last `hours_back` hours. One record per stored clip segment. |
| `list_doorbell_messages` | read | — | List the subset of cameras that are doorbells (`isDoorbell=True`). |

## Write (destructive)

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `set_camera_recording_mode` | write | yes | Set a camera's recording mode (`always`, `motion`, or `never`). PATCHes `recordingSettings.mode`. |
| `set_camera_privacy_mode` | write | yes | Toggle a camera's privacy mask (lens cover) on or off. When `enabled=True`, the camera stops capturing video. |
| `set_motion_sensitivity` | write | yes | Set a camera's motion sensitivity (0-100). 0 effectively disables motion-based recording. |

## Composite (with rollback)

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `provision_camera` | write | yes | Configure a camera end-to-end: recording mode + retention + motion sensitivity + privacy mask. Three-step apply with rollback. The response includes `partial` and `rolled_back` keys when a step fails. |

`provision_camera` captures the camera's `recordingSettings` and `motionSettings` before mutating, then applies in order: recording → sensitivity → privacy. If step 2 or 3 fails, the prior steps are restored to the pre-call snapshot before the error returns.

## Stub mode

In stub mode, the Protect backend exposes two fake cameras (one of which is a doorbell), a small stream of fake motion and smart-detection events, and fake JPEG bytes for snapshots and thumbnails. Every destructive tool persists in the in-memory state for the lifetime of the process.

## Notes on enums

- **`mode`** (for `set_camera_recording_mode`, `provision_camera`): one of `"always"`, `"motion"`, `"never"`. Out-of-range values are rejected with an error envelope.
- **`detection_type`** (for `list_smart_detections`): one of `"person"`, `"vehicle"`, `"animal"`, `"package"`.
- **`sensitivity`** (for `set_motion_sensitivity`, `provision_camera`): integer 0-100. Out-of-range values are rejected.
- **`retention_days`** (for `provision_camera`): non-negative integer. Multiplied by `86_400_000` to derive `retentionDurationMs` on the underlying camera record.

## Real-mode prerequisites

The Protect tools require a UniFi Protect application running on the same gateway addressed by `UNIFI_HOST`. The client sends `X-API-Key` using the configured controller key; it does not use cookie authentication.

The default `protect_api: internal` uses `/proxy/protect/api`, preserving existing behavior. On UniFi OS 5.x, a valid API key may receive 401 from that internal endpoint while Network works. Set `UNIFI_PROTECT_API=integration` for a legacy single-controller deployment, or `protect_api: integration` on the controller in multi-site YAML, to use `/proxy/protect/integration/v1` instead. This was verified by a field reporter on two UniFi OS 5.1.31 consoles (Network 10.6.101): camera list/details and snapshots worked with the same API key.

The Integration API v1 does **not** expose the event, recording or event-thumbnail endpoints used by this module. Those tools return a clear error in integration mode. Camera update endpoints on that surface have not been verified on live hardware; use read-only mode if only camera reads are needed. There is no automatic fallback to the internal API because that could change the authentication surface without the operator's choice.
