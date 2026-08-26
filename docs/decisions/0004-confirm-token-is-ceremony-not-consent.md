# 0004. The confirm-token handshake is ceremony, not consent

**Status:** Accepted as an interim control, with a known and stated inadequacy.
Not equivalent to the "Accepted" in the other records here.

## Context

Twelve tools use a preview-then-confirm handshake: `delete_content_filter`,
`delete_dynamic_dns`, `delete_firewall_group`, `delete_firewall_rule`,
`delete_honeypot`, `delete_port_forward`, `delete_port_profile`, `delete_route`,
`delete_static_dhcp_lease`, `delete_vlan`, `delete_wlan`, and `set_guest_portal`.

Calling one of them does not mutate the controller. It resolves the target, mints a
UUID4 token into an in-process registry with a 300 second TTL, and returns a
preview envelope naming the resource and the token. The change commits only when
`confirm_destructive_action(token)` runs. Implementation is in
`src/mcp_unifi/modules/network/_pending.py`.

The pattern reads like a confirmation prompt. It is not one.

## Decision

Keep the handshake, and state plainly what it does and does not provide.

**What it provides:** a preview of the exact resource that will be destroyed before
anything is destroyed, a bounded window in which nothing has happened yet, an
`_id`-resolved target so a wrong-object mistake is visible in the preview, and two
distinct audit records for one destructive action.

**What it does not provide: consent.** Both calls are made by the same caller. When
that caller is an autonomous agent, the agent previews, reads its own preview, and
confirms, all inside one turn, with no human between the two calls. Against that
threat model the handshake is ceremony. It proves nothing about human intent, and
it must not be described as a safety control that requires approval.

## Alternatives considered

**A bespoke out-of-band approval channel**, for example posting the preview to
Discord and waiting for a reaction before the token becomes usable. Rejected. It
would be real consent, and it would also mean this MCP server owns a chat
integration, a webhook listener, a secret for it, a timeout policy, and an
availability dependency where a destructive operation blocks on a third-party
service being reachable. That is a large, permanently-owned surface bolted onto a
server whose job is to talk to a network controller. It also only works for one
operator on one platform.

**MCP elicitation routed through the harness.** This is the right shape. The
protocol has a flow for a server to ask the client to put a question to the human,
and the client is where a human already is. The server would ask, the harness would
prompt, and the answer would carry actual human intent rather than an agent's echo
of its own request.

Not implemented. Two things would need checking first, and neither has been
verified for this record: whether the pinned `fastmcp==3.4.6` and `mcp==1.29.0`
expose the flow usably from a tool body, and whether the clients this server is
actually used from implement the client half. An elicitation call that the client
silently declines would be a third form of ceremony, so this needs proving before
it ships, not assuming.

**Requiring a human-supplied confirmation phrase as a tool argument.** Rejected: an
agent can supply any string a docstring tells it to supply. It moves the ceremony,
it does not remove it.

**Removing the handshake entirely and relying on read-only mode (ADR 0001).**
Rejected because the preview has value independent of consent. Seeing the resolved
resource before deleting it catches wrong-target errors, which are the common
failure, whereas consent addresses the rare one.

## Consequences and accepted costs

- **A control that looks stronger than it is, which is the specific risk of
  documenting it badly.** Anyone who reads "preview then confirm" and infers human
  approval has been misled. This record exists mainly to prevent that reading.
- Tokens live in a process-global registry with no persistence. A restart drops
  every pending action, and the preview has to be re-run. That is the correct
  failure direction and it is still a rough edge.
- Every destructive operation costs two round trips.
- `confirm_destructive_action` is itself classified `mutates=True` (ADR 0001), so
  read-only mode blocks the commit half. Read-only mode, not this handshake, is the
  control that actually stops an autonomous agent from completing a delete.

## Reversal condition

Replace the handshake with **MCP elicitation through the harness** as soon as both
halves are confirmed present: the pinned SDK exposes the flow from a tool body, and
the clients in use implement it. At that point the preview stays, the local token
registry goes, and this record is superseded rather than amended.

Reverse in the other direction, removing the handshake, if elicitation lands and a
preview turns out to be redundant with what the elicitation prompt already shows
the human. Carrying both would be two confirmations for one action.

Do not build the out-of-band channel. If someone proposes it again, the reason it
was rejected is ownership cost and availability coupling, and neither of those
changes because the idea is raised a second time.
