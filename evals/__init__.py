"""Agent-quality evals for mcp-unifi.

The ``tests/`` suite asks whether the server is correct. This package asks a
different question: whether a **model driving the server** behaves well against
its tool surface, and whether the server's safety controls hold when something
is actively trying to talk its way past them.

Three question classes live here. See ``evals/README.md`` for the methodology.

Everything in this package runs against the in-memory stub controller. No
module here can reach a real UniFi gateway: :func:`evals.harness.eval_server`
constructs :class:`mcp_unifi.config.Settings` with ``stub_mode=True`` passed
explicitly in code, and ``mcp_unifi.dispatcher.build_registry`` only builds a
:class:`~mcp_unifi.backends.RealBackend` on the ``stub_mode`` False branch.
``tests/test_agent_evals.py`` pins that by running the deterministic classes
with the real HTTP client patched to raise.
"""

from __future__ import annotations

#: Bumped when the scoring rules change in a way that makes an older
#: scoreboard non-comparable. Persisted into every result file.
HARNESS_VERSION = "1.0"

__all__ = ["HARNESS_VERSION"]
