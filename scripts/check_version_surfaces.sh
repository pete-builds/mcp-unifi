#!/usr/bin/env bash
# Verify every place a release version lives says the same version.
#
# Usage: scripts/check_version_surfaces.sh [VERSION]
#
# VERSION defaults to the one in pyproject.toml. Exits non-zero, naming each
# surface that disagrees, if any surface or the CHANGELOG section is wrong.
#
# One implementation, two callers: release.yml checks the tag it was started
# on, and ci.yml checks every PR so a half-bumped release PR goes red before
# merge instead of at tag time.
# See CONTRIBUTING.md "Release procedure" for why each surface is here.
#
# Must run on macOS (bash 3.2, BSD sed) and Linux.

set -euo pipefail

cd "$(dirname "$0")/.."

REPO="${REPO:-pete-builds/mcp-unifi}"

pyproject=$(grep -E '^version = ' pyproject.toml | head -1 | sed -E 's/version = "([^"]+)"/\1/')
VERSION="${1:-$pyproject}"
VERSION="${VERSION#v}"

echo "Verifying every version surface matches ${VERSION}..."

fail=0
check() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [ "${actual}" != "${expected}" ]; then
    echo "::error::${label} is '${actual}', expected '${expected}'"
    fail=1
  else
    echo "  ok  ${label} = ${actual}"
  fi
}

init=$(grep -E '^__version__ = ' src/mcp_unifi/__init__.py | head -1 | sed -E 's/__version__ = "([^"]+)"/\1/')
manifest=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
server_version=$(python3 -c "import json;print(json.load(open('server.json'))['version'])")
server_oci=$(python3 -c "import json;print(json.load(open('server.json'))['packages'][0]['identifier'])")
expected_oci="ghcr.io/${REPO}:${VERSION}"
compose_image=$(grep -E "image: ghcr\.io/${REPO}:" docker-compose.yml | head -1 | sed -E 's/.*image: (.+)/\1/')
chart_app=$(grep -E '^appVersion:' charts/mcp-unifi/Chart.yaml | head -1 | sed -E 's/appVersion: "?([^"]+)"?/\1/')

check "pyproject.toml version" "${VERSION}" "${pyproject}"
check "src/mcp_unifi/__init__.py __version__" "${VERSION}" "${init}"
check "manifest.json version" "${VERSION}" "${manifest}"
check "server.json version" "${VERSION}" "${server_version}"
check "server.json packages[0].identifier" "${expected_oci}" "${server_oci}"
check "docker-compose.yml image" "${expected_oci}" "${compose_image}"
check "charts/mcp-unifi/Chart.yaml appVersion" "${VERSION}" "${chart_app}"

# release.yml publishes this section verbatim as the GitHub release body.
notes=$(awk -v v="${VERSION}" '
  $0 ~ "^## \\[" v "\\]" {f=1; next}
  /^## \[/ {f=0}
  f
' CHANGELOG.md)
if printf '%s' "${notes}" | grep -q '[^[:space:]]'; then
  echo "  ok  CHANGELOG.md has a non-empty [${VERSION}] section"
else
  echo "::error::CHANGELOG.md has no non-empty '## [${VERSION}]' section"
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  echo ""
  echo "::error::Version surfaces disagree with ${VERSION}."
  echo "::error::Bump every surface in one commit before releasing."
  echo "::error::See CONTRIBUTING.md for the release procedure."
  exit 1
fi
