#!/bin/sh
# h3spec v0.1.14, the "QUIC servers" section only, against a server that is already running.
# The version is pinned because the case list is what the conformance table in README.md is
# checked against; a newer release may add cases and the table would be quoting an old one.
#
#   scripts/quic/check_h3spec.sh [host] [port]
#
# Needs `gh` (or curl and a direct URL) to fetch the release, and a x86-64 Linux host to run it.
# This repository holds no socket, so it cannot start the server itself: the server repository
# runs this against the binary it builds.
set -eu

host="${1:-127.0.0.1}"
port="${2:-12000}"
version="v0.1.14"
asset="h3spec-linux-x86_64"
dir="${TMPDIR:-/tmp}/moonquic-h3spec-$version"

if [ ! -x "$dir/$asset" ]; then
  mkdir -p "$dir"
  if command -v gh >/dev/null 2>&1; then
    gh release download "$version" -R kazu-yamamoto/h3spec -p "$asset" -D "$dir" --clobber
  else
    curl -fsSL -o "$dir/$asset" \
      "https://github.com/kazu-yamamoto/h3spec/releases/download/$version/$asset"
  fi
  chmod +x "$dir/$asset"
fi

"$dir/$asset" --version
# `--match` is hspec's description filter; the transport cases are all under one describe.
exec "$dir/$asset" "$host" "$port" --no-validate --match "QUIC servers"
