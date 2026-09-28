#!/usr/bin/env bash
# Usage: scripts/publish.sh <version> [rid...]
# Builds self-contained single-file binaries into dist/ and packages each RID.
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:?usage: scripts/publish.sh <version> [rid...]}"
shift
rids=("$@")
if [[ ${#rids[@]} -eq 0 ]]; then
  rids=(win-x64 osx-arm64 osx-x64 linux-x64 linux-arm64)
fi

mkdir -p dist
for rid in "${rids[@]}"; do
  out="dist/$rid"
  rm -rf "$out"
  dotnet publish src/CertInstaller.Cli -c Release -r "$rid" --self-contained \
    -p:PublishSingleFile=true -p:PublishTrimmed=true -p:DebugType=none \
    -p:Version="$version" -o "$out"
  name="certinstall-$version-$rid"
  if [[ $rid == win-* ]]; then
    (cd "$out" && zip -q "../$name.zip" certinstall.exe)
  else
    tar -czf "dist/$name.tar.gz" -C "$out" certinstall
  fi
  echo "packaged dist/$name"
done
