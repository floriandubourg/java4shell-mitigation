#!/usr/bin/env bash
# Build the CVE-2026-114938 runtime-patch agent jar from vendored source.
# No network access, no curl|sh. Requires a JDK 17+ (javac/jar) on PATH.
# The jar targets Java 17 bytecode; attach support depends on the target JVM.
set -euo pipefail
cd "$(dirname "$0")"

command -v javac >/dev/null || { echo "javac not found (need a JDK 17+)"; exit 1; }
command -v jar   >/dev/null || { echo "jar not found (need a JDK 17+)"; exit 1; }

rm -rf build && mkdir build
javac --release 17 -d build src/CVE_2026_114938.java
jar cfm CVE-2026-114938.jar src/MANIFEST.MF -C build .
rm -rf build

echo "built $(pwd)/CVE-2026-114938.jar"
sha256sum CVE-2026-114938.jar 2>/dev/null || shasum -a 256 CVE-2026-114938.jar
