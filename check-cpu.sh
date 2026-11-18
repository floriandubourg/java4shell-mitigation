#!/bin/sh
# Java4Shell (CVE-2026-114938) CPU exposure check (CPU flags only).
# The vulnerable AVX-512 VBMI Base64 decode stub is only generated on x86-64 CPUs that
# expose avx512vbmi. Missing flag rule out this path, not other vulnerabilities.
# CPU flag alone do not establish JVM exposure.
f=$(grep -m1 '^flags' /proc/cpuinfo)
has() { echo "$f" | grep -qw "$1" && echo yes || echo no; }
echo "CPU        : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "avx512vbmi : $(has avx512vbmi)"
if [ "$(has avx512vbmi)" = yes ]; then
  echo "=> EXPOSED CPU  (OpenJDK 17.0.6+/18+ with defaults is vulnerable; mitigate: -XX:-UseBASE64Intrinsics)"
else
  echo "=> not exposed  (the vulnerable stub path is never generated on this CPU)"
fi
