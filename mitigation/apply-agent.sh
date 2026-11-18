#!/usr/bin/env bash
# Apply the CVE-2026-114938 runtime patch to running JVMs on this host / in this container.
#
# Local variant of the upstream apply.sh: it never downloads anything. The
# jar must already be present next to this script (build it once with ./build-agent.sh and
# distribute the jar through your own file distribution system).
#
#   ./apply-agent.sh                    all JVMs found
#   ./apply-agent.sh 1234 5678          only these PIDs
#   ./apply-agent.sh --dry-run [PID..]  stage/load/log; no directives or retransform
#   ./apply-agent.sh --force   [PID..]  apply even if a JVM looks "not exposed"
#   ./apply-agent.sh --yes     [PID..]  do not ask for confirmation (automation)
#
# Needs: jcmd (a JDK) on PATH and permission to attach to the target JVMs.
# Root or the JVM user may still be denied by host policy or namespace boundaries.
# Cross-container access needs visible PIDs, target files, and attach permissions.
# Jar and log names in shared staging directories are predictable. Existing files
# or symlinks can cause tampering or unintended writes; use trusted test hosts.
# Dry-run still stages the jar, loads the agent, and creates or replaces logs.
# The final status checks only directive presence, not whether mitigation worked.
set -u
JAR="${JAVA4SHELL_JAR:-$(cd "$(dirname "$0")" && pwd)/CVE-2026-114938.jar}"
MODE=""; PIDS=(); YES=0
for a in "$@"; do
  case "$a" in
    --dry-run) MODE="dry-run" ;;
    --force)   MODE="force" ;;
    -y|--yes)  YES=1 ;;
    ''|*[!0-9]*) echo "usage: $0 [--dry-run|--force] [--yes] [PID ...]"; exit 2 ;;
    *) PIDS+=("$a") ;;
  esac
done

command -v jcmd >/dev/null || { echo "jcmd not found: run where a JDK is installed"; exit 1; }
[ -f "$JAR" ] || { echo "missing $JAR (run ./build-agent.sh first, or set JAVA4SHELL_JAR)"; exit 1; }

if [ ${#PIDS[@]} -eq 0 ]; then   # every process whose executable is a java launcher (excluding jcmd itself)
  for p in /proc/[0-9]*; do
    p=${p#/proc/}
    a0=$(tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | head -1)
    case "$a0" in java|*/java) ;; *) continue ;; esac
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q 'sun.tools.jcmd' && continue
    PIDS+=("$p")
  done
fi
[ ${#PIDS[@]} -eq 0 ] && { echo "no JVM found"; exit 0; }

echo "Target JVM(s):"
for pid in "${PIDS[@]}"; do echo "  PID $pid  $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-100)"; done
if [ "$MODE" != "dry-run" ] && [ "$YES" != 1 ]; then
  printf "Apply the runtime patch to %d JVM(s)? Type 'yes' to continue: " "${#PIDS[@]}"
  read -r ans || ans=""
  [ "$ans" = "yes" ] || { echo; echo "Aborted. Nothing was changed. (use --yes for non-interactive runs)"; exit 1; }
fi
echo

rc=0
for pid in "${PIDS[@]}"; do
  [ -d "/proc/$pid" ] || { echo "== $pid: no such process"; rc=1; continue; }
  uid=$(stat -c %u "/proc/$pid"); nspid=$(awk '/^NSpid:/{print $NF}' "/proc/$pid/status")
  echo "== PID $pid (uid $uid) $(tr '\0' ' ' < /proc/$pid/cmdline | cut -c1-110)"
  mine=$(readlink /proc/self/ns/mnt); theirs=$(readlink "/proc/$pid/ns/mnt" 2>/dev/null)
  prefix=""; [ -n "$theirs" ] && [ "$theirs" != "$mine" ] && prefix="/proc/$pid/root"
  tjar=""; errs=""
  for d in /tmp /dev/shm /var/tmp; do
    if e=$(cp "$JAR" "$prefix$d/CVE-2026-114938.jar" 2>&1); then chmod 644 "$prefix$d/CVE-2026-114938.jar"; tjar="$d/CVE-2026-114938.jar"; break
    else errs="$errs; $e"; fi
  done
  if [ -z "$tjar" ]; then
    echo "   cannot place jar where PID $pid can read it${prefix:+ (via $prefix)}${errs}"
    rc=1; continue
  fi
  tdir="$prefix$(dirname "$tjar")"; rm -f "$tdir/CVE-2026-114938-$nspid.log"
  SUDO=""; if [ "$(id -u)" != 0 ] && [ "$(id -u)" != "$uid" ]; then
    command -v sudo >/dev/null && SUDO="sudo -n -u #$uid" || { echo "   not root and not the JVM owner (uid $uid)"; rc=1; continue; }
  fi
  out=$($SUDO jcmd "$pid" JVMTI.agent_load "$tjar" $MODE 2>&1)
  if ! echo "$out" | grep -q 'return code: 0'; then echo "   jcmd failed: $(echo "$out" | tr '\n' ' ' | cut -c1-300)"; rc=1; continue; fi
  if [ -f "$tdir/CVE-2026-114938-$nspid.log" ]; then sed 's/^/   /' "$tdir/CVE-2026-114938-$nspid.log"
  else echo "   (agent output is in the target JVM's stderr)"; fi
  if $SUDO jcmd "$pid" Compiler.directives_print 2>/dev/null | grep -q 'Base64\$Decoder.decode0'; then
    echo "   STATUS: patched (directive present)"
  else
    echo "   STATUS: not patched"
  fi
done
exit $rc
