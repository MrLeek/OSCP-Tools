#!/usr/bin/env bash
# suid_report.sh — compact SUID enumeration report
# Usage: sudo ./suid_report.sh
# Produces: /tmp/suid_report_<host>-<ts>/{all_suid.txt,root_suid.txt,report.txt}
set -euo pipefail

HOST="$(hostname -s 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="/tmp/suid_report_${HOST}-${TS}"
mkdir -p "$OUTDIR"

# choose package lookup method (dpkg on Debian, rpm on RHEL)
PKG_TOOL=""
if command -v dpkg-query >/dev/null 2>&1; then
  PKG_TOOL="dpkg"
elif command -v rpm >/dev/null 2>&1; then
  PKG_TOOL="rpm"
fi

# cache for package info
declare -A PKG_CACHE

query_pkg_info() {
  local pkg="$1"
  if [[ -n "${PKG_CACHE[$pkg]:-}" ]]; then
    printf '%s\n' "${PKG_CACHE[$pkg]}"
    return
  fi

  local info="Package: ${pkg} (info unavailable)"
  if [[ "$PKG_TOOL" == "dpkg" ]]; then
    info=$(dpkg-query -W -f='Package: ${Package}\nVersion: ${Version}\n' "$pkg" 2>/dev/null || printf 'Package: %s (info unavailable)\n' "$pkg")
  elif [[ "$PKG_TOOL" == "rpm" ]]; then
    # rpm -q --qf prints name and version-release on one line
    info=$(rpm -q --qf 'Package: %{NAME}\nVersion: %{VERSION}-%{RELEASE}\n' "$pkg" 2>/dev/null || printf 'Package: %s (info unavailable)\n' "$pkg")
  fi

  PKG_CACHE[$pkg]="$info"
  printf '%s\n' "$info"
}

process_file() {
  local bin="$1"
  printf '[*] %s\n' "$bin"
  if [[ "$PKG_TOOL" == "dpkg" ]]; then
    # dpkg -S may return multiple lines; extract unique package names
    pkgs=$(dpkg -S "$bin" 2>/dev/null | cut -d: -f1 | sort -u || true)
  elif [[ "$PKG_TOOL" == "rpm" ]]; then
    # rpm -qf returns package or error
    pkg=$(rpm -qf --queryformat '%{NAME}\n' "$bin" 2>/dev/null || true)
    pkgs="$pkg"
  else
    pkgs=""
  fi

  if [[ -n "${pkgs// /}" ]]; then
    # print package info for each package owning the file
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      query_pkg_info "$p"
    done <<< "$pkgs"
  else
    # fallback: describe the file
    file "$bin" || true
  fi
  printf '\n'
}

# find helpers: safe handling of filenames
find_suid_all() {
  find / -xdev -type f -perm -u=s -print0 2>/dev/null
}
find_suid_root() {
  find / -xdev -type f -perm -u=s -uid 0 -print0 2>/dev/null
}

# Generate all-SUID list
ALL_FILE="$OUTDIR/all_suid.txt"
: > "$ALL_FILE"
while IFS= read -r -d '' f; do
  printf '%s\n' "$f" >> "$ALL_FILE"
done < <(find_suid_all)

# Generate root-owned SUID list
ROOT_FILE="$OUTDIR/root_suid.txt"
: > "$ROOT_FILE"
while IFS= read -r -d '' f; do
  printf '%s\n' "$f" >> "$ROOT_FILE"
done < <(find_suid_root)

# Produce human-readable report
REPORT="$OUTDIR/report.txt"
{
  echo "SUID report for $HOST — $TS"
  echo "Package tool detected: ${PKG_TOOL:-none}"
  echo
  echo "== Root-owned SUID binaries =="
  if [[ -s "$ROOT_FILE" ]]; then
    while IFS= read -r bin; do
      process_file "$bin"
    done < "$ROOT_FILE"
  else
    echo "(none found)"
    echo
  fi

  echo "== All SUID binaries =="
  if [[ -s "$ALL_FILE" ]]; then
    while IFS= read -r bin; do
      process_file "$bin"
    done < "$ALL_FILE"
  else
    echo "(none found)"
    echo
  fi

  # summary
  echo "== Summary =="
  echo "Total SUID binaries: $(wc -l < "$ALL_FILE" 2>/dev/null || echo 0)"
  echo "Root-owned SUID binaries: $(wc -l < "$ROOT_FILE" 2>/dev/null || echo 0)"
} > "$REPORT"

# also copy human-readable output to stdout for immediate view
cat "$REPORT"

echo
echo "Reports saved to: $OUTDIR"
