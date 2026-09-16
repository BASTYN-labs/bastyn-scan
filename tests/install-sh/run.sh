#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# 1. The script must be valid POSIX sh, not bash-flavored.
if ! command -v dash >/dev/null 2>&1; then
    fail "dash is required to validate POSIX compliance (apt-get install dash / it ships on most Linux CI images)"
fi
dash -n install.sh || fail "install.sh is not valid POSIX sh (dash -n rejected it)"
pass "install.sh parses as POSIX sh"

# 2. The whole script must be one function, called on the literal last line —
#    this is the truncation guard. A truncated download must not be able to
#    reach a bare top-level command.
last_line=$(tail -n1 install.sh)
[ "$last_line" = 'main "$@"' ] || fail "last line must be exactly: main \"\$@\" (got: $last_line)"
pass "last line invokes main \"\$@\""

grep -q '^main() {' install.sh || fail "expected a top-level 'main() {' function wrapping the script body"
pass "script body is wrapped in main()"

# No commands outside main()/helper function definitions at top level except
# the final `main "$@"` call and function/variable definitions.
awk '
  /^[a-zA-Z_][a-zA-Z0-9_]*\(\) \{/ { depth++; next }
  /^}/ { if (depth > 0) depth--; next }
  depth == 0 && $0 !~ /^main "\$@"$/ && $0 !~ /^set -eu$/ && $0 !~ /^[A-Za-z_][A-Za-z0-9_]*=/ && NF > 0 && $0 !~ /^#/ {
    print NR": "$0; bad=1
  }
  END { exit bad }
' install.sh && pass "no bare top-level commands outside function bodies" \
  || fail "found a top-level statement outside a function body (see line above) — truncation could execute it early"

# 3. set -eu must be present near the top.
head -n5 install.sh | grep -q '^set -eu' || fail "expected 'set -eu' in the first 5 lines"
pass "set -eu present"

# 4. mktemp -d and a trap cleanup must both be present.
grep -q 'mktemp -d' install.sh || fail "expected a mktemp -d temp working directory"
pass "uses mktemp -d"
grep -q "trap '.*rm -rf" install.sh || fail "expected a trap cleaning up the temp directory"
pass "has a cleanup trap"

# 5. Every curl call must pin the protocol to https.
curl_lines=$(grep -n 'curl ' install.sh | grep -v -- '^[0-9]\+:[[:space:]]*#' || true)
if [ -n "$curl_lines" ]; then
    echo "$curl_lines" | grep -v -- "--proto '=https' --proto-redir '=https'" \
        && fail "found a curl call missing --proto '=https' --proto-redir '=https' (see line above)"
fi
pass "every curl call pins https"

# 6. Checksum verification: given a deliberately corrupted "archive" and a
#    checksum file for the *correct* content, the checksum_verify function
#    must reject it. Source only the function definitions (not main) by
#    stripping the final main "$@" call, then call checksum_verify directly.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
echo "correct content" > "$tmpdir/archive"
sha256sum "$tmpdir/archive" | sed "s#$tmpdir/##" > "$tmpdir/archive.sha256"
echo "WRONG content" > "$tmpdir/archive"  # corrupt it after computing the checksum

script_body=$(sed '$d' install.sh)  # drop the final `main "$@"` line
if (eval "$script_body"; checksum_verify "$tmpdir/archive" "$tmpdir/archive.sha256") 2>"$tmpdir/checksum-test.err"; then
    fail "checksum_verify accepted corrupted content"
fi
grep -q "checksum verification failed" "$tmpdir/checksum-test.err" || fail "expected an explicit checksum-failure message"
pass "checksum_verify rejects corrupted content"

echo "All install.sh structural tests passed."
