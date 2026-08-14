#!/usr/bin/env bash
# Deterministic regression coverage for gh_release.sh. The test uses a
# disposable workspace and command stubs; it never calls crates.io, git
# remotes, or GitHub.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$WORK_DIR/scripts" "$WORK_DIR/bin"
cp "$SCRIPT_DIR/gh_release.sh" "$WORK_DIR/scripts/gh_release.sh"
chmod +x "$WORK_DIR/scripts/gh_release.sh"

for crate in dns-lattice dns-lattice-core dns-lattice-model; do
    mkdir -p "$WORK_DIR/crates/$crate"
    printf '[package]\nname = "%s"\nversion = "1.2.3"\n' "$crate" \
        > "$WORK_DIR/crates/$crate/Cargo.toml"
done

cat > "$WORK_DIR/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '200'
EOF

cat > "$WORK_DIR/bin/git" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    rev-parse) exit 0 ;;
    rev-list) printf '0123456789abcdef\n' ;;
    tag|log) exit 0 ;;
    *) exit 99 ;;
esac
EOF

cat > "$WORK_DIR/bin/gh" <<'EOF'
#!/usr/bin/env bash
# --dry-run must not invoke gh at all; command -v is handled by PATH lookup.
exit 99
EOF

chmod +x "$WORK_DIR/bin/curl" "$WORK_DIR/bin/git" "$WORK_DIR/bin/gh"

output="$(PATH="$WORK_DIR/bin:$PATH" "$WORK_DIR/scripts/gh_release.sh" --dry-run)"
[[ "$output" == *"gh release edit dns-lattice-v1.2.3 --latest"* ]] \
    || { echo "missing facade Latest repair in dry-run output" >&2; exit 1; }
[[ "$output" == *"gh release view dns-lattice-v1.2.3 || gh release create dns-lattice-v1.2.3 --verify-tag --latest=false"* ]] \
    || { echo "missing facade-release recovery in dry-run output" >&2; exit 1; }

GH_LOG="$WORK_DIR/gh.log"
export GH_LOG
cat > "$WORK_DIR/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_LOG"
case "$1 $2" in
    "release view") exit 1 ;;
    "release create"|"release edit") exit 0 ;;
    *) exit 99 ;;
esac
EOF
chmod +x "$WORK_DIR/bin/gh"

PATH="$WORK_DIR/bin:$PATH" "$WORK_DIR/scripts/gh_release.sh" >/dev/null
grep -Fxq 'release view dns-lattice-v1.2.3' "$GH_LOG" \
    || { echo "missing facade release lookup" >&2; exit 1; }
grep -Fq -- 'release create dns-lattice-v1.2.3 --verify-tag --latest=false' "$GH_LOG" \
    || { echo "missing facade release recovery" >&2; exit 1; }
grep -Fxq 'release edit dns-lattice-v1.2.3 --latest' "$GH_LOG" \
    || { echo "missing facade Latest repair after recovery" >&2; exit 1; }
view_line="$(grep -n -F -- 'release view dns-lattice-v1.2.3' "$GH_LOG" | head -1 | cut -d: -f1)"
create_line="$(grep -n -F -- 'release create dns-lattice-v1.2.3 --verify-tag --latest=false' "$GH_LOG" | head -1 | cut -d: -f1)"
edit_line="$(grep -n -F -- 'release edit dns-lattice-v1.2.3 --latest' "$GH_LOG" | head -1 | cut -d: -f1)"
[[ "$view_line" -lt "$create_line" && "$create_line" -lt "$edit_line" ]] \
    || { echo "facade release recovery must run view → create → Latest" >&2; exit 1; }

create_block="$(sed -n '/gh release create "$tag"/,+3p' "$SCRIPT_DIR/gh_release.sh")"
[[ "$create_block" == *"--latest=false"* ]] \
    || { echo "new releases must opt out of GitHub automatic Latest selection" >&2; exit 1; }

echo "gh_release.sh dry-run Latest regression: PASS"
