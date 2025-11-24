#!/usr/bin/env bash
# Small installer for MailProbe
# Installs the script to $PREFIX/bin/mailprobe (default /usr/local/bin)

set -euo pipefail

PREFIX=/usr/local
DRY_RUN=0
FORCE=0
UNINSTALL=0

usage(){
  cat <<EOF
Usage: $0 [--prefix <path>] [--dry-run] [--force] [--uninstall]

Options:
  --prefix PATH   Set installation prefix (default: /usr/local)
  --dry-run       Show what would be done but do not modify anything
  --force         Overwrite existing installation without prompt
  --uninstall     Remove installed binary from PREFIX/bin

Examples:
  $0 --prefix /usr/local
  $0 --prefix ~/.local --force
  $0 --uninstall --prefix /usr/local
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)
      PREFIX="$2"; shift 2;;
    --dry-run)
      DRY_RUN=1; shift;;
    --force)
      FORCE=1; shift;;
    --uninstall)
      UNINSTALL=1; shift;;
    -h|--help)
      usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

BINDIR="$PREFIX/bin"
TARGET="$BINDIR/mailprobe"
SRC="$(realpath "${BASH_SOURCE[0]}")"

if [ "$UNINSTALL" -eq 1 ]; then
  echo "Uninstalling $TARGET"
  if [ $DRY_RUN -eq 1 ]; then
    echo "DRY RUN: Would remove $TARGET"
    exit 0
  fi
  if [ -f "$TARGET" ]; then
    if [ -w "$TARGET" ] || [ $FORCE -eq 1 ]; then
      rm -f "$TARGET"
      echo "Removed $TARGET"
      exit 0
    else
      echo "Need elevated permissions to remove $TARGET" >&2
      sudo rm -f "$TARGET"
      exit 0
    fi
  else
    echo "Nothing to uninstall (no file at $TARGET)"
    exit 0
  fi
fi

echo "Installing MailProbe to $TARGET"

if [ $DRY_RUN -eq 1 ]; then
  echo "DRY RUN: would create $BINDIR and copy mailprobe.sh -> $TARGET"
  exit 0
fi

mkdir -p "$BINDIR"

if [ -f "$TARGET" ] && [ $FORCE -ne 1 ]; then
  read -rp "$TARGET already exists. Overwrite? [y/N] " ans
  case "$ans" in
    y|Y) true;;
    *) echo "Aborting."; exit 1;;
  esac
fi

# Ensure the script is executable
chmod +x mailprobe.sh

if cp mailprobe.sh "$TARGET" 2>/dev/null; then
  echo "Installed mailprobe -> $TARGET"
else
  echo "Attempting privileged install (sudo) to write to $TARGET" >&2
  sudo cp mailprobe.sh "$TARGET"
  sudo chmod +x "$TARGET"
  echo "Installed mailprobe -> $TARGET (via sudo)"
fi

echo "Done. Run '$TARGET -h' or 'mailprobe -h' to verify."
