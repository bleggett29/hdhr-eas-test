#!/bin/sh
# eas_batch.sh - render every ATSC 3.0 capture in a folder, then build the
# combined EAS summary page (eas_summary.html) in that folder.
#
#   ./eas_batch.sh <capture-dir> [dbg-segment-seconds]
#
# - .pcap files are rendered as-is (they carry real timestamps).
# - .dbg files are rendered with -t <seconds> (default 60, match the capture's
#   --seg) so alert times can be estimated inside each segment.
# - Captures that already have a .eas.tsv sidecar are skipped; delete the
#   sidecar to force a re-render.
# - ATSC 1.0 .ts files are listed in the summary (with links) but not analyzed.
#
# Set JOBS=<n> to render n files at once (default 1; each render can use a
# few hundred MB of RAM on a 60 s full-RF capture).

set -u
DIR="${1:-}"
SEG="${2:-60}"
JOBS="${JOBS:-1}"
if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then
    echo "Usage: $0 <capture-dir> [dbg-segment-seconds]" >&2
    exit 1
fi
HERE=$(cd "$(dirname "$0")" && pwd)
RENDER="$HERE/render"
if [ ! -x "$RENDER" ]; then
    echo "render not found at $RENDER - run make first" >&2
    exit 1
fi

render_one() {
    f="$1"
    side="${f%.*}.eas.tsv"
    [ -f "$side" ] && return 0
    case "$f" in
        *.dbg) echo ">> $f (dbg, -t $SEG)"; "$RENDER" -t "$SEG" "$f" > "${f%.*}.render.log" 2>&1 ;;
        *)     echo ">> $f";               "$RENDER" "$f"         > "${f%.*}.render.log" 2>&1 ;;
    esac
    [ $? -eq 0 ] || echo "   render failed - see ${f%.*}.render.log" >&2
}

count=0
for f in "$DIR"/*.pcap "$DIR"/*.dbg; do
    [ -f "$f" ] || continue
    if [ "$JOBS" -gt 1 ]; then
        render_one "$f" &
        count=$((count + 1))
        if [ "$count" -ge "$JOBS" ]; then wait; count=0; fi
    else
        render_one "$f"
    fi
done
wait

"$RENDER" --eas-summary "$DIR/eas_summary.html" "$DIR"
