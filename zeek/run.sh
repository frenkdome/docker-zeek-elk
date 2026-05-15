#!/bin/bash

# Watches ZEEK_INDIR recursively for new PCAP files.
#
# Expected input structure:
#   $ZEEK_INDIR/<vps-name>/pcap/<YYYY>/<MM>/<DD>/<capture>.pcap[.zst]
#
# Output structure (logs appended per VPS per day):
#   $ZEEK_LOGDIR/<vps-name>/<YYYY>-<MM>-<DD>/http.log, modbus.log, ...
#
# Processed PCAPs are moved to:
#   $ZEEK_OUTDIR/<vps-name>/<YYYY>/<MM>/<DD>/<capture>.pcap[.zst]

function log() {
    echo "$(date -Iseconds) $1"
}

log "Watching $ZEEK_INDIR recursively for PCAP files..."

# Watch only 'moved_to' — rsync writes to a hidden temp file and renames it
# once the transfer is complete, so 'moved_to' is guaranteed to fire on a
# fully-written file. 'close_write' fires on every partial rsync chunk and
# would cause Zeek to read an incomplete PCAP.
#
# Requirement on the rsync sender side: use the default temp-file mode
# (do NOT use --inplace). Optionally add --delay-updates for extra safety.
inotifywait -r -m -e moved_to --format "%w%f" "$ZEEK_INDIR/" | while IFS= read -r FULLPATH; do

    # Only process regular files (skip directory move events)
    [ -f "$FULLPATH" ] || continue

    # Only process files that look like PCAPs (plain or zstd-compressed)
    if ! [[ "$FULLPATH" =~ \.pcap([0-9]*)(\.zst)?$ ]]; then
        continue
    fi

    FILENAME=$(basename "$FULLPATH")
    log "New PCAP: $FULLPATH"

    # ── Parse VPS name and date from path ────────────────────────────────
    # Strip leading ZEEK_INDIR prefix → relative path
    # Relative: <vps-name>/pcap/<YYYY>/<MM>/<DD>/<filename>
    REL="${FULLPATH#$ZEEK_INDIR/}"
    VPS_NAME=$(echo "$REL" | cut -d'/' -f1)
    YEAR=$(echo "$REL"     | cut -d'/' -f3)
    MONTH=$(echo "$REL"    | cut -d'/' -f4)
    DAY=$(echo "$REL"      | cut -d'/' -f5)

    if [ -z "$VPS_NAME" ] || [ -z "$YEAR" ] || [ -z "$MONTH" ] || [ -z "$DAY" ]; then
        log "WARNING: Cannot parse VPS/date from path '$FULLPATH' — expected"
        log "  \$ZEEK_INDIR/<vps-name>/pcap/<YYYY>/<MM>/<DD>/<file>.pcap[.zst]"
        log "  Skipping."
        continue
    fi

    DATE="${YEAR}-${MONTH}-${DAY}"
    log "  VPS=$VPS_NAME  date=$DATE"

    # ── Move to finished dir (preserves original structure) ───────────────
    FINISHED_DIR="$ZEEK_OUTDIR/$VPS_NAME/$YEAR/$MONTH/$DAY"
    mkdir -p "$FINISHED_DIR"
    mv "$FULLPATH" "$FINISHED_DIR/$FILENAME"
    MOVED_PATH="$FINISHED_DIR/$FILENAME"

    # ── Decompress if .zst ────────────────────────────────────────────────
    tmpdir=$(mktemp -d)
    PCAP_PATH="$MOVED_PATH"

    if [[ "$FILENAME" == *.zst ]]; then
        DECOMP_NAME="${FILENAME%.zst}"
        DECOMP_PATH="$tmpdir/$DECOMP_NAME"
        log "  Decompressing $FILENAME ..."
        zstd -d --force -q "$MOVED_PATH" -o "$DECOMP_PATH"
        if [ $? -ne 0 ]; then
            log "ERROR: zstd decompression failed for $MOVED_PATH"
            rm -rf "$tmpdir"
            continue
        fi
        PCAP_PATH="$DECOMP_PATH"
    fi

    # ── Run Zeek in tmpdir ────────────────────────────────────────────────
    # Final guard: ensure what we're about to feed Zeek is a regular file
    if [ ! -f "$PCAP_PATH" ]; then
        log "ERROR: PCAP_PATH '$PCAP_PATH' is not a regular file — skipping"
        cd /; rm -rf "$tmpdir"
        continue
    fi
    cd "$tmpdir"
    zeek -C -r "$PCAP_PATH" /usr/local/zeek/share/zeek/site/local.zeek
    log "  Zeek finished"

    # ── Append logs to per-VPS per-day output dir ─────────────────────────
    # Using >> so multiple PCAPs for the same VPS+day accumulate in one set
    # of log files that batch_ingest.py reads as a single daily dataset.
    LOGDIR="$ZEEK_LOGDIR/$VPS_NAME/$DATE"
    mkdir -p "$LOGDIR"
    for f in "$tmpdir"/*.log; do
        [ -f "$f" ] || continue
        cat "$f" >> "$LOGDIR/$(basename $f)"
    done
    log "  Logs appended to $LOGDIR"

    # ── Clean up ──────────────────────────────────────────────────────────
    cd /
    rm -rf "$tmpdir"
done