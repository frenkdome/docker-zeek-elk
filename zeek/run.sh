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
#
# Parallelism: up to ZEEK_WORKERS Zeek processes run simultaneously.
# Set ZEEK_WORKERS in the container environment (default: 4).

ZEEK_WORKERS=${ZEEK_WORKERS:-4}

function log() {
    echo "$(date -Iseconds) $1"
}

# ── Per-PCAP processing (runs as a background job) ────────────────────────────
function process_pcap() {
    local FULLPATH="$1"

    local FILENAME
    FILENAME=$(basename "$FULLPATH")
    log "New PCAP: $FULLPATH"

    # ── Parse VPS name and date from path ────────────────────────────────
    # Strip leading ZEEK_INDIR prefix → relative path
    # Relative: <vps-name>/pcap/<YYYY>/<MM>/<DD>/<filename>
    local REL VPS_NAME YEAR MONTH DAY DATE
    REL="${FULLPATH#$ZEEK_INDIR/}"
    VPS_NAME=$(echo "$REL" | cut -d'/' -f1)
    YEAR=$(echo "$REL"     | cut -d'/' -f3)
    MONTH=$(echo "$REL"    | cut -d'/' -f4)
    DAY=$(echo "$REL"      | cut -d'/' -f5)

    if [ -z "$VPS_NAME" ] || [ -z "$YEAR" ] || [ -z "$MONTH" ] || [ -z "$DAY" ]; then
        log "WARNING: Cannot parse VPS/date from path '$FULLPATH' — expected"
        log "  \$ZEEK_INDIR/<vps-name>/pcap/<YYYY>/<MM>/<DD>/<file>.pcap[.zst]"
        log "  Skipping."
        return
    fi

    DATE="${YEAR}-${MONTH}-${DAY}"
    log "  VPS=$VPS_NAME  date=$DATE"

    # ── Duplicate check: skip if this PCAP was already processed ─────────
    # A PCAP is considered processed if a file with the same base name
    # (with or without .zst) already exists in the finished directory.
    local FINISHED_DIR="$ZEEK_OUTDIR/$VPS_NAME/$YEAR/$MONTH/$DAY"
    local BASE_NOEXT="${FILENAME%.zst}"
    if [ -f "$FINISHED_DIR/$FILENAME" ] || [ -f "$FINISHED_DIR/$BASE_NOEXT" ]; then
        log "  DUPLICATE: $FILENAME already in $FINISHED_DIR — skipping"
        return
    fi

    # ── Move to finished dir temporarily for tracking ─────────────────────
    mkdir -p "$FINISHED_DIR"
    mv "$FULLPATH" "$FINISHED_DIR/$FILENAME"
    local MOVED_PATH="$FINISHED_DIR/$FILENAME"

    # ── Decompress if .zst ────────────────────────────────────────────────
    local tmpdir PCAP_PATH
    tmpdir=$(mktemp -d)
    PCAP_PATH="$MOVED_PATH"

    if [[ "$FILENAME" == *.zst ]]; then
        local DECOMP_NAME="${FILENAME%.zst}"
        local DECOMP_PATH="$tmpdir/$DECOMP_NAME"
        log "  Decompressing $FILENAME ..."
        zstd -d --force -q "$MOVED_PATH" -o "$DECOMP_PATH"
        if [ $? -ne 0 ]; then
            log "ERROR: zstd decompression failed for $MOVED_PATH"
            rm -rf "$tmpdir"
            return
        fi
        PCAP_PATH="$DECOMP_PATH"
    fi

    # ── Run Zeek in tmpdir ────────────────────────────────────────────────
    # Final guard: ensure what we're about to feed Zeek is a regular file
    if [ ! -f "$PCAP_PATH" ]; then
        log "ERROR: PCAP_PATH '$PCAP_PATH' is not a regular file — skipping"
        rm -rf "$tmpdir"
        return
    fi
    ( cd "$tmpdir" && zeek -C -r "$PCAP_PATH" /usr/local/zeek/share/zeek/site/local.zeek )
    log "  Zeek finished: $FILENAME"

    # ── Append logs to per-VPS per-day output dir ─────────────────────────
    # Using >> so multiple PCAPs for the same VPS+day accumulate in one set
    # of log files that batch_ingest.py reads as a single daily dataset.
    # flock prevents interleaved writes when two jobs share the same LOGDIR.
    local LOGDIR="$ZEEK_LOGDIR/$VPS_NAME/$DATE"
    mkdir -p "$LOGDIR"
    (
        flock -x 9
        for f in "$tmpdir"/*.log; do
            [ -f "$f" ] || continue
            cat "$f" >> "$LOGDIR/$(basename "$f")"
        done
    ) 9>"$LOGDIR/.lock"
    log "  Logs appended to $LOGDIR"

    # ── Clean up: delete PCAP after successful ingestion ──────────────────
    rm -rf "$tmpdir"
    rm -f "$MOVED_PATH"
    log "  PCAP deleted: $FILENAME (fully ingested)"
}

# ── Main watcher loop ─────────────────────────────────────────────────────────
log "Watching $ZEEK_INDIR recursively for PCAP files (workers=${ZEEK_WORKERS})..."

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
    [[ "$FULLPATH" =~ \.pcap([0-9]*)(\.zst)?$ ]] || continue

    # Throttle: wait until a worker slot is free
    while [ "$(jobs -rp | wc -l)" -ge "$ZEEK_WORKERS" ]; do
        wait -n 2>/dev/null || sleep 0.2
    done

    process_pcap "$FULLPATH" &
done

# Drain any in-flight jobs before exiting
wait