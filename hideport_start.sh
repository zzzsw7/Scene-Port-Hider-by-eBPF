#!/system/bin/sh

MODDIR=${0%/*}
CONF="$MODDIR/hideport.conf"
LOADER="$MODDIR/system/bin/hideport_loader"
LOG="$MODDIR/hideport.log"
PIDFILE="/dev/hideport_loader.pid"
LOCKDIR="/dev/hideport_loader.lock"

PKG="com.omarea.vtools"
PORTS="8788 8765 14731 14754"
ENABLE_EBPF=1
WAIT_FOR_PROCESS=0
EXTRA_ALLOWED_UIDS=""
WAIT_FOR_UID_TIMEOUT=300

[ -f "$CONF" ] && . "$CONF"
START_CONTEXT="${1:-manual}"

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" >> "$LOG"
}

is_running() {
    [ -f "$PIDFILE" ] || return 1
    local pid
    pid="$(cat "$PIDFILE" 2>/dev/null)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

if ! mkdir "$LOCKDIR" 2>/dev/null; then
    sleep 2
    if is_running; then
        log_msg "$START_CONTEXT" "hideport_loader is already running"
        exit 0
    fi
    log_msg "$START_CONTEXT" "another hideport_loader start is in progress"
    exit 0
fi

cleanup_lock() {
    rmdir "$LOCKDIR" 2>/dev/null
}

trap cleanup_lock EXIT INT TERM

user_to_uid() {
    local user="$1"
    local android_user app_id app_num

    case "$user" in
        '' ) return 1 ;;
        root) echo 0; return 0 ;;
        system) echo 1000; return 0 ;;
        shell) echo 2000; return 0 ;;
        [0-9]*) echo "$user"; return 0 ;;
    esac

    android_user="$(echo "$user" | sed -n 's/^u\([0-9][0-9]*\)_a[0-9][0-9]*$/\1/p')"
    app_num="$(echo "$user" | sed -n 's/^u[0-9][0-9]*_a\([0-9][0-9]*\)$/\1/p')"
    if [ -n "$android_user" ] && [ -n "$app_num" ]; then
        app_id=$((10000 + app_num))
        echo $((android_user * 100000 + app_id))
        return 0
    fi

    return 1
}

append_unique_uid() {
    local list="$1"
    local uid="$2"

    [ -n "$uid" ] || {
        echo "$list"
        return 0
    }

    case " $list " in
        *" $uid "*) echo "$list" ;;
        *) echo "$list $uid" ;;
    esac
}

get_app_uids() {
    local uid user trusted_uids extra_uids stat_uids line

    trusted_uids=""
    extra_uids=""
    stat_uids=""

    uid="$(dumpsys package "$PKG" 2>/dev/null | sed -n 's/.*userId=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
    trusted_uids="$(append_unique_uid "$trusted_uids" "$uid")"

    uid="$(cmd package list packages -U "$PKG" 2>/dev/null | sed -n 's/.* uid:\([0-9][0-9]*\).*/\1/p' | head -n 1)"
    trusted_uids="$(append_unique_uid "$trusted_uids" "$uid")"

    while IFS= read -r line; do
        user="${line%% *}"
        uid="$(user_to_uid "$user" 2>/dev/null)"
        trusted_uids="$(append_unique_uid "$trusted_uids" "$uid")"
    done <<EOF
$(ps -A -o USER,ARGS 2>/dev/null | grep -F "$PKG")
EOF

    extra_uids="$(echo "$EXTRA_ALLOWED_UIDS" | tr ' ' '\n' | sed '/^$/d' | sort -n -u | tr '\n' ' ')"

    if [ -z "$(echo "$trusted_uids $extra_uids" | tr ' ' '\n' | sed '/^$/d' | head -n 1)" ]; then
        return 1
    fi

    uid="$(stat -c "%u" "/data/data/$PKG" 2>/dev/null)"
    stat_uids="$(append_unique_uid "$stat_uids" "$uid")"

    echo "$trusted_uids $extra_uids $stat_uids" | tr ' ' '\n' | sed '/^$/d' | sort -n -u | tr '\n' ' '
}

wait_for_uid() {
    local uids
    local i=0

    while [ "$i" -lt "$WAIT_FOR_UID_TIMEOUT" ]; do
        uids="$(get_app_uids)"
        if [ -n "$uids" ]; then
            echo "$uids"
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done

    return 1
}

wait_for_process_if_requested() {
    [ "$WAIT_FOR_PROCESS" = "1" ] || return 0

    while ! pidof "$PKG" >/dev/null 2>&1; do
        sleep 1
    done
    sleep 3
}

if [ "$ENABLE_EBPF" != "1" ]; then
    log_msg "$START_CONTEXT" "eBPF loader disabled by config"
    exit 0
fi

if is_running; then
    log_msg "$START_CONTEXT" "hideport_loader is already running"
    exit 0
fi

if [ ! -x "$LOADER" ]; then
    log_msg "$START_CONTEXT" "missing executable: $LOADER"
    exit 1
fi

APP_UIDS="$(wait_for_uid)"
if [ -z "$APP_UIDS" ]; then
    log_msg "$START_CONTEXT" "failed to resolve UID for package $PKG"
    exit 1
fi

wait_for_process_if_requested

ARGS=""
for port in $PORTS; do
    ARGS="$ARGS --port $port"
done
for uid in $APP_UIDS; do
    ARGS="$ARGS --uid $uid"
done

log_msg "$START_CONTEXT" "starting hideport_loader for package $PKG uids $APP_UIDS ports $PORTS"
"$LOADER" $ARGS >> "$LOG" 2>&1 &
echo "$!" > "$PIDFILE"
