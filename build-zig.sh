#!/usr/bin/env bash
# modlink - cross-compile check from macOS/Linux using zig.
#
# This does NOT replace testing on Windows; it exists so compile errors are
# caught without a Windows machine in the loop. It links a real .exe.
set -euo pipefail
cd "$(dirname "$0")"

ZIG="${ZIG:-zig}"
TARGET="${TARGET:-x86_64-windows-gnu}"
OUT="build/modlink.exe"

mkdir -p build

RCFLAGS=()
if [ -f res/3proxy.exe ]; then
  "$ZIG" rc --output build/modlink.res.o -- /i res res/modlink.rc 2>/dev/null \
    && RCFLAGS+=(build/modlink.res.o) \
    || echo "  note: resource compile skipped (zig rc unavailable)"
else
  echo "  note: res/3proxy.exe missing - building without the embedded engine"
fi

"$ZIG" cc -target "$TARGET" -o "$OUT" \
  src/main.c src/util.c src/json.c src/config.c src/proxy3.c \
  src/net.c src/hilink.c src/reconn.c src/ui_theme.c src/ui_main.c \
  ${RCFLAGS[@]+"${RCFLAGS[@]}"} \
  -Isrc -O2 -Wall -Wextra -Wno-unused-parameter \
  -DUNICODE -D_UNICODE \
  -Wl,/subsystem:windows \
  -luser32 -lgdi32 -lcomctl32 -lshell32 -lole32 \
  -lwinhttp -lws2_32 -ldwmapi -luxtheme -ladvapi32

echo "  OK: $OUT"
