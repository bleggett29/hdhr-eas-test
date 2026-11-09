#!/usr/bin/env bash
# HDHR EAS Test v0.5 - Windows 10/11 build (64-bit)
#
# Run this inside the MSYS2 "UCRT64" shell (https://www.msys2.org), from the
# folder that holds this script:
#
#     ./build_windows.sh             install the build packages with pacman, then build
#     ./build_windows.sh --no-deps   build only (packages already installed)
#     ./build_windows.sh --no-ffplay skip building FFmpeg with AC-4 (the viewer
#                                    then has no ATSC 3.0 sound)
#
# The first run also builds FFmpeg 6.1 with the AC-4 audio decoder
# (tools/build_ffplay_ac4.sh, 15-30 minutes): the GUI's built-in viewer links
# it, and ffplay.exe/ffmpeg.exe come along. Later runs reuse it.
#
# Result: dist/hdhr_eas_test/  (a self-contained folder - copy it anywhere)
#         dist/hdhr_eas_test_v0.5_windows_x64.zip
#
#   hdhr_eas_test.exe   the GTK 4 GUI (double-click this)
#   hdhr_eas_cli.exe    command-line runner (optional; scripting)
#   render.exe          RENDER, used for the ATSC 3.0 reports
#   ffplay.exe          plays saved .ts files (with AC-4 audio); ffmpeg.exe too
#   *.dll, share\, lib\ GTK 4 / FFmpeg / libxml2 / OpenSSL runtime
set -euo pipefail
cd "$(dirname "$0")"

VER=0.5
case "${MSYSTEM:-}" in
    UCRT64|MINGW64|CLANG64) ;;
    *) echo "Run this from the MSYS2 UCRT64 shell (Start menu: 'MSYS2 UCRT64')."; exit 1 ;;
esac
PFX=${MINGW_PACKAGE_PREFIX:?MSYS2 environment not set}
ROOT=${MINGW_PREFIX:?MSYS2 environment not set}     # /ucrt64

DEPS=1; FFPLAY=1
for a in "$@"; do
    case "$a" in
        --no-deps)   DEPS=0 ;;
        --no-ffplay) FFPLAY=0 ;;
        *) echo "usage: ./build_windows.sh [--no-deps] [--no-ffplay]"; exit 2 ;;
    esac
done

if [ "$DEPS" = 1 ]; then
    echo "== Installing build packages (pacman)"
    pacman -S --needed --noconfirm make zip git patch \
        "$PFX-gcc" "$PFX-pkgconf" "$PFX-gtk4" "$PFX-libxml2" \
        "$PFX-ffmpeg" "$PFX-openssl" "$PFX-zlib" "$PFX-SDL2" "$PFX-nasm"
fi

for m in gtk4 libxml-2.0 libavcodec libavutil openssl zlib; do
    pkg-config --exists "$m" || { echo "Missing $m - run without --no-deps"; exit 1; }
done

B=build/win
OUT=dist/hdhr_eas_test
rm -rf "$B" "$OUT"
mkdir -p "$B" "$OUT"

CC=${CC:-gcc}
WARN="-Wall -Wno-format-truncation -Wno-unused-function"
HDINC="-Isrc/tui/libhdhomerun"
WINLIBS="-lws2_32 -liphlpapi -lbcrypt"

echo "== libhdhomerun (Silicondust, LGPL-2.1)"
HD=""
for f in channels channelscan control debug device device_selector discover \
         pkt sock video os_windows sock_windows; do
    # Silicondust builds the Windows library as UNICODE (registry calls use L"" strings)
    $CC -O2 $WARN -DUNICODE -D_UNICODE $HDINC -c "src/tui/libhdhomerun/hdhomerun_$f.c" -o "$B/hd_$f.o"
    HD="$HD $B/hd_$f.o"
done

ENGINE="src/tui/eas_capture.c src/tui/eas_run.c src/tui/plat.c src/tui/zipw.c src/tui/l1_detail_parser.c"

# FFmpeg 6.1 with AC-4: ffplay.exe/ffmpeg.exe, plus the static libraries the
# GUI's built-in viewer links (so ATSC 3.0 audio plays in the window).
AC4_PC="$(pwd)/build/ffplay-ac4/out/lib/pkgconfig"
FF_MODS="libavformat libavfilter libavcodec libswscale libswresample libavutil"
if [ "$FFPLAY" = 1 ]; then
    echo "== FFmpeg 6.1 with AC-4 (first time: 15-30 minutes)"
    tools/build_ffplay_ac4.sh
fi
# SDL2 for the viewer's sound. Not SDL2main, and not sdl2.pc's -Dmain=SDL_main:
# the GUI has its own main().
SDL_CFLAGS=$(pkg-config --cflags sdl2 | sed 's/-Dmain=SDL_main//g')
if [ -f "$AC4_PC/libavcodec.pc" ]; then
    VIEWER_CFLAGS="-DHAVE_VIEWER $(PKG_CONFIG_PATH="$AC4_PC" pkg-config --cflags $FF_MODS) $SDL_CFLAGS"
    VIEWER_LIBS="$(PKG_CONFIG_PATH="$AC4_PC" pkg-config --static --libs $FF_MODS) -lSDL2 -lwinmm"
    echo "   viewer: FFmpeg with AC-4 (static)"
else
    VIEWER_CFLAGS="-DHAVE_VIEWER $(pkg-config --cflags $FF_MODS) $SDL_CFLAGS"
    VIEWER_LIBS="$(pkg-config --libs $FF_MODS) -lSDL2 -lwinmm"
    echo "   viewer: MSYS2 FFmpeg - NO AC-4, ATSC 3.0 audio will be silent (built with --no-ffplay)"
fi

echo "== hdhr_eas_test.exe (GUI)"
$CC -O2 $WARN $HDINC $(pkg-config --cflags gtk4) $VIEWER_CFLAGS -mwindows -o "$OUT/hdhr_eas_test.exe" \
    src/tui/gui.c src/tui/gui_eas.c src/tui/hdhr_dev.c src/tui/player.c src/tui/viewer.c $ENGINE $HD \
    $VIEWER_LIBS $(pkg-config --libs gtk4) $(pkg-config --libs zlib) $WINLIBS -lpthread

echo "== hdhr_eas_cli.exe (command line)"
$CC -O2 $WARN $HDINC -o "$OUT/hdhr_eas_cli.exe" src/tui/eas_cli.c $ENGINE $HD \
    $(pkg-config --libs zlib) $WINLIBS -lpthread

echo "== render.exe (RENDER 0.4 + EAS)"
# render/win/ supplies the POSIX network headers Windows lacks, and <pcap.h>
# maps to the built-in pcap_lite reader (no Npcap/WinPcap needed).
RSRC=""
for f in a3render mmt input plp l1_detail_parser crypto esg bps egps utility direct_parsers eas pcap_lite; do
    RSRC="$RSRC src/render/$f.c"
done
build_render() {
    $CC -O2 $WARN -Wno-pointer-sign -Wno-unused-variable -Wno-unused-but-set-variable "$@" \
        -D_FILE_OFFSET_BITS=64 -Isrc/render/win -Isrc/render -Isrc/render/libhdhomerun \
        $(pkg-config --cflags libxml-2.0 libavcodec libavutil openssl zlib) \
        -o "$OUT/render.exe" $RSRC $HD \
        $(pkg-config --libs libxml-2.0 libavcodec libavutil openssl zlib) $WINLIBS -lpthread -lm
}
if ! build_render; then
    # GCC 16 has crashed ("internal compiler error") inside Windows' wingdi.h
    # here. RENDER needs no graphics API, so try again without it.
    echo "   retrying RENDER without the Windows graphics headers"
    build_render -DWIN32_LEAN_AND_MEAN -DNOGDI
fi

if [ "$FFPLAY" = 1 ]; then
    cp build/ffplay-ac4/out/bin/ffplay.exe build/ffplay-ac4/out/bin/ffmpeg.exe "$OUT/"
fi

echo "== Collecting runtime DLLs"
copy_deps() {   # copy every DLL from the MSYS2 prefix that the given files need
    local d list
    # "|| true": finding no new DLLs is normal, not an error
    list=$(ldd "$@" 2>/dev/null | awk '{print $3}' | grep -i "^$ROOT/bin/" | sort -u || true)
    for d in $list; do
        [ -f "$OUT/$(basename "$d")" ] || cp "$d" "$OUT/"
    done
    return 0
}
copy_deps "$OUT"/*.exe
copy_deps "$OUT"/*.dll       # second pass catches DLLs pulled in by DLLs
copy_deps "$OUT"/*.dll

echo "== GTK 4 runtime data"
mkdir -p "$OUT/share/glib-2.0/schemas" "$OUT/share/icons" "$OUT/lib"
cp "$ROOT"/share/glib-2.0/schemas/*.xml "$OUT/share/glib-2.0/schemas/" 2>/dev/null || true
glib-compile-schemas "$OUT/share/glib-2.0/schemas"
for theme in Adwaita hicolor; do
    if [ -d "$ROOT/share/icons/$theme" ]; then cp -r "$ROOT/share/icons/$theme" "$OUT/share/icons/"; fi
done
if [ -d "$ROOT/lib/gdk-pixbuf-2.0" ]; then
    cp -r "$ROOT/lib/gdk-pixbuf-2.0" "$OUT/lib/"
    copy_deps "$OUT"/lib/gdk-pixbuf-2.0/2.10.0/loaders/*.dll
    # the cache holds absolute paths; make them relative to the app folder
    LC="$OUT/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"
    # (gdk-pixbuf on Windows resolves relative entries against the app folder)
    if [ -f "$LC" ]; then
        sed -i -E 's#"[^"]*[/\\]+lib[/\\]+gdk-pixbuf-2\.0[/\\]+([^"]*)"#"lib/gdk-pixbuf-2.0/\1"#; :a; s#(lib/gdk-pixbuf-2\.0/[^"\\]*)\\+#\1/#; ta' "$LC"
    fi
fi

echo "== Docs and licenses"
cp LICENSE "$OUT/LICENSE.txt"
cp -r licenses "$OUT/"
cp README.md "$OUT/README.md"
cat > "$OUT/START HERE.txt" <<EOF
HDHR EAS Test v$VER for Windows 10/11
Copyright (C) 2026 Brian Scott. GPLv3 - see LICENSE.txt and the licenses folder.

Double-click hdhr_eas_test.exe.
  Tuners tab   - pick a tuner, change channels, watch it in the viewer, save test captures
  EAS Test tab - pick a channel per tuner, run a short test, arm the real run

Keep this whole folder together (render.exe and the DLLs must stay next to
hdhr_eas_test.exe). Watch... plays the tuner right in the window, with AC-4
sound for ATSC 3.0; double-click the picture for full screen (Esc to return).
ffplay.exe is included for playing saved .ts files. Optional extra:
  Python 3 (python.org)  - "Web server on" for viewing reports from other PCs
See README.md for the full instructions.
EOF

echo "== Zip"
( cd dist && rm -f "hdhr_eas_test_v${VER}_windows_x64.zip" && zip -qr "hdhr_eas_test_v${VER}_windows_x64.zip" hdhr_eas_test )
du -sh "$OUT" "dist/hdhr_eas_test_v${VER}_windows_x64.zip"
echo
echo "Done: dist/hdhr_eas_test/hdhr_eas_test.exe"
echo "      dist/hdhr_eas_test_v${VER}_windows_x64.zip"
