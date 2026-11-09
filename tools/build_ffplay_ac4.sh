#!/usr/bin/env bash
# HDHR EAS Test - build ffplay (and ffmpeg) 6.1 with the AC-4 audio decoder.
#
# ATSC 3.0 stations send their audio as Dolby AC-4. Stock FFmpeg 6.1 can't
# decode it, so this script patches FFmpeg with Paul B Mahol's AC-4 decoder
# (tools/ffmpeg_ac4.patch, from github.com/funnymanva/ffmpeg-with-ac4) and
# builds it. The GUI's built-in viewer links these FFmpeg libraries (so ATSC
# 3.0 sound plays in the window); the TUI's live viewing uses this ffplay.
#
#   Linux:   tools/build_ffplay_ac4.sh            (needs git or curl, SDL2 dev files, nasm on x86)
#   Windows: run inside the MSYS2 UCRT64 shell    (build_windows.sh calls this for you)
#
# Result: build/ffplay-ac4/out/{bin,lib} and, on Linux, ./ffplay and ./ffmpeg
# in the package folder. Run "make" afterwards so the GUI links it.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TAG=n6.1
WORK="$ROOT/build/ffplay-ac4"
SRC="$WORK/FFmpeg-$TAG"
PREFIX="$WORK/out"
PATCH="$ROOT/tools/ffmpeg_ac4.patch"

case "$(uname -s)" in
    MINGW*|MSYS*) WIN=1; EXE=.exe ;;
    *)            WIN=0; EXE= ;;
esac

if [ -x "$PREFIX/bin/ffplay$EXE" ] && [ "${1:-}" != "--rebuild" ]; then
    echo "ffplay with AC-4 already built ($PREFIX/bin/ffplay$EXE). Use --rebuild to build again."
else
    mkdir -p "$WORK"
    if [ ! -d "$SRC" ]; then
        echo "== Getting FFmpeg $TAG source"
        if command -v git >/dev/null 2>&1; then
            git -c advice.detachedHead=false clone --depth 1 --branch "$TAG" \
                https://github.com/FFmpeg/FFmpeg.git "$SRC"
        else
            curl -fL -o "$WORK/ffmpeg-$TAG.tar.gz" \
                "https://github.com/FFmpeg/FFmpeg/archive/refs/tags/$TAG.tar.gz"
            tar -xzf "$WORK/ffmpeg-$TAG.tar.gz" -C "$WORK"
        fi
        echo "== Applying the AC-4 decoder patch"
        (cd "$SRC" && patch -p1 < "$PATCH")
    fi

    command -v pkg-config >/dev/null 2>&1 && pkg-config --exists sdl2 || {
        echo "SDL2 development files are missing (ffplay needs them)."
        echo "  Debian/Ubuntu/Pi OS: sudo apt install libsdl2-dev     Fedora: sudo dnf install SDL2-devel"
        echo "  Arch: sudo pacman -S sdl2     MSYS2: pacman -S \$MINGW_PACKAGE_PREFIX-SDL2"
        exit 1
    }
    # threads are "autodetect" in FFmpeg, so ask for them by name
    if [ "$WIN" = 1 ]; then PLAT=(--enable-w32threads); else PLAT=(--enable-pthreads); fi
    ASM=()
    case "$(uname -m)" in
        x86_64|i?86) command -v nasm >/dev/null 2>&1 || { echo "(nasm not found - building without x86 assembly; slower decode)"; ASM=(--disable-x86asm); } ;;
    esac

    echo "== Configuring FFmpeg (a few minutes)"
    cd "$SRC"
    # --disable-autodetect keeps the result portable: only SDL2 and zlib are used.
    ./configure --prefix="$PREFIX" \
        --disable-doc --disable-debug --disable-ffprobe \
        --enable-ffplay --enable-ffmpeg \
        --disable-autodetect --enable-sdl2 --enable-zlib "${PLAT[@]}" \
        --extra-cflags="-Wno-incompatible-pointer-types -Wno-int-conversion" \
        "${ASM[@]}"
    grep -qs "CONFIG_AC4_DECODER 1" config_components.h config.h || { echo "AC-4 decoder not enabled - patch failed?"; exit 1; }
    echo "== Building (10-30 minutes; a Pi 5 takes longer)"
    JOBS=$( (nproc || sysctl -n hw.ncpu || echo 4) 2>/dev/null | head -1)
    make -j"$JOBS"
    make install
fi

DEC=$("$PREFIX/bin/ffplay$EXE" -hide_banner -decoders 2>/dev/null || true)
case "$DEC" in
    *" ac4 "*) echo "AC-4 decoder: present" ;;
    *) echo "AC-4 decoder missing from the build!"; exit 1 ;;
esac

if [ "$WIN" = 0 ]; then
    cp "$PREFIX/bin/ffplay" "$PREFIX/bin/ffmpeg" "$ROOT/"
    echo
    echo "Installed ./ffplay and ./ffmpeg (with AC-4) next to hdhr_eas_test."
fi
