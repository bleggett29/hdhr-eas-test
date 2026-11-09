#!/bin/sh
# HDHR EAS Test v0.5 - install script
#
#   ./install.sh          check for the required packages, offer to install
#                         any that are missing, then build
#   ./install.sh --check  only check and report; change nothing
#   ./install.sh --gui    also install GTK 4 and build the desktop GUI
#   ./install.sh --no-gui don't ask about the GUI
#   ./install.sh --ffplay also build ffplay with AC-4 audio (live viewing; 15-30 min)
#   ./install.sh --no-ffplay don't ask about ffplay
#
# Works with apt (Debian, Ubuntu, Raspberry Pi OS), dnf/yum (Fedora, RHEL,
# Rocky, Alma), zypper (openSUSE), pacman (Arch, Manjaro), apk (Alpine),
# xbps (Void) and emerge (Gentoo).

set -u
cd "$(dirname "$0")" || exit 1
CHECK_ONLY=0
GUI=ask
FFPLAY=ask
for a in "$@"; do
    case "$a" in
        --check)     CHECK_ONLY=1 ;;
        --gui)       GUI=yes ;;
        --no-gui)    GUI=no ;;
        --ffplay)    FFPLAY=yes ;;
        --no-ffplay) FFPLAY=no ;;
        *) echo "usage: ./install.sh [--check] [--gui|--no-gui] [--ffplay|--no-ffplay]"; exit 2 ;;
    esac
done

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ok]      %s\n' "$*"; }
miss() { printf '  [MISSING] %s\n' "$*"; }

# ---------------------------------------------------------------- checks
MISSING=""
need() { MISSING="$MISSING $1"; }

check_all() {
    MISSING=""
    say "Checking what's needed to build and run HDHR EAS Test:"
    for t in cc make pkg-config python3; do
        if command -v "$t" >/dev/null 2>&1; then ok "$t"; else miss "$t"; need "$t"; fi
    done
    # libraries, checked through pkg-config where they publish a .pc file
    for pc in ncurses:ncurses libxml-2.0:libxml2 zlib:zlib openssl:openssl \
              libavcodec:ffmpeg-libavcodec libavutil:ffmpeg-libavutil; do
        mod=${pc%%:*}; label=${pc#*:}
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists "$mod" 2>/dev/null; then
            ok "$label"
        elif [ "$mod" = "ncurses" ] && command -v pkg-config >/dev/null 2>&1 && pkg-config --exists ncursesw 2>/dev/null; then
            ok "$label (ncursesw)"
        elif [ "$mod" = "ncurses" ] && [ -f /usr/include/ncurses.h ]; then
            ok "$label"
        else
            miss "$label development files"; need "$label"
        fi
    done
    # libpcap doesn't always ship a .pc file - look for the header too
    if { command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libpcap 2>/dev/null; } || \
       [ -f /usr/include/pcap.h ] || [ -f /usr/include/pcap/pcap.h ] || [ -f /usr/local/include/pcap.h ]; then
        ok "libpcap"
    else
        miss "libpcap development files"; need "libpcap"
    fi
    if command -v systemctl >/dev/null 2>&1; then ok "systemctl (only needed for --pause-services)"; fi
    [ -z "$MISSING" ]
}

have_gtk4() { command -v pkg-config >/dev/null 2>&1 && pkg-config --exists gtk4 2>/dev/null; }

# ---------------------------------------------------------------- package manager
PM=""
for p in apt-get dnf yum zypper pacman apk xbps-install emerge; do
    if command -v "$p" >/dev/null 2>&1; then PM=$p; break; fi
done

pkgs_for() {
    case "$PM" in
    apt-get)
        echo "build-essential pkg-config python3 libncurses-dev libxml2-dev zlib1g-dev libssl-dev libavcodec-dev libavutil-dev libpcap-dev" ;;
    dnf|yum)
        # FFmpeg headers: Fedora ships ffmpeg-free-devel; RHEL/Rocky/Alma need EPEL + RPM Fusion (ffmpeg-devel)
        if [ "$PM" = dnf ] && dnf -q list --available ffmpeg-free-devel >/dev/null 2>&1; then FF=ffmpeg-free-devel; else FF=ffmpeg-devel; fi
        echo "gcc make pkgconf-pkg-config python3 ncurses-devel libxml2-devel zlib-devel openssl-devel libpcap-devel $FF" ;;
    zypper)
        # openSUSE: FFmpeg headers come from the main repo (ffmpeg-*-devel) or Packman
        echo "gcc make pkg-config python3 ncurses-devel libxml2-devel zlib-devel libopenssl-devel libpcap-devel ffmpeg-7-libavcodec-devel ffmpeg-7-libavutil-devel" ;;
    pacman)
        echo "base-devel pkgconf python ncurses libxml2 zlib openssl ffmpeg libpcap" ;;
    apk)
        echo "build-base pkgconf python3 ncurses-dev libxml2-dev zlib-dev openssl-dev ffmpeg-dev libpcap-dev linux-headers" ;;
    xbps-install)
        echo "base-devel pkg-config python3 ncurses-devel libxml2-devel zlib-devel openssl-devel ffmpeg-devel libpcap-devel" ;;
    emerge)
        echo "dev-build/make dev-util/pkgconf dev-lang/python sys-libs/ncurses dev-libs/libxml2 sys-libs/zlib dev-libs/openssl media-video/ffmpeg net-libs/libpcap" ;;
    esac
}

gui_pkgs_for() {
    case "$PM" in
    # GTK 4, plus SDL2 and FFmpeg's format/filter/scale libraries for the built-in viewer
    apt-get)      echo "libgtk-4-dev libsdl2-dev libavformat-dev libavfilter-dev libswscale-dev libswresample-dev" ;;
    dnf|yum)      echo "gtk4-devel SDL2-devel" ;;
    zypper)       echo "gtk4-devel libSDL2-devel" ;;
    pacman)       echo "gtk4 sdl2" ;;
    apk)          echo "gtk4.0-dev sdl2-dev" ;;
    xbps-install) echo "gtk4-devel SDL2-devel" ;;
    emerge)       echo "gui-libs/gtk media-libs/libsdl2" ;;
    esac
}

ffplay_pkgs_for() {
    case "$PM" in
    apt-get)      echo "libsdl2-dev nasm git patch" ;;
    dnf|yum)      echo "SDL2-devel nasm git patch" ;;
    zypper)       echo "libSDL2-devel nasm git patch" ;;
    pacman)       echo "sdl2 nasm git patch" ;;
    apk)          echo "sdl2-dev nasm git patch" ;;
    xbps-install) echo "SDL2-devel nasm git patch" ;;
    emerge)       echo "media-libs/libsdl2 dev-lang/nasm dev-vcs/git sys-devel/patch" ;;
    esac
}

have_ac4_ffplay() { [ -x ./ffplay ] && ./ffplay -hide_banner -decoders 2>/dev/null | grep -q " ac4 "; }

install_cmd() {
    case "$PM" in
    apt-get)      echo "apt-get update && apt-get install -y $1" ;;
    dnf)          echo "dnf install -y $1" ;;
    yum)          echo "yum install -y $1" ;;
    zypper)       echo "zypper --non-interactive install $1" ;;
    pacman)       echo "pacman -S --needed --noconfirm $1" ;;
    apk)          echo "apk add $1" ;;
    xbps-install) echo "xbps-install -Sy $1" ;;
    emerge)       echo "emerge --noreplace $1" ;;
    esac
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then sh -c "$1"
    elif command -v sudo >/dev/null 2>&1; then sudo sh -c "$1"
    elif command -v doas >/dev/null 2>&1; then doas sh -c "$1"
    else say "Need root to install packages (no sudo or doas found). Run as root: $1"; return 1
    fi
}

# ---------------------------------------------------------------- main
say "HDHR EAS Test v0.5 - installer"
say ""
if check_all; then
    say ""
    say "Everything needed is installed."
else
    say ""
    if [ "$CHECK_ONLY" -eq 1 ]; then
        say "Missing:$MISSING"
        exit 1
    fi
    if [ -z "$PM" ]; then
        say "No supported package manager found. Install the development packages for:"
        say "  C compiler, make, pkg-config, python3, ncurses, libxml2, zlib, openssl, ffmpeg (libavcodec/libavutil), libpcap"
        exit 1
    fi
    PKGS=$(pkgs_for)
    CMD=$(install_cmd "$PKGS")
    say "Package manager: $PM"
    say "To install the missing pieces this will run (as root):"
    say "  $CMD"
    case "$PM" in
        dnf|yum) say "  (RHEL/Rocky/Alma: FFmpeg headers need EPEL and RPM Fusion enabled first.)" ;;
        zypper)  say "  (If the FFmpeg packages aren't found, add the Packman repo or install libavcodec-devel/libavutil-devel.)" ;;
    esac
    printf 'Install now? [Y/n] '
    read -r ans
    case "$ans" in n|N|no|NO) say "Not installing. Re-run when ready."; exit 1 ;; esac
    as_root "$CMD" || { say "Package install failed - see the messages above."; exit 1; }
    say ""
    if ! check_all; then
        say ""
        say "Still missing:$MISSING"
        say "Install those by hand (names differ between distributions), then run ./install.sh again."
        exit 1
    fi
fi

# ---------------------------------------------------------------- optional GUI
if have_gtk4; then
    say "  [ok]      GTK 4 (the desktop GUI will be built too)"
elif [ "$CHECK_ONLY" -eq 1 ]; then
    say "  [--]      GTK 4 not installed (optional: only for the desktop GUI; the TUI has every feature)"
else
    if [ "$GUI" = ask ]; then
        say ""
        say "Optional: a desktop GUI (GTK 4) can be built as well. It needs a desktop"
        say "session; the TUI works anywhere, including over SSH, and has every feature."
        printf 'Install GTK 4 and build the GUI too? [y/N] '
        read -r ans
        case "$ans" in y|Y|yes|YES) GUI=yes ;; *) GUI=no ;; esac
    fi
    if [ "$GUI" = yes ]; then
        if [ -z "$PM" ]; then
            say "No supported package manager found - install the GTK 4 development package yourself."
        else
            GCMD=$(install_cmd "$(gui_pkgs_for)")
            say "Running (as root): $GCMD"
            as_root "$GCMD" || say "GTK 4 install failed - continuing without the GUI."
            have_gtk4 || say "GTK 4 still not found - the GUI will be skipped."
        fi
    fi
fi

# ---------------------------------------------------------------- optional ffplay with AC-4
if have_ac4_ffplay; then
    say "  [ok]      ffplay with AC-4 (live viewing)"
    FFPLAY=no
elif [ "$CHECK_ONLY" -eq 1 ]; then
    say "  [--]      ffplay with AC-4 not built (optional: live viewing; run tools/build_ffplay_ac4.sh)"
else
    if [ "$FFPLAY" = ask ]; then
        say ""
        say "Optional: live viewing (Watch in the GUI, v in the TUI) needs FFmpeg with the"
        say "AC-4 decoder for ATSC 3.0 sound. Building it takes 15-30 minutes (longer on a"
        say "Pi) and is only useful with a display to watch on."
        printf 'Build FFmpeg/ffplay with AC-4 now? [y/N] '
        read -r ans
        case "$ans" in y|Y|yes|YES) FFPLAY=yes ;; *) FFPLAY=no ;; esac
    fi
    if [ "$FFPLAY" = yes ] && [ -n "$PM" ]; then
        FCMD=$(install_cmd "$(ffplay_pkgs_for)")
        say "Running (as root): $FCMD"
        as_root "$FCMD" || say "Package install failed - the ffplay build may fail."
    fi
fi

[ "$CHECK_ONLY" -eq 1 ] && exit 0

say ""
say "Building..."
if make >build.log 2>&1; then
    say "Build OK. Details in build.log."
    say ""
    say "Run it:   ./hdhr_eas_test            (you free the tuners yourself)"
    say "     or:  ./hdhr_eas_test --pause-services"
    say "Then press e for the EAS screen. See README.md."
    if [ -x ./hdhr_eas_test_gui ]; then
        say "Desktop GUI: ./hdhr_eas_test_gui   (same options; EAS Test tab)"
    fi
    if [ "$FFPLAY" = yes ]; then
        say ""
        say "Building ffplay with AC-4 (15-30 minutes; log in ffplay_build.log)..."
        if tools/build_ffplay_ac4.sh >ffplay_build.log 2>&1; then
            say "ffplay with AC-4 built: ./ffplay"
            if have_gtk4; then
                say "Relinking the GUI's viewer with it..."
                make gui >>build.log 2>&1 && say "GUI viewer now has AC-4 sound." || say "GUI relink failed - see build.log"
            fi
        else
            say "ffplay build FAILED (the rest works). Last lines of ffplay_build.log:"
            tail -n 15 ffplay_build.log
        fi
    fi
else
    say "Build FAILED. Last lines of build.log:"
    tail -n 20 build.log
    exit 1
fi
