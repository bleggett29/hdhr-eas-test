# Makefile for hdhomerun_tui

# Compiler and flags
CC = gcc
CFLAGS = -Wall -I./libhdhomerun
LDFLAGS = -lncurses -lpthread -lz

# OS Detection
OS := $(shell uname -s)

# Name of the final executable
TARGET = hdhomerun_tui

# Base library sources
LIB_SRCS_BASE = \
	libhdhomerun/hdhomerun_channels.c \
	libhdhomerun/hdhomerun_channelscan.c \
	libhdhomerun/hdhomerun_control.c \
	libhdhomerun/hdhomerun_debug.c \
	libhdhomerun/hdhomerun_device.c \
	libhdhomerun/hdhomerun_device_selector.c \
	libhdhomerun/hdhomerun_discover.c \
	libhdhomerun/hdhomerun_os_posix.c \
	libhdhomerun/hdhomerun_pkt.c \
	libhdhomerun/hdhomerun_sock.c \
	libhdhomerun/hdhomerun_sock_posix.c \
	libhdhomerun/hdhomerun_video.c

# OS-specific sources for getting local IP info
ifeq ($(OS),Linux)
  IF_DETECT_SRC = libhdhomerun/hdhomerun_sock_netlink.c
  LDFLAGS += -lrt
else
  # Default for macOS, BSD, etc.
  IF_DETECT_SRC = libhdhomerun/hdhomerun_sock_getifaddrs.c
endif

# Combine all library sources
LIB_SRCS = $(LIB_SRCS_BASE) $(IF_DETECT_SRC)
LIB_OBJS = $(LIB_SRCS:.c=.o)

# Source files for the TUI application
APP_SRCS = hdhomerun_tui.c l1_detail_parser.c eas_capture.c eas_run.c plat.c zipw.c player.c
APP_OBJS = $(APP_SRCS:.c=.o)

# Default target
all: $(TARGET)

# Rule to link the final executable
$(TARGET): $(APP_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(APP_OBJS) $(LIB_OBJS) $(LDFLAGS)

# Rule to compile a .c file into a .o file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

hdhomerun_tui.o eas_capture.o eas_run.o plat.o zipw.o player.o: eas_capture.h eas_run.h l1_detail_parser.h plat.h zipw.h player.h

# Optional GTK4 GUI (Linux).  "make gui" - needs the GTK 4 development package.
GUI_TARGET = hdhr_eas_test_gui
GUI_SRCS = gui.c gui_eas.c hdhr_dev.c player.c viewer.c eas_capture.c eas_run.c plat.c zipw.c l1_detail_parser.c
GUI_LIBS = -lz -lpthread $(if $(filter Linux,$(OS)),-lrt,)

# Built-in viewer: FFmpeg + SDL2 (audio). Prefer the AC-4 FFmpeg build made by
# tools/build_ffplay_ac4.sh (static); else the system FFmpeg (no AC-4 audio);
# else build without the viewer (Watch then opens ffplay).
FF_MODS = libavformat libavfilter libavcodec libswscale libswresample libavutil
AC4_PC := $(abspath ../../build/ffplay-ac4/out/lib/pkgconfig)
ifneq ($(wildcard $(AC4_PC)/libavcodec.pc),)
  VIEWER_CFLAGS := -DHAVE_VIEWER $(shell PKG_CONFIG_PATH=$(AC4_PC) pkg-config --cflags $(FF_MODS)) $(shell pkg-config --cflags sdl2)
  VIEWER_LIBS   := $(shell PKG_CONFIG_PATH=$(AC4_PC) pkg-config --static --libs $(FF_MODS)) $(shell pkg-config --libs sdl2)
  VIEWER_NOTE   := built-in viewer with AC-4
else ifeq ($(shell pkg-config --exists $(FF_MODS) sdl2 2>/dev/null && echo yes),yes)
  VIEWER_CFLAGS := -DHAVE_VIEWER $(shell pkg-config --cflags $(FF_MODS) sdl2)
  VIEWER_LIBS   := $(shell pkg-config --libs $(FF_MODS) sdl2)
  VIEWER_NOTE   := built-in viewer with the system FFmpeg (no AC-4 - run tools/build_ffplay_ac4.sh, then make again)
else
  VIEWER_NOTE   := no built-in viewer (FFmpeg/SDL2 development files missing) - Watch uses ffplay
endif

gui: $(GUI_TARGET)

$(GUI_TARGET): $(GUI_SRCS) gui.h hdhr_dev.h player.h viewer.h eas_capture.h eas_run.h plat.h zipw.h $(LIB_OBJS) $(wildcard $(AC4_PC)/libavcodec.pc)
	$(CC) $(CFLAGS) -O2 -Wno-format-truncation $(shell pkg-config --cflags gtk4) $(VIEWER_CFLAGS) -o $@ $(GUI_SRCS) $(LIB_OBJS) $(VIEWER_LIBS) $(shell pkg-config --libs gtk4) $(GUI_LIBS)
	@echo "GUI: $(VIEWER_NOTE)"

# Clean up build files
clean:
	rm -f $(TARGET) $(GUI_TARGET) $(APP_OBJS) $(LIB_OBJS)

# Install target (optional)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Uninstall target (optional)
uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all gui clean install uninstall
