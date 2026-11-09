# HDHR EAS Test v0.5 (Linux)
#   make         builds ./hdhr_eas_test (TUI) and ./render,
#                plus ./hdhr_eas_test_gui when GTK 4 development files are installed
#   make gui     the GTK 4 GUI only
# (Use ./install.sh the first time: it checks and installs the required packages.)
# Windows: see build_windows.sh.
HDHR_OBJS = $(addprefix $(CURDIR)/src/tui/libhdhomerun/hdhomerun_, \
	channels.o channelscan.o control.o debug.o device.o device_selector.o \
	discover.o os_posix.o pkt.o sock.o sock_posix.o video.o sock_netlink.o)

HAVE_GTK4 := $(shell pkg-config --exists gtk4 2>/dev/null && echo yes)

all: hdhr_eas_test render $(if $(HAVE_GTK4),hdhr_eas_test_gui,)
	@echo
	@echo "Built ./hdhr_eas_test (TUI) and ./render."
	@$(if $(HAVE_GTK4),echo "Built ./hdhr_eas_test_gui (GTK 4 GUI).",echo "GUI not built (GTK 4 development files not installed) - the TUI has every feature.")
	@echo "Run ./hdhr_eas_test and press e  (or ./hdhr_eas_test_gui on a desktop)."

hdhr_eas_test: FORCE
	$(MAKE) -C src/tui
	cp src/tui/hdhomerun_tui hdhr_eas_test

hdhr_eas_test_gui gui: hdhr_eas_test FORCE
	$(MAKE) -C src/tui gui
	cp src/tui/hdhr_eas_test_gui hdhr_eas_test_gui

render: hdhr_eas_test FORCE
	$(MAKE) -C src/render HDHR_LIB="$(HDHR_OBJS) -lpthread -lrt"
	cp src/render/render .

clean:
	$(MAKE) -C src/tui clean
	$(MAKE) -C src/render clean
	rm -f hdhr_eas_test hdhr_eas_test_gui render

.PHONY: all gui clean FORCE
FORCE:
