# HDHR EAS Test v0.5

**By Brian Scott.** Copyright © 2026 Brian Scott.

Record your local TV stations with HDHomeRun tuners during the **nationwide
Emergency Alert System (EAS) test**, then see what each station sent.

Built on **HDHomeRun TUI v0.9** and **RENDER v0.4** by **RabbitEars**
(Mark J. Colombo, rabbitears.info).

---

## What it's for

FEMA and the FCC run a nationwide EAS test on **Tuesday, November 17, 2026**,
starting at **2:20 p.m. ET** (1:20 CT, 12:20 MT, 11:20 PT). If it's postponed,
the backup date is **December 3, 2026**. Stations relay the test sometime in
the next 30 minutes, and it lasts about a minute. It's on TV and radio only,
nothing on phones.

HDHR EAS Test:

- records one station per tuner for the whole test window, in 1-minute files
- for **ATSC 3.0** stations, checks every file with RENDER for alert
  signalling (the AEAT) and makes an HTML report for each file, plus one
  summary page across all stations
- for **ATSC 1.0** stations, keeps the video so you can watch the on-air test
- shares the results on your home network and can zip them

Everything is set up from one screen in the program. There are three ways to
run it, all with the same features:

| | Runs on | Start it with |
|---|---|---|
| **TUI** (text screen) | Linux, also over SSH | `./hdhr_eas_test`, then press **e** |
| **GUI** (GTK 4 window) | Windows 10/11 | double-click `hdhr_eas_test.exe` |
| **GUI** (GTK 4 window) | Linux desktop | `./hdhr_eas_test_gui` |

> **Note:** the Linux GUI is built from the same code as the Windows GUI and
> was checked in a test environment, but **it hasn't been tried on a real
> Linux desktop by the author.** On Linux, the TUI is the tested way to run
> it. If the GUI misbehaves, use the TUI.

---

## What you need

- A Linux computer (a Raspberry Pi works) or a Windows 10/11 PC, on the same
  network as your HDHomeRun(s).
- HDHomeRun tuners. ATSC 3.0 stations need an ATSC 3.0 model. If a model
  can't do ALP-PCAP, the program falls back to its debug format by itself.
- Disk space, roughly per station for a 50-minute run:
  - ATSC 3.0: about **9 GB**
  - ATSC 1.0: about **7 GB**
- A wired (gigabit) network connection if you record more than about 4
  stations at once. Wi-Fi or 100 Mbit links lose data.

---

## Install on Linux

```
unzip hdhr_eas_test.zip
cd hdhr_eas_test
./install.sh
```

`install.sh` checks for everything needed: a compiler, make, pkg-config,
python3, and the ncurses, libxml2, zlib, OpenSSL, FFmpeg
(libavcodec/libavutil) and libpcap development files. It lists what's
missing, offers to install it with your package manager (apt, dnf/yum,
zypper, pacman, apk, xbps or emerge), then builds.

- It also asks whether to build the **desktop GUI** (needs GTK 4). Say no on a
  Pi you use over SSH. `./install.sh --gui` or `--no-gui` answers in advance.
- And whether to build **FFmpeg with AC-4** for live viewing (see
  [Live viewing](#live-viewing-built-in-viewer-ac-4-sound)). `--ffplay` or `--no-ffplay`
  answers in advance; `tools/build_ffplay_ac4.sh` builds it any time later.
- `./install.sh --check` only reports and changes nothing.
- After an update, `make` is enough.

You end up with these side by side. Keep them together:

- `hdhr_eas_test`, the TUI
- `hdhr_eas_test_gui`, the GUI (only if GTK 4 was installed)
- `render`, which both run for the reports
- `ffplay` and `ffmpeg` with AC-4 (only if you built them)

---

## Install on Windows 10/11

**Ready-made:** unzip `hdhr_eas_test_v0.5_windows_x64.zip` anywhere (for
example `C:\HDHR EAS Test`) and double-click `hdhr_eas_test.exe`. Keep the
whole folder together: `render.exe` and the DLLs must stay next to it.

The first time, Windows may ask:

- **SmartScreen** ("Windows protected your PC"): More info, then Run anyway.
  The program isn't code-signed.
- **Firewall**: allow **Private networks**. It's needed to find the
  HDHomeRuns and, if you use it, to share the reports.

**Watch…** on the Tuners tab plays a tuner right in the window, with AC-4
sound for ATSC 3.0.

Optional extra: **Python 3** from python.org (tick *Add python.exe to PATH*)
for **Web server on**, so other devices can open the reports. Without it, use
**Open report**.

**Building it yourself** (to make the zip above):

1. Install MSYS2 from msys2.org.
2. Open **MSYS2 UCRT64** from the Start menu.
3. Go to this folder, for example `cd "/c/Users/you/Downloads/hdhr_eas_test"`.
4. Run `./build_windows.sh`. It installs GTK 4, FFmpeg, SDL2, libxml2,
   OpenSSL and zlib with pacman, builds everything, and collects it in
   `dist/hdhr_eas_test/`, plus `dist/hdhr_eas_test_v0.5_windows_x64.zip`.
   The first run also builds FFmpeg with AC-4 for the viewer, which adds 15–30 minutes; later
   runs reuse it. `--no-deps` skips pacman, `--no-ffplay` skips ffplay.

Or let GitHub build it: put this folder in a GitHub repository, then
**Actions**, **Windows build**, **Run workflow**. The finished folder is
attached to the run.

Windows gets the GUI plus `hdhr_eas_cli.exe`, a command-line runner for
scripts. The TUI is Linux only.

---

## Live viewing (built-in viewer, AC-4 sound)

**GUI:** on the Tuners tab, pick a tuner and click **Watch…** under the
**Viewer** (if the channel has more than one program, pick one). The picture
plays right there in the window, with sound.

- **Full screen**, or double-click the picture. **Esc**, **F** or a
  double-click returns. **M** mutes in full screen.
- **Vol −** / **Vol +** set the volume, up to 1000%. ATSC 3.0 (AC-4) sound
  is usually very quiet, so it has its own setting, starting at **500%**;
  everything else starts at 100%. The buttons change the setting for the
  kind of audio you're watching, and both are remembered. Loud peaks are
  softened rather than distorted. In full screen: **+** / **−** (or Up/Down).
- **Mute** turns the sound off and on.
- **Stop watching** ends it and frees the tuner's stream.
- 1080i and 480i stations are deinterlaced, and widescreen SD shows at 16:9.

**TUI:** press **v** on the main screen and pick the program. An ffplay
window opens (a terminal can't show video). Press **v** again, or **q** in
ffplay, to stop.

Either way the tuner sends the program to this computer as MPEG-TS over UDP.

ATSC 3.0 stations send **Dolby AC-4** audio, which regular FFmpeg can't
decode. HDHR EAS Test uses FFmpeg 6.1 with the AC-4 decoder (Paul B Mahol's
decoder, patch from github.com/funnymanva/ffmpeg-with-ac4, in
`tools/ffmpeg_ac4.patch`). The GUI's viewer is built with it, and the same
build gives you `ffplay` and `ffmpeg`:

- **Windows:** `build_windows.sh` builds it the first time (15–30 minutes)
  and builds the viewer with it. `ffplay.exe` and `ffmpeg.exe` come along
  for playing saved `.ts` files.
- **Linux:** say yes when `install.sh` asks, or run
  `tools/build_ffplay_ac4.sh` and then `make`. It needs SDL2 development
  files, git, patch and nasm (x86). About 5 minutes on a fast PC, longer on a
  Pi 5.

Without the AC-4 build, the viewer still shows the picture but ATSC 3.0
sound is silent, and it says so. Live viewing needs a desktop; over SSH, use
the recordings.

Live viewing uses the tuner, so stop it before a test run. **Release tuner** (or
Tune `0`) frees a tuner completely.

---

## Step 1: Free your tuners

During the test, **each tuner you record on must not be used by anything
else**: RabbitEars bandscan, a DVR, live viewing, and so on. A tuner that's
still busy answers "503" and won't record.

### RabbitEars bandscan you started by hand

Stop it with Ctrl-C in its terminal, or:

```
pkill -f scan_tuner.pl
```

Afterwards, start it again the way you normally do.

### Bandscan started by cron

`@reboot` entries only run at boot, so stopping the running copy is enough
for one test:

```
crontab -l | grep scan_tuner        # see the entries
pkill -f scan_tuner.pl              # stop the running copies
```

Afterwards, restart them by rebooting, or by running the same commands from
your crontab with `nohup ... &`.

If you have timed entries (not `@reboot`), run `crontab -e`, put `#` in front
of the `scan_tuner.pl` lines for the test, then remove the `#` afterwards.

### Bandscan or logger as a systemd service

**Option A, by hand:**

```
sudo systemctl stop scan-tuner-XXXXXXXX     # each of your services
# ... the test ...
sudo systemctl start scan-tuner-XXXXXXXX
```

**Option B, automatic (Linux only):** start the program with `--pause-services`
(TUI or GUI). The EAS
screen then stops your services before the run and starts them again after.
This needs permission to run those exact commands without a password. Change
the service names to yours:

```
SC=$(command -v systemctl)
sudo tee /etc/sudoers.d/hdhr-eas-test >/dev/null <<EOF
$USER ALL=(root) NOPASSWD: $SC stop scan-tuner-10A85A62, $SC start scan-tuner-10A85A62, $SC stop rf27watch, $SC start rf27watch
EOF
sudo chmod 440 /etc/sudoers.d/hdhr-eas-test
sudo visudo -cf /etc/sudoers.d/hdhr-eas-test
```

### DVR or live viewing

Make sure no recordings are scheduled from about 12:10 to 13:00 MT (adjust
for your zone), and that nobody is watching through the tuners you'll use.

> Without `--pause-services` the program still clears **stale** tuner locks
> left by a program that stopped, but it never takes a tuner that's actively
> streaming somewhere. The monitor shows that tuner as **IN USE elsewhere**,
> and recording starts within a few seconds of you freeing it.

---

## Step 2: Set it up

### GUI (Windows, Linux desktop)

Start `hdhr_eas_test.exe` (Windows) or `./hdhr_eas_test_gui` (Linux, add
`--pause-services` if you want Option B). It has two tabs:

- **Tuners**: pick a tuner on the left to see its signal, programs and PLPs.
  Change channel, Seek, Tune, Channel map, PLPs, **Release tuner**, PLP details,
  and Save 30 s (TS or PCAP) for quick checks. The **Viewer** shows the
  tuner live (see Live viewing).
- **EAS Test**: everything for the test, top to bottom:
  1. **Pick a channel for each tuner**: type it in the EAS channel box
     (`27` = ATSC 1.0 RF 27, `31p0` = ATSC 3.0 RF 31 PLP 0, `31p0p1` = two
     PLPs, `-` = none), or click **Use current** after tuning it on the
     Tuners tab. The box turns red if it's not valid.
  2. **Free your tuners**: the reminder, or with `--pause-services`, the
     services to pause.
  3. **Schedule and options**: start and stop (this computer's clock),
     segment length, ATSC 3.0 format, output folder, reports on/off, test-run
     length.
  4. **Test run now** and **Arm scheduled run...**

  The right side shows the run: status per tuner, the report link, **Cancel
  run**, **Zip results...**, **Open report**, **Open folder**, **Web
  server on/off** and the recent log.

Settings are saved as you change them.

### TUI (Linux)

```
./hdhr_eas_test                   # or: ./hdhr_eas_test --pause-services
```

On the main screen press **e**. The EAS screen lists every tuner it found and
what each is tuned to right now.

| Key | Does |
|---|---|
| Up / Down | Pick a tuner |
| Enter | Type the channel for that tuner: `27` = ATSC 1.0 RF 27, `31p0` = ATSC 3.0 RF 31 PLP 0, `31p0p1` = two PLPs, `-` = none |
| u | Use what the tuner is tuned to now. Tune it on the main screen first |
| x | Clear the tuner |
| s / e | Start and stop time, `YYYY-MM-DD HH:MM`, in this computer's local time. Defaults are 2026-11-17 12:10 to 13:00 |
| o | Output folder (default `~/eas2026`) |
| g / f | Segment length (default 60 s), ATSC 3.0 format (ALP-PCAP, or debug) |
| r / l | Reports after the run on or off, test-run length |
| w | Web server on or off |
| p d h b | With `--pause-services` only: services to pause (`d` finds them), another machine, how early to pause |
| **T** | **Test run now** |
| **A** | **Arm the real run** |
| m | Monitor a run (`c` cancel, `z` zip, `w` web, `o` open on this desktop) |
| q | Back |

Settings are saved as you change them.

---

## Step 3: Do a test run (before the 17th)

GUI: **Test run now**. TUI: press **T**, then **y**. It records for 2 minutes, makes the reports, and
shows the monitor. Check:

- every tuner says **recording**, with no **IN USE** or `503`
- the report link opens on your PC: `http://<this computer>:8000/...`
- if you used `--pause-services`, your services are running again
  afterwards

---

## Step 4: Arm the real run

GUI: **Arm scheduled run...** TUI: press **A**. Check the review: the clock,
tuners, and disk space. Then confirm (**y** in the TUI).

The run happens in the background. **You can close the program (and SSH).**
Don't reboot or power off the computer until it finishes. To check on it,
open the program again: the GUI's EAS Test tab, or in the TUI **e**, then
**m**.

**Windows:** keep the PC **on and signed in** until the run ends. The run
keeps the PC awake, but signing out, restarting for Windows Update, or
shutting down stops it. Check Windows Update the day before. Laptops: plug in.

---

## Step 5: Results

When the run finishes, the monitor shows the link to the summary. For
example:

```
http://192.168.1.78:8000/eas_summary.html
```

The summary has:

- a timeline of alerts across all stations
- a table for each ATSC 3.0 station, with a link to every file's full report
- the ATSC 1.0 video files. Open the ones from 12:20–12:50 MT in ffplay
  (`ffplay file.ts`), VLC or mpv to see the test.

**No alert in a 3.0 report doesn't mean the station missed the test.** The
on-air crawl and audio are in the program itself. The alert signalling is
extra, and stations may not send it for a test.

### Zips

When a run ends you're offered:

1. **ATSC 3.0 reports + logs.** Small, good for sharing.
2. **Full test files**, every `.pcap` and `.ts`.
3. **No zip.** Use **Zip results...** (GUI) or `z` on the monitor (TUI) any
   time later.

> ⚠️ **CAUTION: the full zip is huge.** It's a second copy of every
> recording, about **7–9 GB per station** for the real run, so 4 stations is
> about 30 GB. It needs that much **extra** free disk, and takes a long time
> to download. The program shows the size, checks free space, and asks before
> making one. You usually want option 1, and you can copy individual files
> from the folder instead.

---

## Files

| Where | What |
|---|---|
| `~/eas2026/` (Windows: `C:\Users\you\eas2026\`) | Real run: recordings, reports, `eas_summary.html`, `eas_capture.log` |
| `~/eas2026/test_<date-time>/` | Each test run |
| `~/hdhr_captures/` | GUI quick captures (Save 30 s, PLP details) |
| `~/.config/hdhr_eas_test/` (Windows: `%APPDATA%\HDHR EAS Test\`) | Settings (`eas.conf`), run status, runner and web server logs |

---

## Troubleshooting

- **IN USE / 503:** something else still has that tuner (see Step 1).
- **"sudo won't run ..." in the log:** the sudoers step in Step 1, Option B,
  is missing a service.
- **Files much smaller than about 70 MB per 30 s (ATSC 1.0):** data is being
  lost. Use wired gigabit, or record fewer stations.
- **"RENDER not found":** `render` (`render.exe`) must sit next to the
  program. On Linux run `make` again; on Windows keep the folder together.
- **No tuners found (Windows):** allow the program through the firewall on
  Private networks, and check that the network is set to Private, not Public.
  **Add device...** with the HDHomeRun's IP address also works.
- **A tuner stuck on a channel or locked** (for example after the bandscan
  stopped): **Release tuner** in the GUI, or Tune `0`. In the TUI press **c**
  and enter `0`. It clears the tuner's lock, stream and channel.
- **Can't delete or move the program folder (Windows):** something from it is
  still running. Close ffplay, and if a scheduled run is waiting, use
  **Cancel run** (the background runner is `hdhr_eas_test.exe`). Task
  Manager shows any leftover `hdhr_eas_test.exe` or `ffplay.exe`.
- **Web server says Python isn't installed (Windows):** install Python 3 from
  python.org with *Add python.exe to PATH*, or use **Open report**.
- **Viewer choppy:** set the environment variable `HDHR_VIEWER_STATS` to a
  file name before starting the program, and every 5 s it adds how many
  frames were shown and dropped. On Windows, in PowerShell:
  `$env:HDHR_VIEWER_STATS = "$env:USERPROFILE\viewer_stats.txt"`, then
  `.\hdhr_eas_test.exe` from that window (in Command Prompt:
  `set HDHR_VIEWER_STATS=%USERPROFILE%\viewer_stats.txt`). The file is
  `C:\Users\<you>\viewer_stats.txt`. On Linux `=1` prints to the terminal. Lots of drops with high CPU means the PC can't keep up; a weak
  Wi-Fi link shows up as the picture stopping and starting.
- **GUI window blank or flickering:** start it with the environment variable
  `GSK_RENDERER=cairo` (Windows: `set GSK_RENDERER=cairo` in a Command Prompt,
  then run `hdhr_eas_test.exe` from that window).
- **Linux GUI won't build:** it needs GTK 4 (`libgtk-4-dev` or your distro's
  equivalent). Raspberry Pi OS / Debian 12 ship GTK 4.8, which is supported. Or just
  use the TUI.

---

## License

**HDHR EAS Test**: Copyright © 2026 Brian Scott. Free software under the
**GNU General Public License v3**; see `LICENSE`. It comes with
**no warranty**.

It's built on, and includes, the following. Each keeps its own copyright:

- **HDHomeRun TUI v0.9**: Copyright (C) 2025 Mark J. Colombo (RabbitEars).
  GPLv3.
- **RENDER v0.4**: RabbitEars. GPLv3. Its L1 parsing is adapted from
  drmpeg's dtv-utils (GPLv3).
- **libhdhomerun**: Copyright (C) 2005-2023 Silicondust USA Inc. **LGPL 2.1**,
  see `licenses/LGPL-2.1-libhdhomerun.txt`. Included in `src/tui/libhdhomerun`.
- **On Linux**, the system libraries the programs link to are installed by
  your distribution under their own licenses and aren't included here:
  GTK 4 and GLib (LGPL 2.1+), FFmpeg libavcodec/libavutil (LGPL 2.1+),
  libxml2 (MIT), libpcap (BSD), OpenSSL (Apache 2.0), zlib, ncurses (MIT).
- **The Windows zip** includes those libraries as DLLs, unmodified from
  MSYS2 (msys2.org), each under its own license: GTK 4, GLib, Pango, Cairo,
  HarfBuzz, gdk-pixbuf and friends (LGPL 2.1+ / MIT), the Adwaita icons
  (LGPL 3 / CC BY-SA 3.0), FFmpeg (LGPL 2.1+/GPL as built by MSYS2), libxml2,
  OpenSSL, zlib, and the MinGW-w64 runtime. Their sources are available from
  the MSYS2 project. `render.exe` reads PCAP files with its own built-in reader
  (`src/render/pcap_lite.c`), so Npcap isn't needed.
- **FFmpeg with AC-4** (built by `tools/build_ffplay_ac4.sh`; the GUI's
  viewer links its libraries, and it makes `ffplay` / `ffmpeg`):
  FFmpeg 6.1, LGPL 2.1+ (built without GPL parts), with the AC-4 decoder by
  Paul B Mahol (LGPL 2.1+). The patch comes from
  github.com/funnymanva/ffmpeg-with-ac4. FFmpeg's source is at ffmpeg.org;
  the script downloads it and keeps it in `build/ffplay-ac4/`. The viewer
  and ffplay use SDL2 (zlib license) for sound.

The full source is in `src/`. `patches/` holds the changes made to the
original TUI and RENDER.
