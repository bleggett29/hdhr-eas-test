RENDER - RabbitEars NextGen Data Evaluator and Reporter - v0.4.0

RENDER is software written using Google Gemini and Anthropic Claude to parse
ATSC 3.0 signals and output them in an HTML format, similar to the TSReader
HTML Export format.  It has been written for the Linux command line, but 
should compile on the Mac with the proper prerequisites and should be 
possible to get working on Windows.

Many thanks to drmpeg; his l1detail parsing code has been adapted for use in
RENDER.  It, like RENDER, is licensed in GPLv3.

https://github.com/drmpeg/dtv-utils/tree/master

It also uses code from:

- FFMPEG/libavcodec
  + Licensed under the LGPL 2.1
- This AC-4 patch:  https://github.com/funnymanva/ffmpeg-with-ac4
  + Licensed under the MIT license

The software supports the following input formats:

Packets:
- HDHomeRun Debug
- IPv4-PCAP
- ALP-PCAP
- STLTP-PCAP (partial)

Text:
- HDHomeRun plpinfo format
- HDHomeRun l1detail format
- HDHomeRun TUI text output format

Unless the provided data is in STLTP-PCAP format, both the packet data and 
the text data are needed for full information.  The ideal set of information
at present is the ALP-PCAP combined with either the l1detail or the HDHomeRun
TUI text output from an HDHomeRun with the Dev upgrade.  These items together
should have the same name, and provide all the information that the software
can currently parse.

It supports or mostly supports the following ATSC 3.0 functions and 
parameters:

- PLP Information (if any Text available)
- L1 Basic and L1 Detail (if l1detail or TUI text/Dev available)
- Link Mapping Table (if ALP-PCAP or STLTP-PCAP)
- Service List Table
- Capability Descriptor Table, which is Signal Signing
- Broadcast Positioning System
- ROUTE-based audio/video and data streams
- Most other LLS tables, including AEAT, RRT, SMT, etc
- Basic info on MPEG-TS packets
- Data usage analysis (only fully-supported for ALP-PCAP or STLTP-PCAP)
- Minimal eGPS support
- Partial ESG support

These functions are known to be have issues, or be significantly incomplete 
or non-functional:

- __MMT Media__ - It is believed that the MMT parsing works, but it appears 
that no station is actually transmitting the signaling necessary to make it 
actually function properly.  A work-around is implemented but it only gathers
the audio/video parameters some of the time, and should not be considered
reliable.
- __ESG Support__ - Some stations still do not have ESG data showing, or it
is not showing complete ESG data.  This will continue to be reviewed in the 
future.
- __eGPS Support__ - The code displays eGPS raw data, but the data seems to 
be in a proprietary format with little or no public documentation.  Attempts
to reverse-engineer the structure beyond minimal header support have been 
unsuccessful.
- __Bitrates__ -  While the usage chart shows the total data and number of 
packets in all cases, for debug and IPv4 input formats, the necessary data 
is missing and probably cannot be reverse engineered.

To build on Ubuntu, it is believed you'll need these packages:

build-essential
libpcap-dev
libxml2-dev
zlib1g-dev
libssl-dev

To build on RedHat, it is believed you'll need these packages:

libpcap-devel
libxml2-devel
zlib-devel
openssl-devel

And you'll need the HDHomeRun library, but I've included that in the zip file
if you don't already have it installed.

Building RENDER should be as running "make" in the source directory, which 
will produce an executable by that name.

To run RENDER, put a PCAP or debug file in the folder with your executable 
and then create a text file with that same name but ending in .txt which 
contains the PLP info from the HDHomeRun plpinfo command along with, if 
applicable, the l1detail string.  Alternatively, if you're using the latest
HDHomeRun TUI, using the a or z keys to capture a debug or PCAP file should
result in a PCAP and .txt file with the same name that you can use.

Then just run it:

./render <pcap|debug file name>

It'll output an HTML file with the same name that you can then review.  As 
RENDER is currently highly experimental, if any output looks questionable, 
please reach out to me by e-mail (webmaster@rabbitears.info) or on the 
RabbitEars Discord (https://discord.gg/tnamT4eccd).

Please also reach out with any questions or comments.  Enjoy this tool!
