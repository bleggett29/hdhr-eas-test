/* Windows stand-in for <pcap.h>: RENDER only reads capture files, so it uses
 * the small built-in reader in pcap_lite.c instead of Npcap. GPLv3. */
#include "../pcap_lite.h"
