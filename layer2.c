#include "layer2.h"
#include "layer3.h"
#include "network_analyzer.h"
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>

void handle_ethernet(const u_char *packet) {
  struct ether_header *eth;

  if (na_state.verbose == 1)
    printf(" » Ethernet II");
  if (na_state.verbose > 1)
    printf(" ╒═══════════════ ETHERNET ════════════════\n");

  eth = (struct ether_header *)packet;
  packet += sizeof(struct ether_header);
  uint16_t eth_type = htons(eth->ether_type);

  if (na_state.verbose > 1) {
    printf(" ├ source          :   %s\n",
           ether_ntoa((const struct ether_addr *)eth->ether_shost));
    printf(" ├ destination     :   %s\n",
           ether_ntoa((const struct ether_addr *)eth->ether_dhost));
  }

  switch (eth_type) {
  case ETHERTYPE_IP:
    handle_ip(packet);
    break;

  case ETHERTYPE_IPV6:
    handle_ip6(packet);
    break;

  case ETHERTYPE_PUP:
    if (na_state.verbose == 1)
      printf(" » PUP");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = PUP\n");
    break;

  case ETHERTYPE_SPRITE:
    if (na_state.verbose == 1)
      printf(" » Sprite");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = Sprite\n");
    break;

  case ETHERTYPE_ARP:
    handle_arp(packet);
    break;

  case ETHERTYPE_REVARP:
    if (na_state.verbose == 1)
      printf(" » Reverse ARP");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = Reverse ARP\n");
    break;

  case ETHERTYPE_AT:
    if (na_state.verbose == 1)
      printf(" » AppleTalk protocol");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = AppleTalk protocol\n");
    break;

  case ETHERTYPE_AARP:
    if (na_state.verbose == 1)
      printf(" » AppleTalk ARP");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = AppleTalk ARP\n");
    break;

  case ETHERTYPE_VLAN:
    if (na_state.verbose == 1)
      printf(" » IEEE 802.1Q VLAN tagging");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = IEEE 802.1Q VLAN tagging\n");
    break;

  case ETHERTYPE_IPX:
    if (na_state.verbose == 1)
      printf(" » IPX");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = IPX\n");
    break;

  case ETHERTYPE_LOOPBACK:
    if (na_state.verbose == 1)
      printf(" » loopback, used to test interfaces");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = loopback, used to test interfaces\n");
    break;

  default:
    if (na_state.verbose == 1)
      printf(" » unknown protocol");
    if (na_state.verbose > 1)
      printf(" ╞══ Proto = unknown protocol\n");
    break;
  }

  if (na_state.verbose > 1)
    printf(" ╘═════════════════════════════════════════\n");
}
