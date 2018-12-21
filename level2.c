#include "level2.h"
#include "network_analyzer.h"
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

void handle_ethernet(const u_char *packet) {
  struct ether_header *eth;

  if (na_state.verbose == 1) printf("Ethernet II");
  else {

  }

  eth = (struct ether_header *)packet;
  packet += sizeof(struct ether_header);

  uint16_t eth_type = htons(eth->ether_type);



  printf(" ╒═══════════════ ETHERNET ════════════════\n");
  printf(" ├ source          :   %s\n",
         ether_ntoa((const struct ether_addr *)eth->ether_shost));
  printf(" ├ destination     :   %s\n",
         ether_ntoa((const struct ether_addr *)eth->ether_dhost));

  switch (eth_type) {
  case ETHERTYPE_IP:
    handle_ip(packet, header->len - consumed_size);
    break;

  case ETHERTYPE_IPV6:
    handle_ip6(packet, header->len - consumed_size);
    break;

  case ETHERTYPE_PUP:
    printf(" ╞══ Proto = PUP\n");
    break;

  case ETHERTYPE_SPRITE:
    printf(" ╞══ Proto = Sprite\n");
    break;

  case ETHERTYPE_ARP:
    printf(" ╞══ Proto = ARP, Address resolution\n");
    break;

  case ETHERTYPE_REVARP:
    printf(" ╞══ Proto = Reverse ARP\n");
    break;

  case ETHERTYPE_AT:
    printf(" ╞══ Proto = AppleTalk protocol\n");
    break;

  case ETHERTYPE_AARP:
    printf(" ╞══ Proto = AppleTalk ARP\n");
    break;

  case ETHERTYPE_VLAN:
    printf(" ╞══ Proto = IEEE 802.1Q VLAN tagging\n");
    break;

  case ETHERTYPE_IPX:
    printf(" ╞══ Proto = IPX\n");
    break;

  case ETHERTYPE_LOOPBACK:
    printf(" ╞══ Proto = loopback, used to test interfaces\n");
    break;

  default:
    printf(" ╞══════════════════ ?? ═══════════════════\n");
    break;
  }

  printf(" ╘═════════════════════════════════════════\n");
}
