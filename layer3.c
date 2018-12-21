#include "layer3.h"
#include "layer4.h"
#include "network_analyzer.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdio.h>

void handle_ip(const u_char *packet) {
  struct ip *ip_header = (struct ip *)packet;
  int ip_size = ip_header->ip_hl * 4;
  packet += ip_size;

  if (na_state.verbose == 1)
    printf(" » IP");
  if (na_state.verbose > 1) {
    printf(" ╞══════════════════ IP ═══════════════════\n");
    printf(" ├ version         :   %d\n", ip_header->ip_v);
    printf(" ├ header length   :   %d\n", ip_header->ip_hl);
    printf(" ├ TTL             :   %d\n", ip_header->ip_ttl);
    printf(" ├ Protocol        :   %d\n", ip_header->ip_p);
    printf(" ├ source          :   %s\n", inet_ntoa(ip_header->ip_src));
    printf(" ├ destination     :   %s\n", inet_ntoa(ip_header->ip_dst));
  }

  switch (ip_header->ip_p) {
  case 6:
    handle_tcp(packet);
    break;
  case 17:
    handle_udp(packet);
    break;
  default:
    // do nothing
    break;
  }
}

void handle_ip6(const u_char *packet) {
  struct ip6_hdr *ip6_header = (struct ip6_hdr *)packet;
  packet += sizeof(struct ip6_hdr);

  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ip6_header->ip6_src, src, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst, INET6_ADDRSTRLEN);

  u_int8_t next = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  u_int16_t len = htons(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);

  if (na_state.verbose == 1)
    printf(" » IPv6");
  if (na_state.verbose > 1) {
    printf(" ╞═════════════════ IPv6 ══════════════════\n");
    printf(" ├ source          :   %s\n", src);
    printf(" ├ destination     :   %s\n", dst);
    printf(" ├ next header     :   %d\n", next);
    printf(" ├ payload length  :   %d\n", len);
  }

  switch (next) {
  case 6:
    handle_tcp(packet);
    break;
  case 17:
    handle_udp(packet);
    break;
  default:
    // do nothing
    break;
  }
}
