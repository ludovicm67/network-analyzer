#include "layer4.h"
#include "layer5.h"
#include "network_analyzer.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>

void handle_tcp(const u_char *packet) {
  struct tcphdr *tcp_header = (struct tcphdr *)packet;
  int len = tcp_header->th_off * 4;
  int src = ntohs(tcp_header->th_sport);
  int dst = ntohs(tcp_header->th_dport);
  packet += len;

  if (na_state.verbose == 1)
    printf(" » TCP");
  if (na_state.verbose > 1) {
    printf(" ╞═════════════════ TCP ═══════════════════\n");
    printf(" ├ source port     :   %d\n", src);
    printf(" ├ dest port       :   %d\n", dst);
    printf(" ├ length          :   %d\n", len);
    printf(" ├ flags           :   ");
    if (tcp_header->th_flags & TH_FIN)
      printf("FIN ");
    if (tcp_header->th_flags & TH_SYN)
      printf("SYN ");
    if (tcp_header->th_flags & TH_RST)
      printf("RST ");
    if (tcp_header->th_flags & TH_PUSH)
      printf("PUSH ");
    if (tcp_header->th_flags & TH_ACK)
      printf("ACK ");
    if (tcp_header->th_flags & TH_URG)
      printf("URG ");
    printf("\n");
  }

  if (src == 21 || dst == 21) {
    handle_ftp(packet);
  } else if (src == 80 || dst == 80) {
    handle_http(packet);
  } else if (src == 443 || dst == 443) {
    handle_https(packet);
  } else if (src == 25 || dst == 25) {
    handle_smtp(packet);
  }
}

void handle_udp(const u_char *packet) {
  struct udphdr *udp_header = (struct udphdr *)packet;
  packet += sizeof(struct udphdr);

  int src = ntohs(udp_header->uh_sport);
  int dst = ntohs(udp_header->uh_dport);

  if (na_state.verbose == 1)
    printf(" » UDP");
  if (na_state.verbose > 1) {
    printf(" ╞═════════════════ UDP ═══════════════════\n");
    printf(" ├ source port     :   %d\n", src);
    printf(" ├ dest port       :   %d\n", dst);
    printf(" ├ length          :   %d\n", ntohs(udp_header->uh_ulen));
  }

  if (src == 53 || dst == 53) {
    handle_dns(packet);
  } else if (src == 67 || dst == 67 || src == 68 || dst == 68) {
    handle_dhcp(packet);
  }
}
