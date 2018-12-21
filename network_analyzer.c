#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include "network_analyzer.h"
#include "level2.h"

void print_raw(const u_char *packet, int length) {
  u_char c;
  int i, j;

  // display paquet by lines of size 16
  for (j = 0; j < length + 16; j += 16) {
    if (j >= length) break;
    printf("  %04x   ", j);

    // display in hex form
    for (i = j; i < j + 16 && i < length; i++) {
      printf("%02x ", packet[i]);
      if (i == j + 7) printf(" ");
    }

    // add missing spaces if needed
    for (; i < j + 16; i++) {
      printf("   ");
      if (i == j + 7) printf(" ");
    }

    printf("  ");

    // display all ASCII characters
    for (i = j; i < j + 16 && i < length; i++) {
      c = packet[i];
      if (isprint(c)) printf("%c", c);
      else printf(".");
      if (i == j + 7) printf(" ");
    }

    printf("\n");
  }
}

void handle_udp(const u_char *packet, __attribute__((unused)) int length) {
  struct udphdr *udp_header = (struct udphdr *) packet;
  packet += sizeof(struct udphdr);

  printf(" ╞═════════════════ UDP ═══════════════════\n");
  printf(" ├ source port     :   %d\n", ntohs(udp_header->uh_sport));
  printf(" ├ dest port       :   %d\n", ntohs(udp_header->uh_dport));
  printf(" ├ length          :   %d\n", ntohs(udp_header->uh_ulen));

}

void handle_tcp(const u_char *packet, __attribute__((unused)) int length) {
  struct tcphdr *tcp_header = (struct tcphdr *) packet;
  packet += sizeof(struct tcphdr);

  printf(" ╞═════════════════ TCP ═══════════════════\n");
  printf(" ├ source port     :   %d\n", ntohs(tcp_header->th_sport));
  printf(" ├ dest port       :   %d\n", ntohs(tcp_header->th_dport));

}

void handle_ip(const u_char *packet, int length) {
  struct ip *ip_header = (struct ip *)packet;
  int ip_size = ip_header->ip_hl * 4;
  packet += ip_size;

  printf(" ╞══════════════════ IP ═══════════════════\n");
  printf(" ├ version         :   %d\n", ip_header->ip_v);
  printf(" ├ header length   :   %d\n", ip_header->ip_hl);
  printf(" ├ TTL             :   %d\n", ip_header->ip_ttl);
  printf(" ├ Protocol        :   %d\n", ip_header->ip_p);
  printf(" ├ source          :   %s\n", inet_ntoa(ip_header->ip_src));
  printf(" ├ destination     :   %s\n", inet_ntoa(ip_header->ip_dst));

  switch (ip_header->ip_p) {
    case 6:
      handle_tcp(packet, length - ip_size);
      break;
    case 17:
      handle_udp(packet, length - ip_size);
      break;
    default:
      // do nothing
      break;
  }
}

void handle_ip6(const u_char *packet, int length) {
  struct ip6_hdr *ip6_header = (struct ip6_hdr *)packet;
  packet += sizeof(struct ip6_hdr);

  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ip6_header->ip6_src, src, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst, INET6_ADDRSTRLEN);

  u_int8_t next = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  u_int16_t len = htons(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);

  printf(" ╞═════════════════ IPv6 ══════════════════\n");
  printf(" ├ source          :   %s\n", src);
  printf(" ├ destination     :   %s\n", dst);
  printf(" ├ next header     :   %d\n", next);
  printf(" ├ payload length  :   %d\n", len);

  switch (next) {
    case 6:
      handle_tcp(packet, length - len);
      break;
    case 17:
      handle_udp(packet, length - len);
      break;
    default:
      // do nothing
      break;
  }
}

// will handle each packet
void packet_handler(__attribute__((unused)) u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {

  char formatted_time[22];
  time_t rawtime;
  struct tm *timeinfo;

  time(&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(formatted_time, 22, "[%F %T]", timeinfo);

  if (na_state.verbose > 1) printf("\n");
  printf("\n %s length=%d:", formatted_time, header->len);
  if (na_state.verbose > 1) printf("\n");
  if (na_state.verbose == 3) print_raw(packet, header->len);

  handle_ethernet(packet);
}

// show the user how to run the program correctly
void usage(char *program_name) {
  fprintf(stderr, "Usage: %s ", program_name);
  fprintf(stderr, "[-i device] ");
  fprintf(stderr, "[-f filter]\n");

  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  bpf_u_int32 mask, net;
  char *device, *filter_exp;
  char errbuf[PCAP_ERRBUF_SIZE];
  int c, found, has_filter, nb_errors;
  pcap_if_t *devices, *dev_tmp;
  pcap_t *session;
  struct bpf_program fp;

  has_filter = 0;
  nb_errors = 0;
  device = "any";

  // parse options
  while ((c = getopt(argc, argv, "+i:f:")) != EOF) {
    switch (c) {
    case 'i':
      device = optarg;
      break;
    case 'f':
      has_filter = 1;
      filter_exp = optarg;
      break;
    case '?':
      nb_errors++;
      break;
    }
  }

  // if something went wrong
  if (nb_errors || !device) {
    usage(argv[0]);
  }

  // fetch all available devices
  if (pcap_findalldevs(&devices, errbuf) == -1) {
    perror("pcap_findalldevs failed");
    exit(EXIT_FAILURE);
  }

  found = 0;
  for (dev_tmp = devices; dev_tmp; dev_tmp = dev_tmp->next) {
    if (!strcmp(dev_tmp->name, device)) {
      found++;
      break;
    }
  }

  // free devices list
  pcap_freealldevs(devices);

  // check if device exists
  if (!found) {
    fprintf(stderr, "Device '%s' not found!\n", device);
  }

  // get device informations
  if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", device);
    net = 0;
    mask = 0;
  }

  // open device for reading
  if ((session = pcap_open_live(device, BUFSIZ, 0, -1, errbuf)) == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
    exit(EXIT_FAILURE);
  }

  // use filter if some are specified
  if (has_filter) {
    if (pcap_compile(session, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter '%s': %s\n", filter_exp,
              pcap_geterr(session));
      exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(session, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter '%s': %s\n", filter_exp,
              pcap_geterr(session));
      exit(EXIT_FAILURE);
    }
  }

  // handle each packet
  pcap_loop(session, -1, packet_handler, NULL);

  // close pcap session
  pcap_close(session);

  return EXIT_SUCCESS;
}
