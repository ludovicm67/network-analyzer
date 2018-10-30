#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void handle_ip(const u_char *packet) {
  struct ip *ip_header = (struct ip *)packet;
  packet += sizeof(struct ip);

  printf(" ╞══════════════════ IP ═══════════════════\n");
  printf(" ├ version         :   %d\n", ip_header->ip_v);
  printf(" ├ header length   :   %d\n", ip_header->ip_hl);
  printf(" ├ TTL             :   %d\n", ip_header->ip_ttl);
  printf(" ├ source          :   %s\n", inet_ntoa(ip_header->ip_src));
  printf(" ├ destination     :   %s\n", inet_ntoa(ip_header->ip_dst));
}

void handle_ip6(const u_char *packet) {
  struct ip6_hdr *ip6_header = (struct ip6_hdr *)packet;
  packet += sizeof(struct ip6_hdr);

  printf(" ╞═════════════════ IPv6 ══════════════════\n");
}

void handle_arp(const u_char *packet) {
  printf(" ╞═════════════════ ARP ═══════════════════\n");
}

// will handle each packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {
  int i;
  int consumed_size;
  struct ether_header *eth;
  eth = (struct ether_header *)packet;
  packet += sizeof(struct ether_header);

  consumed_size = sizeof(struct ether_header);

  uint16_t eth_type = htons(eth->ether_type);

  printf("\n\ngot packet with length=%d :\n", header->len);

  printf(" ╒═══════════════ ETHERNET ════════════════\n");
  printf(" ├ source          :   %s\n",
         ether_ntoa((const struct ether_addr *)eth->ether_shost));
  printf(" ├ destination     :   %s\n",
         ether_ntoa((const struct ether_addr *)eth->ether_dhost));

  switch (eth_type) {
  case ETHERTYPE_IP:
    handle_ip(packet);
    packet += sizeof(struct ip);
    consumed_size += sizeof(struct ip);
    break;

  case ETHERTYPE_IPV6:
    handle_ip6(packet);
    packet += sizeof(struct ip6_hdr);
    consumed_size += sizeof(struct ip6_hdr);
    break;

  case ETHERTYPE_ARP:
    handle_arp(packet);
    break;

  default:
    printf(" ╞══════════════════ ?? ═══════════════════\n");
    break;
  }

  printf(" ╘═════════════════════════════════════════\n");

  // for the moment print the content of the packet (output can be strange)
  for (i = 0; i < header->len - consumed_size; i++) {
    printf("%c", packet[i]);
  }
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
