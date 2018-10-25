#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header,
                    const unsigned char *packet) {
  int i;
  printf("got packet with length=%d\n", header->len);

  // for the moment print the content of the packet (output can be strange)
  for (i = 0; i < header->len; i++) {
    printf("%c", packet[i]);
  }
  printf("\n");
}

int main(int argc, char const *argv[]) {
  char *interface = "lo";
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;
  pcap_t *session;

  // get device informations
  if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", interface);
    net = 0;
    mask = 0;
  }

  // open device for reading
  if ((session = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf)) == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    exit(EXIT_FAILURE);
  }

  // handle each packet
  pcap_loop(session, -1, packet_handler, NULL);

  // close pcap session
  pcap_close(session);

  return EXIT_SUCCESS;
}
