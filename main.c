#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

void got_packet(unsigned char *args, const struct pcap_pkthdr *header,
                const unsigned char *packet) {
  printf("got packet!\n");
}

int main(int argc, char const *argv[]) {
  char *interface = "lo";
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;
  pcap_t *handle;

  if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", interface);
    net = 0;
    mask = 0;
  }

  if ((handle = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf)) == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);

  return EXIT_SUCCESS;
}
