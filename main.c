#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// will handle each packet
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

// show the user how to run the program correctly
void usage(char * program_name) {
  fprintf(stderr, "Usage: %s ", program_name);
  fprintf(stderr, "[-i device]\n");

  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  int nberrors, c, found;
  char *device;
  pcap_if_t *devices, *dev_tmp;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;
  pcap_t *session;

  nberrors = 0;

  // parse options
  while ((c = getopt(argc, argv, "+i:")) != EOF) {
    switch (c) {
      case 'i':
        device = optarg;
        break;
      case '?':
        nberrors++;
        break;
    }
  }

  // if something went wrong
  if (nberrors || !device) {
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

  // handle each packet
  pcap_loop(session, -1, packet_handler, NULL);

  // close pcap session
  pcap_close(session);

  return EXIT_SUCCESS;
}
