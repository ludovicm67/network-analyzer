#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
