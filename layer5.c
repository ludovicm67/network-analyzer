#include "layer3.h"
#include "layer4.h"
#include "network_analyzer.h"
#include <stdio.h>
#include <stdlib.h>

// void handle_bootp(const u_char *packet) {

// }

// void handle_dhcp(const u_char *packet) {

// }

// void handle_dns(const u_char *packet) {

// }

// void handle_http(const u_char *packet) {

// }

// void handle_https(const u_char *packet) {

// }

void handle_ftp(const u_char *packet) {
  int code = atoi((char *)packet);
  u_char *msg = (u_char *)packet + 4;
  u_char *tmp = msg;
  while (*tmp != '\n')
    tmp++;
  *tmp = '\0';

  if (na_state.verbose == 1)
    printf(" » FTP");
  if (na_state.verbose > 1) {
    printf(" ╞══════════════════ FTP ══════════════════\n");
    printf(" ├ code         :   %d\n", code);
    printf(" ├ message      :   %s\n", msg);
  }
}

void handle_ftp_data(__attribute__((unused)) const u_char *packet) {
  if (na_state.verbose == 1)
    printf(" » FTP DATA");
  if (na_state.verbose > 1) {
    printf(" ╞═══════════════ FTP DATA ════════════════\n");
  }
}

// void handle_smtp(const u_char *packet) {

// }
