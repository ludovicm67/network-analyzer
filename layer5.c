#include "layer3.h"
#include "layer4.h"
#include "network_analyzer.h"
#include <stdio.h>
#include <stdlib.h>

void handle_bootp(__attribute__((unused)) const u_char *packet) {}

void handle_dhcp(const u_char *packet) {
  if (na_state.verbose == 1)
    printf(" » DHCP");
  if (na_state.verbose > 1) {
    u_int8_t dhcp = (u_int8_t) * (packet + 240);
    u_int8_t type = (u_int8_t) * (packet + 242);
    printf(" ╞══════════════════ DHCP ═════════════════\n");
    if (dhcp == 53) {
      switch (type) {
      case 1:
        printf(" ├ message type : Discover\n");
        break;
      case 2:
        printf(" ├ message type : Offer\n");
        break;
      case 3:
        printf(" ├ message type : Request\n");
        break;
      case 5:
        printf(" ├ message type : ACK\n");
        break;
      }
    }
  }
}

void handle_dns(__attribute__((unused)) const u_char *packet) {
  if (na_state.verbose == 1)
    printf(" » DNS");
  if (na_state.verbose > 1) {
    printf(" ╞══════════════════ DNS ══════════════════\n");
  }
}

void handle_http(const u_char *packet) {
  if (na_state.verbose == 1)
    printf(" » HTTP");
  if (na_state.verbose > 1) {
    printf(" ╞═════════════════ HTTP ══════════════════\n");
    if (*packet == 'H' && *(packet + 1) == 'T' && *(packet + 2) == 'T' &&
        *(packet + 3) == 'P') {
      u_char *msg = (u_char *)packet + 5;
      u_char *tmp = msg;
      while (*tmp != ' ')
        tmp++;
      *tmp = '\0';
      if (*msg == '1' || *msg == '2')
        printf(" ├ version : %s\n", msg);
      msg = tmp + 1;
      tmp = msg;
      while (*tmp != ' ')
        tmp++;
      *tmp = '\0';
      if (atoi((char *)msg))
        printf(" ├ code : %s\n", msg);
    } else {
      printf(" ├ HTTP content (following an other packet due to TCP "
             "segmentation)\n");
    }
  }
}

void handle_https(const u_char *packet) {
  if (na_state.verbose == 1)
    printf(" » HTTPS");
  if (na_state.verbose > 1) {
    printf(" ╞═════════════════ HTTPS ═════════════════\n");
    if (*packet == 'H' && *(packet + 1) == 'T' && *(packet + 2) == 'T' &&
        *(packet + 3) == 'P') {
      u_char *msg = (u_char *)packet + 5;
      u_char *tmp = msg;
      while (*tmp != ' ')
        tmp++;
      *tmp = '\0';
      if (*msg == '1' || *msg == '2')
        printf(" ├ version : %s\n", msg);
      msg = tmp + 1;
      tmp = msg;
      while (*tmp != ' ')
        tmp++;
      *tmp = '\0';
      if (atoi((char *)msg))
        printf(" ├ code : %s\n", msg);
    } else {
      printf(" ├ HTTPS content (following an other packet due to TCP "
             "segmentation)\n");
    }
  }
}

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

void handle_smtp(const u_char *packet) {
  u_char *msg = (u_char *)packet;
  u_char *tmp = msg;
  while (*tmp != '\n')
    tmp++;
  *tmp = '\0';

  if (na_state.verbose == 1)
    printf(" » SMTP");
  if (na_state.verbose > 1) {
    printf(" ╞══════════════════ SMTP ═════════════════\n");
    if (*msg) {
      if (atoi((char *)msg) >= 100) {
        printf(" ├ code      :   %d\n", atoi((char *)msg));
        printf(" ├ message   :   %s\n", msg + 4);
      } else if (*msg >= 'A' && *msg <= 'Z') {
        printf(" ├ message   :   %s\n", msg);
      } else {
        printf(" ├ SMTP content (following an other packet due to TCP "
               "segmentation)\n");
      }
    } else {
      printf(" ├ SMTP content (following an other packet due to TCP "
             "segmentation)\n");
    }
  }
}
