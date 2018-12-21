#ifndef __LAYER3_H
#define __LAYER3_H

#include <arpa/inet.h>

void handle_ip(const u_char *packet);
void handle_ip6(const u_char *packet);
void handle_arp(const u_char *packet);

#endif
