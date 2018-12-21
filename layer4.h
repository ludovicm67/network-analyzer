#ifndef __LAYER4_H
#define __LAYER4_H

#include <arpa/inet.h>

void handle_tcp(const u_char *packet);
void handle_udp(const u_char *packet);

#endif
