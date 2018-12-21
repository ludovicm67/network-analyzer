#ifndef __LAYER5_H
#define __LAYER5_H

#include <arpa/inet.h>

void handle_dhcp(const u_char *packet);
void handle_dns(const u_char *packet);
void handle_http(const u_char *packet);
void handle_https(const u_char *packet);
void handle_ftp(const u_char *packet);
void handle_smtp(const u_char *packet);

#endif
