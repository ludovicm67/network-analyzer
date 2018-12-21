#ifndef __BOOTP_H
#define __BOOTP_H

#include <arpa/inet.h>

struct bootp {
  u_char bp_op;
  u_char bp_htype;
  u_char bp_hlen;
  u_char bp_hops;
  u_int32_t bp_xid;
  unsigned short bp_secs;
  unsigned short bp_flags;
  struct in_addr bp_ciaddr;
  struct in_addr bp_yiaddr;
  struct in_addr bp_siaddr;
  struct in_addr bp_giaddr;
  u_char bp_chaddr[16];
  char bp_sname[64];
  char bp_file[128];
  u_char bp_vend[64];
};

#endif
