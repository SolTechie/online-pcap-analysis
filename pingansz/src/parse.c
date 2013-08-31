#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include "pcap.h"
#include "services.h"
#include "parse.h"

static int ipv4_parse(pcap_record_t *prec, const char *pktdata, int pktlen);
static int ipv6_parse(pcap_record_t *prec, const char *pktdata, int pktlen);
static int udp_parse(pcap_record_t *prec, const char *pktdata, int pktlen);
static int tcp_parse(pcap_record_t *prec, const char *pktdata, int pktlen);

int parse_record(pcap_record_t *prec, const char *pktdata, int pktlen) {
  // number, time, framelen, caplen have been set
  uint16_t  eth_type;       /* type field of ethernet header */
  char *ptr = (char *)pktdata;
  int k;

  /* initializing ... */
  prec->protocol[0] = '\0';
  prec->info[0] = '\0';
  prec->v4_cast = UNICAST;      /* initialized unicast */
  prec->tcp_info.valid = 0; 

  /* the least significant bit of the most significant byte of
   * the destination mac address is set when the address is a
   * multicase address.
   * broadcase address(ff:ff:ff:ff:ff:ff) is special case */
  if (ptr[0] & 0x01 == 1) {
    for (k = 0; k < 6 && ptr[0] == 0xff; k++) ;

    if (k < 6) prec->v4_cast = MULTICAST;
    else prec->v4_cast = BROADCAST;
  }

  eth_type = ntohs( *(uint16_t *)(ptr + 12) );

  //printf("eth_type = %d\n", eth_type);
  switch (eth_type) {
    case 0x0800:    /* IPv4 */
      strcat(prec->protocol, "IPv4");
      ipv4_parse(prec, pktdata + 14, pktlen - 14);
      break;

    case 0x86dd:    /* IPv6 */
      strcat(prec->protocol, "IPv6");
      ipv6_parse(prec, pktdata + 14, pktlen - 14);
      break;

    case 0x0806:    /* ARP  */
      prec->version = -1;      /* not ip packet */
      strcat(prec->protocol, "ARP");
      break;

    case 0x8035:    /* RARP */
      prec->version = -1;      /* not ip packet */
      strcat(prec->protocol, "RARP");
      break;

    default:
      prec->version = -1;      /* not ip packet */
      break;
  }

  return 0;
}

static int ipv4_parse(pcap_record_t *prec, const char *pktdata, int pktlen) {
  char  *ptr = (char *)pktdata;
  int   protocol;
  int   hsize;          /* header size (byte) */

  if (pktlen < 20) {
    ERR_LOG("size of IPv4 packet is less than 20");
    strcat(prec->info, "Packet size limit during capture.");
    return -1;
  }

  hsize = *(uint8_t *)ptr & 0x0f;
  hsize *= 4;

  prec->version = 4;   /* ipv4 */
  prec->pktsize = ntohs( *(uint16_t *)(ptr + 2) );

  protocol = *(uint8_t *)(ptr + 9);     /* TCP, UDP, ICMP, IGMP ... */

  prec->src_ip[0] = *(uint32_t *)(ptr + 12);
  prec->dst_ip[0] = *(uint32_t *)(ptr + 16);

  switch (protocol) {
    case 1:     /* ICMP */
      strcat(prec->protocol, ":ICMP");
      break;

    case 2:     /* IGMP */
      strcat(prec->protocol, ":IGMP");
      break;
      
    case 6:     /* TCP */
      strcat(prec->protocol, ":TCP");
      tcp_parse(prec, pktdata + hsize, pktlen - hsize);
      break;

    case 8:     /* EGP */
      strcat(prec->protocol, ":EGP");
      break;

    case 9:     /* IGP */
      strcat(prec->protocol, ":IGP");
      break;

    case 17:    /* UDP */
      strcat(prec->protocol, ":UDP");
      udp_parse(prec, pktdata + hsize, pktlen - hsize);
      break;

    case 41:    /* IPv6 tunnel */
      strcat(prec->protocol, ":IPv6");
      break;

    case 89:    /* OSPF */
      strcat(prec->protocol, ":OSPF");
      break;

    default:
      break;
  }

  return 0;
}

static int ipv6_parse(pcap_record_t *prec, const char *pktdata, int pktlen) {
  char  *ptr = (char *)pktdata;
  int   protocol;
  int   hsize;

  prec->version = 6;
  prec->pktsize = ntohs( *(uint16_t *)(ptr + 4) ) + 40; /* payload length +  basic header (40 bytes) */
  protocol = *(uint8_t *)(ptr + 6);

  hsize = 40;

  memcpy( prec->src_ip, ptr +  8, 16 );
  memcpy( prec->dst_ip, ptr + 24, 16 );

  switch (protocol) {
    case 6:     /* TCP */
      strcat(prec->protocol, ":TCP");
      tcp_parse(prec, pktdata + hsize, pktlen - hsize);
      break;

    case 17:    /* UDP */
      strcat(prec->protocol, ":UDP");
      udp_parse(prec, pktdata + hsize, pktlen - hsize);
      break;

    default:
      break;
  }

  return 0;
}

static int udp_parse(pcap_record_t *prec, const char *pktdata, int pktlen) {
  char *ptr = (char *)pktdata;
  int k;

  if (pktlen < 4) {
    ERR_LOG("size of UDP packet is less than 8");
    strcat(prec->info, "[Packet size limit during capture]");
    return -1;
  }

  prec->src_port = ntohs( *(uint16_t *)ptr );
  prec->dst_port = ntohs( *(uint16_t *)(ptr + 2) );

  if ( (k = index_of_service(prec->src_port)) != -1 ||
       (k = index_of_service(prec->dst_port)) != -1 ) {
    strcat(prec->protocol, ":");
    strcat(prec->protocol, services[k].name);
  }

  sprintf(prec->info, "%u > %u", prec->src_port, prec->dst_port);

  return 0;
}

static int tcp_parse(pcap_record_t *prec, const char *pktdata, int pktlen) {
  char *ptr = (char *)pktdata;
  int k;

  uint32_t  seq, ackseq;
  uint8_t   urg, ack, psh, rst, syn, fin;
  uint8_t   flags;
  uint16_t  winsize;
  char      buf[80];

  if (pktlen < 4) {
    ERR_LOG("size of TCP packet is less than 4");
    strcat(prec->info, "[Packet size limit during capture]");
    return -1;
  }

  prec->src_port = ntohs( *(uint16_t *)ptr );
  prec->dst_port = ntohs( *(uint16_t *)(ptr + 2) );

  if ( (k = index_of_service(prec->src_port)) != -1 ||
       (k = index_of_service(prec->dst_port)) != -1 ) {
    strcat(prec->protocol, ":");
    strcat(prec->protocol, services[k].name);
  }

  sprintf(prec->info, "%u > %u", prec->src_port, prec->dst_port);


  if (pktlen < 16) {
    //ERR_LOG("size of TCP Packet is less than 16");
    fprintf(stderr, "%d  pktlen = %d\n", prec->number, pktlen);
    strcat(prec->info, "[Packet size limit during capture]");
    return -1;
  }

  prec->tcp_info.valid = 1;

  prec->tcp_info.seq_no = ntohl( *(uint32_t *)(ptr + 4) );
  prec->tcp_info.ack_no = ntohl( *(uint32_t *)(ptr + 8) );
  
  flags     = *(uint8_t *)(ptr + 13);
  prec->tcp_info.fin    = flags & 0x01;
  prec->tcp_info.syn    = (flags >> 1) & 0x01;
  prec->tcp_info.ack    = (flags >> 4) & 0x01;

  winsize   = ntohs( *(uint16_t *)(ptr + 14) );

  strcat(prec->info, " [");
  if ( flags & 0x10 ) {
    strcat(prec->info, " ACK");
  }
  if ( flags & 0x08 ) {
    strcat(prec->info, " PSH");
  }
  if ( flags & 0x04 ) {
    strcat(prec->info, " RST");
  }
  if ( flags & 0x02 ) {
    strcat(prec->info, " SYN");
  }
  if ( flags & 0x01 ) {
    strcat(prec->info, " FIN");
  }
  strcat(prec->info, "] ");

  sprintf(buf, "Seq=%u Ack=%u Win=%hu", prec->tcp_info.seq_no,
                                        prec->tcp_info.ack_no,
                                        winsize);
  strcat(prec->info, buf);

  return 0;
}

static void ipv6addr2string(uint8_t *addr, char *ipstring) { 
  uint16_t  temp[8];
  int i, j;
  int cnt, maxcnt, idx;
  char *ptr;

  memcpy(temp, addr, 16);

  for (i = 0; i < 8; i++) temp[i] = ntohs(temp[i]);

  maxcnt = cnt = 0;
  idx = -1;
  for (i = 0; i < 8; i++) {
    if (temp[i] == 0) cnt++;
    else {
      if (cnt > maxcnt) {
        maxcnt = cnt;
        idx = i - cnt;
      }
      cnt = 0;
    }
  }

  if (idx == -1) { 
    if (cnt > 0) { /* all zeros */
      ipstring[0] = ':';
      ipstring[1] = ':';
      ipstring[2] = '\0';
    }
    else { /* all non-zero */
      sprintf(ipstring, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx", 
                      temp[0], temp[1], temp[2], temp[3], 
                      temp[4], temp[5], temp[6], temp[7] );
    }
  }
  else {
    ipstring[0] = '\0';
    ptr = ipstring;

    if (idx == 0) {
      *ptr++ = ':';
      *ptr = '\0';
    }
    else { 
      for (i = 0; i < idx; i++) { 
        j = sprintf(ptr, "%hx:", temp[i]); 
        ptr += j; 
      }
    }

    i = idx + maxcnt;
    if (i == 8) {
      *ptr++ = ':';
      *ptr = '\0';
    }
    else { 
      for ( ; i < 8; i++) { 
        j = sprintf(ptr, ":%hx", temp[i]); 
        ptr += j; 
      }
    }
  }
}

void write_to_file_csv(FILE *fp, pcap_record_t *prec) {
  char srcip[40];
  char dstip[40];
  char *ptr;
  int i, j;


  if (prec->version == 4) {
    ptr = (char *)(prec->src_ip);
    sprintf(srcip, "%hhu.%hhu.%hhu.%hhu", *(uint8_t*)ptr, 
                                          *(uint8_t*)(ptr+1), 
                                          *(uint8_t*)(ptr+2), 
                                          *(uint8_t*)(ptr+3) );
    ptr = (char *)(prec->dst_ip);
    sprintf(dstip, "%hhu.%hhu.%hhu.%hhu", *(uint8_t*)ptr,
                                          *(uint8_t*)(ptr+1), 
                                          *(uint8_t*)(ptr+2), 
                                          *(uint8_t*)(ptr+3) );
  }
  else if (prec->version == 6) {
    ipv6addr2string( (uint8_t *)(prec->src_ip), srcip );
    ipv6addr2string( (uint8_t *)(prec->dst_ip), dstip );
  }
  else {
    /* empty string */
    srcip[0] = '\0';
    dstip[0] = '\0';
  }

  /* (No., Time, Source IP, Source Port, Destination IP, Destination Port, Protocol, Length, Info) */
  fprintf( fp, "%d,%u.%06u,%s,%d,%s,%d,%s,%d,%s\n", prec->number,
                                                  prec->ts_sec, 
                                                  prec->ts_usec, 
                                                  srcip, prec->src_port, 
                                                  dstip, prec->dst_port, 
                                                  prec->protocol, 
                                                  prec->framelen, 
                                                  prec->info );
}

void usage(char *progname) {
  printf("Usage: %s <pcap_file_path> <result_file_path>\n\n", progname);
}
