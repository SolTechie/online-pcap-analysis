#ifndef _PINGANSZ_PARSE_H_
#define _PINGANSZ_PARSE_H_ 1

#define ERR_LOG(err_msg) do{fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, err_msg); }while(0);

#define UNICAST 0
#define MULTICAST 1
#define BROADCAST 2

typedef struct tcp_hdr_s {
  uint8_t   valid;      /* tagging the validity of this record */
  uint32_t  seq_no;     /* sequence number */
  uint32_t  ack_no;     /* acknowledge number */

  uint8_t   fin;        /* FIN flag */
  uint8_t   syn;        /* SYN flag */
  uint8_t   ack;        /* ACK flag */
} tcp_hdr_t;

typedef struct pcap_record_s {
  int       number;         /* record number  */
  uint32_t  ts_sec;
  uint32_t  ts_usec;
  int       framelen;       /* frame length */

  int       version;        /* ip version */
  int       pktsize;         /* ip packet length */
  int       v4_cast;        /* ipv4 packet cast(0:unicast, 1:multicast, 2: broadcast) */

  uint32_t  src_ip[4];      /* ip address */
  int       src_port;       /* port */

  uint32_t  dst_ip[4];
  int       dst_port;

  tcp_hdr_t tcp_info;       /* when the transport layer segment is TCP */

  char      protocol[40];   /* protocol like IP:TCP:HTTP */
  char      info[1024];
} pcap_record_t;

int parse_record(pcap_record_t *prec, const char *pktdata, int pktlen);
void write_to_file_csv(FILE *fp, pcap_record_t *prec);

#endif  /* _PINGANSZ_PARSE_H_ */
