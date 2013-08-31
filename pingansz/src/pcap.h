#ifndef _PINGANSZ_PCAP_H_
#define _PINGANSZ_PCAP_H_ 1

#define MAX_FNAME_LEN   255

#include <stdint.h>

typedef struct pcap_hdr_s { 
  uint32_t  magic_number;   /* detect file format and byte ordering */ 
  uint16_t  version_major;  /* major version number */ 
  uint16_t  version_minor;  /* minor version number */ 
  int32_t   thiszone;       /* correction time between UTC and local. 
                             * in practice, time stamps are always in UTC,
                             * so thiszone is always 0 */

  uint32_t  sigfigs;        /* accuracy of time stamps in the capture.
                             * in practice, all tools set it to 0 */ 

  uint32_t  snaplen;        /* snapshot length for the capture */
  uint32_t  network;        /* link-layer header type(1 for Ethernet) */
} pcap_hdr_t;


typedef struct pcaprec_hdr_s {
  uint32_t  ts_sec;         /* timestamp second */
  uint32_t  ts_usec;        /* timestamp microsecond */
  uint32_t  incl_len;       /* # of octets of packet saved in file */
  uint32_t  orig_len;       /* actual length of packet */
} pcaprec_hdr_t;



typedef struct PCAP_s {
  /* as iterator, is there more records */
  int           (*has_next_rec)(struct PCAP_s *);
  /* get the next record */
  int           (*next_rec)(struct PCAP_s *, pcaprec_hdr_t *, char *, int *);
  /* cleanup, close opened file */
  int           (*close)(struct PCAP_s *);

  FILE          *fp;
  pcap_hdr_t    fhdr;       /* pcap file header */
  int           swapped;    /* for endianess problem */
  long          filesize;   /* byte count of the pcap file */
} PCAP;

PCAP *pcap_open(const char *fname);

#endif /* _PINGANSZ_PCAP_H_ */
