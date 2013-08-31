#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "pcap.h"

#define RETURN_ERROR(ERR, LOC) { save_errno = ERR; goto LOC; }

static int pcap_has_next(PCAP *ppcap);

static int pcap_next_rec(PCAP *ppcap,
              pcaprec_hdr_t *rechdr,
              char *buf, int *buflen);

static int pcap_close(PCAP *ppcap);

/**
 * Open the specified pcap file, initialization for later operation.
 * allocate memory for a new PCAP structure and open file with name 
 * <fname> and try to read its header info.
 * @param   fname   file path to a PCAP file
 * @return  pointer to PCAP structure when succeed,
 *          NULL when failed and set errno(-1 when PCAP format check failed).
 */
PCAP *pcap_open(const char *fname) {
  FILE      *fp = NULL;
  int       save_errno = 0;
  PCAP      *ppcap = NULL;
  size_t    retsize;

  if (fname == NULL) {
    RETURN_ERROR(EINVAL, error0);
  }

  if ( (ppcap = (PCAP *)malloc(sizeof(PCAP))) == NULL ) {
    RETURN_ERROR(errno, error0);
  }

  if ((fp = fopen(fname, "rb")) == NULL) {
    RETURN_ERROR(errno, error0);
  }

  retsize = fread( &(ppcap->fhdr),
                    sizeof(pcap_hdr_t),
                    1,
                    fp );
  if (retsize != 1) {
    RETURN_ERROR(errno, error0);
  }

  /* file header check */
  if (ppcap->fhdr.magic_number == 0xa1b2c3d4) {
    ppcap->swapped = 0;
  }
  else if (ppcap->fhdr.magic_number = 0xd4c3b2a1) {
    ppcap->swapped = 1;
  }
  else {
    /* pcap magic number check failed */
    RETURN_ERROR(-1, error0);
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    RETURN_ERROR(errno, error0);
  }

  retsize = ftell(fp);

  if (retsize == -1) {
    RETURN_ERROR(errno, error0);
  }

  /* the offset of the EOF relative to SEEK_SET
   * is equal file size when no hole in the file */
  ppcap->filesize = retsize;
  fprintf(stderr, "filesize = %ld\n", ppcap->filesize);

  /* set the offset of fp to the first record */
  if (fseek(fp, sizeof(pcap_hdr_t), SEEK_SET) != 0) {
    RETURN_ERROR(errno, error0);
  }

  ppcap->fp = fp;
  ppcap->has_next_rec = pcap_has_next;
  ppcap->next_rec = pcap_next_rec;
  ppcap->close = pcap_close;

  return ppcap;

error0:
  if (fp != NULL) {
    fclose(fp);
  }
  if (ppcap != NULL) {
    free(ppcap);
  }
  errno = save_errno;
  return NULL;
}

/**
 * Release resource when pcap operation ended.
 * @param   ppcap   pointer to PCAP structure
 * @return  0 when clean up succeed, otherwise -1 and set `errno`
 */
static int pcap_close(PCAP *ppcap) {

  if (ppcap == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fclose(ppcap->fp) != 0)
    return -1;

  free(ppcap);

  return 0;
}

/**
 * Whether there are more records.
 * @param   pcapfile    pointer to PCAP structure, must be initialized.
 * @return  1 when there are more records, otherwise 0.
 */
static int pcap_has_next(PCAP *ppcap) {
  /* we simply check the offset relative to SEEK_SET, then compare 
   * the offset value to filesize. if the data size after current
   * position is larger than sizeof(pcap_hdr_t), this method return 1.
   */
  long cur_pos;
  cur_pos = ftell(ppcap->fp);
  if (ppcap->filesize - cur_pos > sizeof(pcaprec_hdr_t)) {
    return 1;
  }

  return 0;
}

/**
 * Read a new record from < ppcap->fp >, store the record header to 
 * the position pointed by <rechdr>, and store the packet data to 
 * position pointed by <buf>, the integer pointed by <buflen> indicate
 * the length of the buffer, and when successful return, this value
 * would be the actual length of packet data be read.
 * @param   ppcap       pointer to an initilized PCAP structure
 * @param   rechdr      used to store the record header
 * @param   buf         used to store the record data
 * @param   buflen      value-result argument
 * @return  0 when success, and set the file offset to the end of latest
 *          read record, otherwise return -1 and set errno.
 */
static int pcap_next_rec(PCAP *ppcap,
              pcaprec_hdr_t *rechdr,
              char *buf, int *buflen) {

  int save_errno = 0;
  size_t    retsize;
  int offset;
  //long temp;

  //temp = ftell(ppcap->fp);

  //fprintf(stderr, "ftell() = %ld\n", temp);
  //fprintf(stderr, "buflen = %d\n", *buflen);

  retsize = fread(rechdr, sizeof(pcaprec_hdr_t), 1, ppcap->fp);

  if (retsize != 1) {
    fprintf(stderr, "%s:%d: fread() failed\n", __FILE__, __LINE__);
    //fprintf(stderr, "ftell() = %ld\n", temp);
    if (feof(ppcap->fp)) {
      fprintf(stderr, "Reached EOF(feof)\n");
    }
    else if (ferror(ppcap->fp)) {
      fprintf(stderr, "ERROR (ferror)\n");
    }
    RETURN_ERROR(errno, error0);
  }

  if (rechdr->incl_len < *buflen) {
    *buflen = rechdr->incl_len;
  }

  offset = rechdr->incl_len - *buflen;

  retsize = fread(buf, *buflen, 1, ppcap->fp);
  if (retsize != 1) { 
    fprintf(stderr, "%s:%d: fread() failed\n", __FILE__, __LINE__);
    if (feof(ppcap->fp)) {
      fprintf(stderr, "Reached EOF(feof)\n");
    }
    else if (ferror(ppcap->fp)) {
      fprintf(stderr, "ERROR (ferror)\n");
    }
    RETURN_ERROR(errno, error0);
  }

  /* point to next record */
  if (offset > 0) { 
    fseek(ppcap->fp, offset, SEEK_CUR);
  }

  return 0;

error0:
  // now this clean operation is called int the calling method
  //ppcap->close(ppcap); 

  return -1;
}
