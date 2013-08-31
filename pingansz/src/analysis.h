#ifndef _PINGANSZ_ANALYSIS_H_
#define _PINGANSZ_ANALYSIS_H_ 1

#define PARSE_LEN   60

// # of traffic record when representing traffic/second with line chart
#define TRAFFIC_INTERVAL    10

/*
 * The structure is used to save some state when
 * calculating round trip time
 */ 
typedef struct rtt_calc_s{

  /* 1 for SYN is dectected,
   * 2 for (SYN, <SYN,ACK>) are dectected
   * 0 for null state */
  int   conn_state;      

  // used to check the consecutive SYN and <SYN,ACK>
  uint32_t  seq_no;
  uint32_t  ack_no;

  // capture time of last record, the difference
  // of 2 capture time of handshake segment is 
  // treated as RTT
  uint32_t  ts_sec;
  uint32_t  ts_usec;


  // total time of all rounds ( SYN-><ACK,SYN> )
  // used with round to calculate average RTT 
  uint32_t  rtt_sec;
  uint32_t  rtt_usec;

  // number of round
  int       rtt_round;
} rtt_calc_t;

#endif /* _PINGANSZ_ANALYSIS_H_ */
