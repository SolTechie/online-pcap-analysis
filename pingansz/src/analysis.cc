#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "pcap.h"
#include "services.h"
#include "parse.h"
#include "analysis.h"

using namespace std;

FILE    *fp_parse;

static int
ip2ip_rtt_handler( pcap_record_t *prec,
                   map<unsigned long long, rtt_calc_t> &ip2ip_rtt );

static int
ip2ip_traffic_handler( pcap_record_t *prec,
                       map<unsigned long long, long> &ip2ip_traffic );

static int
network_service_handler( pcap_record_t *prec,
                         map< int, set<uint32_t> > &serv_clients,
                         map< int, long > &traffic_of_service );

static void
per_sec_traffic_write(const char *fpath, vector< pair<uint32_t, long> > &result);

static void
ip2ip_traffic_write(const char *fpath, map<unsigned long long, long> &result);

static void
rtt_write(const char *fpath, map<unsigned long long, rtt_calc_t> &result);

static void
service_clients_traffic_write( const char *fpath, 
                               map< int, set<uint32_t> > &serv_clients, 
                               map< int, long > &traffic_of_service );

int analysis(PCAP *ppcap, const char *json_dir) {
  // total traffic per second
  vector< pair<uint32_t, long> > per_sec_traffic;
  uint32_t  pre_second;
  long      cnt;

  // key: <ip1, ip2>, value: traffic count
  map<unsigned long long, long> ip2ip_traffic;
  map<unsigned long long, long>::iterator itr_traffic;

  // key: <src_ip, dst_ip>
  map<unsigned long long, rtt_calc_t> ip2ip_rtt;
  map<unsigned long long, rtt_calc_t>::iterator itr_rtt;
  rtt_calc_t        pair_rtt;

  // count number of client and traffic of service
  map< int, set<uint32_t> > serv_clients;
  map< int, long > traffic_of_service;

  pcaprec_hdr_t     rechdr;
  char              buf[PARSE_LEN];
  int               buflen = PARSE_LEN;
  int               number = 0;

  uint32_t          start_sec, start_usec;
  uint32_t          sec, usec;
  pcap_record_t     *prec;

  char      per_sec_traffic_fname[MAX_FNAME_LEN];
  char      rtt_fname[MAX_FNAME_LEN];
  char      ip2ip_traffic_fname[MAX_FNAME_LEN];
  char      service_fname[MAX_FNAME_LEN];

  strcpy(per_sec_traffic_fname, json_dir);
  strcat(per_sec_traffic_fname, "traffic_per_second");

  strcpy(rtt_fname, json_dir);
  strcat(rtt_fname, "delay");

  strcpy(ip2ip_traffic_fname, json_dir);
  strcat(ip2ip_traffic_fname, "p2p_traffic");

  strcpy(service_fname, json_dir);
  strcat(service_fname, "service");

  // first captured record
  if ( ppcap->has_next_rec(ppcap) ) {
    if ( ppcap->next_rec( ppcap, &rechdr, buf, &buflen ) != 0 ) {
      fprintf(stderr, "%s:%d: next_rec() failed\n", __FILE__, __LINE__);
      return -1;
    }

    start_sec = rechdr.ts_sec;
    start_usec = rechdr.ts_usec;

    if ( (prec = (pcap_record_t*)malloc(sizeof(pcap_record_t))) == NULL ) {
      fprintf(stderr, "%s:%d: malloc() failed!\n", __FILE__, __LINE__);
      return -1;
    }

    prec->number    = ++number;
    prec->ts_sec    = 0;
    prec->ts_usec   = 0;
    prec->framelen  = rechdr.orig_len;

    parse_record(prec, buf, buflen);
    
    // write the parsed record to file with csv format
    write_to_file_csv(fp_parse, prec);

    // per second traffic count
    pre_second = 0;
    cnt = prec->framelen;

    // ip to ip traffic count
    ip2ip_rtt_handler(prec, ip2ip_rtt);

    // ip to ip delay count
    ip2ip_traffic_handler(prec, ip2ip_traffic);

    // network service
    network_service_handler(prec, serv_clients, traffic_of_service);

    while ( ppcap->has_next_rec(ppcap) ) {
      buflen = PARSE_LEN;

      if ( ppcap->next_rec(ppcap, &rechdr, buf, &buflen) != 0 ) {
        fprintf(stderr, "%s:%d: next_rec() failed: no. = %d\n", __FILE__, __LINE__, number);
        return -1;
      }

      sec = rechdr.ts_sec - start_sec;
      if (rechdr.ts_usec < start_usec) {
        sec--;
        usec = rechdr.ts_usec + 1000000 - start_usec;
      }
      else {
        usec = rechdr.ts_usec - start_usec;
      }

      prec->number      = ++number;
      prec->ts_sec      = sec;
      prec->ts_usec     = usec;
      prec->framelen    = rechdr.orig_len;

      parse_record(prec, buf, buflen);

      // write the parsed record to file with csv format
      write_to_file_csv(fp_parse, prec);

      // per second traffic count
      if (sec == pre_second) {
        cnt += prec->framelen;
      }
      else {
        per_sec_traffic.push_back( pair<uint32_t, long>(pre_second, cnt) );
        for ( ++pre_second; pre_second < sec; ++pre_second) {
          per_sec_traffic.push_back( pair<uint32_t, long>(pre_second, 0L) );
        }
        pre_second = sec;
        cnt = prec->framelen;
      }

      // ip to ip traffic count
      ip2ip_rtt_handler(prec, ip2ip_rtt);

      // ip to ip delay count
      ip2ip_traffic_handler(prec, ip2ip_traffic); 
      
      // network service
      network_service_handler(prec, serv_clients, traffic_of_service);
    }
  }

  // write the statistic result to file
  per_sec_traffic_write(per_sec_traffic_fname, per_sec_traffic);
  ip2ip_traffic_write(ip2ip_traffic_fname, ip2ip_traffic);
  rtt_write(rtt_fname, ip2ip_rtt);
  service_clients_traffic_write(service_fname, serv_clients, traffic_of_service);

  free(prec);

  return 0;
}

static void usage(char *progname) {
  printf("Usage: %s <pcap_file_path> <parse_file_path> <json_files_dir>\n\n", progname);
}

int main(int argc, char *argv[]) {
  char pcap_path[MAX_FNAME_LEN];
  char parse_file_path[MAX_FNAME_LEN];
  char json_files_dir[MAX_FNAME_LEN];
  PCAP *ppcap = NULL;
  char *ptrch;

  if (argc != 4) {
    usage(argv[0]);
    return 0;
  }

  strncpy(pcap_path, argv[1], MAX_FNAME_LEN);
  pcap_path[MAX_FNAME_LEN-1] = '\0';

  strncpy(parse_file_path, argv[2], MAX_FNAME_LEN);
  parse_file_path[MAX_FNAME_LEN-1] = '\0';

  strncpy(json_files_dir, argv[3], MAX_FNAME_LEN);
  for (ptrch = json_files_dir; *ptrch; ptrch++);
  if ( *(ptrch-1) != '/' ) {
    *ptrch++ = '/';
    *ptrch = '\0';
  }

  printf("pcap_path = %s\n", pcap_path);
  printf("parse_file_path= %s\n", parse_file_path);

  ppcap = pcap_open(pcap_path);

  if (ppcap == NULL) {
    ERR_LOG("pcap_open() failed!");
    return -1;
  }

  if ( (fp_parse = fopen(parse_file_path, "wt")) == NULL) {
    ERR_LOG("fopen failed!");
    return -1;
  } 
  // write field name
  fprintf(fp_parse, "No.,Time,Source IP Address,Source Port,Destination IP Address,Destination Port,Protocol,Length,Info\n");

  if (analysis(ppcap, json_files_dir) != 0) {
    fprintf(stderr, "analysis() failed!\n");
  }

  ppcap->close(ppcap);

  return 0;
}

static int
ip2ip_traffic_handler( pcap_record_t *prec,
                       map<unsigned long long, long> &ip2ip_traffic ) {
  map<unsigned long long, long>::iterator itr;
  uint32_t  ipsrc, ipdst;
  long long key;
  long      cnt;
  // only handle ipv4 traffic
  if (prec->version == 4) {
    ipsrc = ntohl( prec->src_ip[0] );
    ipdst = ntohl( prec->dst_ip[0] );

    if (ipsrc < ipdst) {
      key = ipsrc;
      key = (key << 32) | ipdst;
    }
    else {
      key = ipdst;
      key = (key << 32) | ipsrc;
    }

    cnt = prec->pktsize;

    itr = ip2ip_traffic.find(key);
    if (itr == ip2ip_traffic.end()) {
      ip2ip_traffic.insert(pair<unsigned long long, long>(key, cnt));
    }
    else {
      itr->second += cnt;
    }
  }

  return 0;
}

static int
ip2ip_rtt_handler( pcap_record_t *prec,
                   map<unsigned long long, rtt_calc_t> &ip2ip_rtt ) { 
  map<unsigned long long, rtt_calc_t>::iterator itr;
  uint32_t      ipsrc, ipdst;
  long long     key;
  rtt_calc_t    pair_rtt;

  if (prec->version == 4 && prec->tcp_info.valid) { // TCP header info is available 
    ipsrc = ntohl( prec->src_ip[0] );
    ipdst = ntohl( prec->dst_ip[0] );

    if (prec->tcp_info.syn && !prec->tcp_info.ack) { // first handshake segment 
      key = ipsrc; 
      key = (key << 32) | ipdst;

      itr = ip2ip_rtt.find(key); 
      
      if (itr == ip2ip_rtt.end()) {
        pair_rtt.conn_state = 1;
        pair_rtt.seq_no = prec->tcp_info.seq_no;
        pair_rtt.ts_sec = prec->ts_sec;
        pair_rtt.ts_usec = prec->ts_usec; 

        pair_rtt.rtt_sec = 0;
        pair_rtt.rtt_usec = 0;
        pair_rtt.rtt_round = 0;

        ip2ip_rtt.insert( pair<unsigned long long, rtt_calc_t>(key, pair_rtt) ); 
      } 
      else { 
        itr->second.conn_state = 1;
        itr->second.seq_no    = prec->tcp_info.seq_no; 
        itr->second.ts_sec    = prec->ts_sec; 
        itr->second.ts_usec   = prec->ts_usec; 
      }
    } 
    else if (prec->tcp_info.syn && prec->tcp_info.ack) { 
      key = ipdst; 
      key = (key << 32) | ipsrc;

      itr = ip2ip_rtt.find(key); 
      if (itr != ip2ip_rtt.end()) {
        if ( itr->second.conn_state == 1 &&
             itr->second.seq_no + 1 == prec->tcp_info.ack_no ) { 
          itr->second.conn_state = 2; 
          itr->second.rtt_sec += prec->ts_sec - itr->second.ts_sec; 
          if (prec->ts_usec < itr->second.ts_usec) { 
            itr->second.rtt_usec += prec->ts_usec + 1000000 - itr->second.ts_usec; 
            itr->second.rtt_sec--; 
          }
          else {
            itr->second.rtt_usec += prec->ts_usec - itr->second.ts_usec; 
          }

          itr->second.rtt_round++;
        }
      }
    }
  }

  return 0;
}

/*
 * @param   prec            pointer to parsed record
 * @param   serv_clients    map of service index(services[]) to client ip set of this service
 * @param   traffic_of_service  map of service index to the traffic of this service
 */
static int
network_service_handler( pcap_record_t *prec,
                         map< int, set<uint32_t> > &serv_clients,
                         map< int, long > &traffic_of_service ) {
  map< int, set<uint32_t> >::iterator map_itr1;
  map< int, long >::iterator map_itr2;
  int   serv_idx;

  if (prec->version == 4) { 
    serv_idx = index_of_service( prec->dst_port ); 

    if (serv_idx != -1) { 
      // client ip
      map_itr1 = serv_clients.find(serv_idx); 
      if (map_itr1 == serv_clients.end()) { 
        set<uint32_t> ip_set; 
        ip_set.insert( ntohl(prec->src_ip[0]) ); 
        serv_clients.insert( pair< int, set<uint32_t> >(serv_idx, ip_set) );
      }
      else {
        map_itr1->second.insert( ntohl(prec->src_ip[0]) );
      }

      // traffic count
      map_itr2 = traffic_of_service.find(serv_idx); 
      if ( map_itr2 == traffic_of_service.end() ) {
        traffic_of_service.insert( pair< int, long >(serv_idx, prec->pktsize) );
      }
      else {
        map_itr2->second += prec->pktsize;
      }
    }

    if ( prec->src_port != prec->dst_port ) { 
      serv_idx = index_of_service( prec->src_port );
      if (serv_idx != -1) {
        // traffic count 
        map_itr2 = traffic_of_service.find(serv_idx); 
        if ( map_itr2 == traffic_of_service.end() ) {
          traffic_of_service.insert( pair< int, long >(serv_idx, prec->pktsize) );
        }
        else {
          map_itr2->second += prec->pktsize;
        }
      }
    }
  }

  return 0;
}

static void
per_sec_traffic_write(const char *fpath, vector< pair<uint32_t, long> > &result) {
  FILE  *fp = NULL;
  char  fname[MAX_FNAME_LEN];
  vector< pair<uint32_t, long> >::iterator itr;

  int   interval_len;
  long  traffic;
  int   i, j;

  if (result.size() < 1) {
    return;
  }

  strcpy(fname, fpath);
  strcat(fname, "_list.json");

  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf(stderr, "%s:%d: fopen() failed when opening file %s for writing\n",
                    __FILE__, __LINE__, fname);
    return;
  }

  itr = result.begin();
  fprintf( fp, "[\n{\n\t\"second\" : %u,\n\t\"traffic\" : %ld\n}",
                itr->first, itr->second );
  for ( ++itr; itr != result.end(); ++itr ) {
    fprintf( fp, ",\n{\n\t\"second\" : %u,\n\t\"traffic\" : %ld\n}",
                  itr->first, itr->second );
  }
  fprintf( fp, "\n]");

  fclose(fp);

  strcpy(fname, fpath);
  strcat(fname, "_line.json");

  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf(stderr, "%s:%d: fopen() failed when opening file %s for writing\n",
                    __FILE__, __LINE__, fname);
    return;
  }

  interval_len = result.size() / TRAFFIC_INTERVAL;
  if (interval_len < 0) {
    interval_len = 1;
  }

  if (interval_len == 1) { 
    fprintf( fp, "{\n\t\"labels\" : [\"0\"" ); 
    for (i = 0; i < result.size(); i++) {
      fprintf( fp, ",\"%d\"", i );
    }
    itr = result.begin();
    fprintf( fp, "],\n\t\"datasets\" : [\n\t\t{\n\t\t\t\"fillColor\" : \"rgba(151,187,205,0.5)\",\n\t\t\t\"strokeColor\" : \"rgba(151,187,205,1)\",\n\t\t\t\"pointColor\" : \"rgba(151,187,205,1)\",\n\t\t\t\"pointStrokeColor\" : \"#fff\",\n\t\t\t\"data\" : [%ld", itr->second );
    for (++itr; itr != result.end(); ++itr) {
      fprintf( fp, ",%ld", itr->second );
    }
    fprintf( fp, "]\n\t\t}\t]\n}" );
  }
  else { 
    fprintf( fp, "{\n\t\"labels\" : [\"0-%d\"", interval_len - 1 );
    for (i = interval_len; i+interval_len < result.size(); i += interval_len) {
      fprintf( fp, ",\"%d-%d\"", i, i + interval_len - 1 );
    }
    /* the value result.size() may not be a multiple of interval_len */
    fprintf( fp, ",\"%d-%d\"],", i, (int)result.size() - 1 );

    traffic = 0; 
    for (i = 0, itr = result.begin(); i < interval_len; ++i, ++itr) { 
      traffic += itr->second; 
    }
    fprintf( fp, "\n\t\"datasets\" : [\n\t\t{\n\t\t\t\"fillColor\" : \"rgba(151,187,205,0.5)\",\n\t\t\t\"strokeColor\" : \"rgba(151,187,205,1)\",\n\t\t\t\"pointColor\" : \"rgba(151,187,205,1)\",\n\t\t\t\"pointStrokeColor\" : \"#fff\",\n\t\t\t\"data\" : [%ld", traffic );

    for (i = interval_len; i+interval_len < result.size(); i += interval_len) {
      traffic = 0;
      for (j = 0; j < interval_len; ++j, ++itr) {
        traffic += itr->second;
      }
      fprintf( fp, ",%ld", traffic );
    }

    traffic = 0;
    for ( ; itr != result.end(); ++itr) {
      traffic += itr->second;
    }
    fprintf( fp, ",%ld]\n\t\t}\n\t]\n}", traffic );
  }

  fclose(fp);
}

static bool
cmp(pair<unsigned long long, long> x, pair<unsigned long long, long> y) {
  return    x.second > y.second;
}

static void
rtt_write(const char *fpath, map<unsigned long long, rtt_calc_t> &result) {
  FILE  *fp = NULL;
  char  ip_string[51][2][16];
  long  rtt_usec[51];

  uint8_t   ip[8];
  int   cnt, k;
  char  fname[MAX_FNAME_LEN];

  vector<pair<unsigned long long, long> >           rtt_list;
  vector<pair<unsigned long long, long> >::iterator vec_itr;
  map<unsigned long long, rtt_calc_t>::iterator     map_itr;

  for (map_itr = result.begin(); map_itr != result.end(); ++map_itr) {
    if (map_itr->second.rtt_round > 0) { 
      // calculate the average RTT in microsecond
      rtt_list.push_back( pair<unsigned long long, long>(map_itr->first, (map_itr->second.rtt_sec * 1000000 + map_itr->second.rtt_usec) / map_itr->second.rtt_round ) );
    }
  }

  if (rtt_list.size() < 1) {
    return;
  }

  sort(rtt_list.begin(), rtt_list.end(), cmp);

  strcpy(fname, fpath);
  strcat(fname, "_list.json");

  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf(stderr, "fopen() failed when opening %s for writing!\n", fname);
    return;
  }

  cnt = 0;
  for ( vec_itr = rtt_list.begin();
        vec_itr != rtt_list.end() && cnt < 50;
        ++vec_itr, ++cnt) {
    memcpy(ip, &(vec_itr->first), 8);
    sprintf(ip_string[cnt][0], "%hhu.%hhu.%hhu.%hhu", ip[7], ip[6], ip[5], ip[4]);
    sprintf(ip_string[cnt][1], "%hhu.%hhu.%hhu.%hhu", ip[3], ip[2], ip[1], ip[0]);
    rtt_usec[cnt] = vec_itr->second;
  }

  fprintf( fp, "[\n{\n\t\"ipPair\" : \"%s-%s\",\n\t\"rtt\" : %ld\n}",
               ip_string[0][0], ip_string[0][1], rtt_usec[0] ); //us
  for (k = 1; k < cnt; k++) { 
    fprintf( fp, ",\n{\n\t\"ipPair\" : \"%s-%s\",\n\t\"rtt\": %ld\n}",
                 ip_string[k][0], ip_string[k][1], rtt_usec[k] );
  }

  for ( ;
         vec_itr != rtt_list.end();
         ++vec_itr ) {
    memcpy(ip, &(vec_itr->first), 8);
    sprintf(ip_string[50][0], "%hhu.%hhu.%hhu.%hhu", ip[7], ip[6], ip[5], ip[4]);
    sprintf(ip_string[50][1], "%hhu.%hhu.%hhu.%hhu", ip[3], ip[2], ip[1], ip[0]);
    rtt_usec[50] = vec_itr->second;
    fprintf( fp, ",\n{\n\t\"ipPair\" : \"%s-%s\",\n\t\"rtt\": %ld\n}",
                 ip_string[50][0], ip_string[50][1], rtt_usec[50] );
  }
  fprintf( fp, "\n]");
  fclose(fp);           // write list finished

  strcpy(fname, fpath);
  strcat(fname, "_bar.json");
  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf(stderr, "fopen() failed when opening %s for writing!\n", fname);
    return;
  }

  fprintf(fp, "{\n\t\"labels\" : [\"%s-%s\"", ip_string[0][0], ip_string[0][1]);
  for (k = 1; k < cnt; k++) {
    fprintf(fp, ",\"%s-%s\"", ip_string[k][0], ip_string[k][1]);
  }
  fprintf(fp, "],\n\t\"datasets\" : [\n\t{\n\t\t\"fillColor\" : \"rgba(151,187,205, 0.5)\",\n\t\t\"strokeColor\" : \"rgba(151,187,205,1)\",\n\t\t\"data\" :[%ld", rtt_usec[0]);
  for (k = 1; k < cnt; k++) {
    fprintf(fp, ",%ld", rtt_usec[k]);
  }
  fprintf(fp, "]\n\t}\n\t]\n}");

  fclose(fp);
}

static void
ip2ip_traffic_write(const char *fpath, map<unsigned long long, long> &result) {
  FILE  *fp = NULL;
  char  ip_string[11][2][16];
  long  top10[11];
  char  color[11][8] = {"#F7464A", "#E2EAE9", "#D4CCC5", "#949FB1", "#4D5360",
                        "#F38630", "#E0E4CC", "#69D2E7", "#83567D", "#CFDB30",
                        "#CEF9B8" /* for other */
                       };
  //long  other;
  uint8_t   ip[8];
  int   cnt, k;
  char  fname[MAX_FNAME_LEN];

  vector<pair<unsigned long long, long> >           traffic;
  vector<pair<unsigned long long, long> >::iterator vec_itr;
  map<unsigned long long, long>::iterator           itr;

  for (itr = result.begin(); itr != result.end(); ++itr) {
    traffic.push_back( *itr );
  }

  if (traffic.size() < 1) {
    return;
  }

  sort(traffic.begin(), traffic.end(), cmp);

  strcpy(fname, fpath);
  strcat(fname, "_list.json");
  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf(stderr, "fopen() failed when opening %s for writing!\n", fname);
    return;
  }

  cnt = 0;
  for ( vec_itr = traffic.begin();
        vec_itr != traffic.end() && cnt < 10;
        ++vec_itr, ++cnt) {
    memcpy(ip, &(vec_itr->first), 8);
    sprintf(ip_string[cnt][0], "%hhu.%hhu.%hhu.%hhu", ip[7], ip[6], ip[5], ip[4]);
    sprintf(ip_string[cnt][1], "%hhu.%hhu.%hhu.%hhu", ip[3], ip[2], ip[1], ip[0]);
    top10[cnt] = vec_itr->second;
    //total_traffic += vec_itr->second;
  }

  fprintf( fp, "[\n{\n\t\"ipPair\" : \"%s-%s\",\n\t\"traffic\" : %ld\n}",
                ip_string[0][0], ip_string[0][1], top10[0] );
  for (k = 1; k < cnt; k++) {
    fprintf( fp, ",\n{\n\t\"ipPair\" : \"%s-%s\",\n\t\"traffic\" : %ld\n}",
                  ip_string[k][0], ip_string[k][1], top10[k] );
  }

  //other = 0;
  for ( ; vec_itr != traffic.end(); ++vec_itr ) {
    //other += vec_itr->second;
    memcpy(ip, &(vec_itr->first), 8);
    sprintf(ip_string[10][0], "%hhu.%hhu.%hhu.%hhu", ip[7], ip[6], ip[5], ip[4]);
    sprintf(ip_string[10][1], "%hhu.%hhu.%hhu.%hhu", ip[3], ip[2], ip[1], ip[0]);

    fprintf( fp, ",\n{\n\t\"ipPair\" : \"%s-%s\",\n\t\"traffic\" : %ld\n}",
                  ip_string[k][0], ip_string[k][1], vec_itr->second );
  }
  fprintf(fp, "\n]");
  fclose(fp);

  strcpy(fname, fpath);
  strcat(fname, "_pie.json");
  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf(stderr, "fopen() failed when opening %s for writing!\n", fname);
    return;
  }

  fprintf(fp, "[\n{\n\t\"value\" : %ld,\n\t\"color\" : \"%s\"\n}", top10[0], color[0]);
  for (k = 1; k < cnt; k++) { 
    fprintf(fp, ",\n{\n\t\"value\" : %ld,\n\t\"color\" : \"%s\"\n}", top10[k], color[k]);
  }
  /*
  if (other != 0) {
    fprintf(fp, ",\n{\n\tvalue : %ld,\n\tcolor : \"%s\"\n}", other, color[10]);
  }*/
  fprintf(fp, "\n]");

  fclose(fp);
}

static void
service_clients_traffic_write( const char *fpath, 
                               map< int, set<uint32_t> > &serv_clients, 
                               map< int, long > &traffic_of_service ) {
  FILE  *fp = NULL;
  char  fname[MAX_FNAME_LEN];

  strcpy(fname, fpath);
  strcat(fname, "_traffic_bar.json");

  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf( stderr, "%s:%d: fopen() failed when open file %s for writing!\n",
                     __FILE__, __LINE__, fname );
    return;
  }

  if (traffic_of_service.size() > 0) { 
    map< int, long >::iterator traffic_itr; 
    traffic_itr = traffic_of_service.begin(); 
    fprintf( fp, "{\n\t\"labels\" : [\"%s\"",
                  services[ traffic_itr->first ].name ); 
    for (++traffic_itr; traffic_itr != traffic_of_service.end();
            ++traffic_itr) { 
      fprintf( fp, ",\"%s\"", services[ traffic_itr->first ].name ); 
    } 

    traffic_itr = traffic_of_service.begin(); 
    fprintf( fp, "],\n\t\"datasets\" : [\n\t\t{\n\t\t\t\"fillColor\" : \"rgba(151,187,205,0.5)\",\n\t\t\t\"strokeColor\" : \"rgba(151,187,205,1)\",\n\t\t\t\"data\" : [%ld", traffic_itr->second);
    for (++traffic_itr; traffic_itr != traffic_of_service.end();
            ++traffic_itr) { 
      fprintf( fp, ",%ld", traffic_itr->second ); 
    } 
    fprintf( fp, "]\n\t\t}\n\t]\n}" );
  }

  fclose(fp);

  strcpy(fname, fpath);
  strcat(fname, "_clients_count_bar.json");

  if ( (fp = fopen(fname, "wt")) == NULL ) {
    fprintf( stderr, "%s:%d: fopen() failed when open file %s for writing!\n",
                     __FILE__, __LINE__, fname );
    return;
  }
  if (serv_clients.size() > 0) { 
    map< int, set<uint32_t> >::iterator client_itr; 
    client_itr = serv_clients.begin(); 
    fprintf( fp, "{\n\t\"labels\" : [\"%s\"",
                  services[ client_itr->first ].name ); 
    for (++client_itr; client_itr != serv_clients.end();
            ++client_itr) { 
      fprintf( fp, ",\"%s\"", services[ client_itr->first ].name ); 
    } 

    client_itr = serv_clients.begin(); 
    fprintf( fp, "],\n\t\"datasets\" : [\n\t\t{\n\t\t\t\"fillColor\" : \"rgba(151,187,205,0.5)\",\n\t\t\t\"strokeColor\" : \"rgba(151,187,205,1)\",\n\t\t\t\"data\" : [%ld", client_itr->second.size() );
    for (++client_itr; client_itr != serv_clients.end();
            ++client_itr) { 
      fprintf( fp, ",%d", (int)(client_itr->second.size()) ); 
    } 
    fprintf( fp, "]\n\t\t}\n\t]\n}" );
  }

  fclose(fp);
}
