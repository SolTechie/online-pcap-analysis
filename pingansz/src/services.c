#include <stdint.h>
#include "services.h"

service_t services[] = {
  {  1, "tcpmux"},
  {  5, "rje"},
  {  7, "echo"},
  {  9, "discard"},
  { 11, "systat"},
  { 13, "daytime"},
  { 17, "qotd"},
  { 18, "msp"},
  { 19, "chargen"},
  { 20, "ftp-data"},
  { 21, "ftp"},
  { 22, "ssh"},
  { 23, "telnet"},
  { 24, "lmtp"},
  { 25, "smtp"},
  { 37, "time"},
  { 39, "rlp"},
  { 42, "nameserver"},
  { 43, "nicname"},
  { 49, "tacacs"},
  { 50, "re-mail-ck"},
  { 53, "dns"},      /* DNS */
  { 63, "whois++"},
  { 67, "bootps"},
  { 68, "bootpc"},
  { 69, "tftp"},
  { 70, "gopher"},
  { 71, "netrjs-1"},
  { 72, "netrjs-2"},
  { 73, "netrjs-3"},
  { 74, "netrjs-4"},
  { 79, "finger"},
  { 80, "http"},
  { 88, "kerberos"},
  { 95, "supdup"},
  {101, "hostname"},
  {102, "iso-tsap"},
  {105, "csnet-ns"},
  {107, "rtelnet"},
  {109, "pop2"},
  {110, "pop3"},
  {111, "sunrpc"},
  {113, "auth"},
  {115, "sftp"},
  {117, "uucp-path"},
  {119, "nntp"},
  {123, "ntp"},
  {137, "netbios-ns"},
  {138, "netbios-dgm"},
  {139, "netbios-ssn"},
  {143, "imap"},
  {161, "snmp"},
  {162, "snmptrap"},
  {163, "cmip-man"},
  {164, "cmip-agent"},
  {174, "mailq"},
  {177, "xdmcp"},
  {178, "nextstep"},
  {179, "bgp"},
  {191, "prospero"},
  {191, "prospero"},
  {194, "irc"},
  {199, "smux"},
  {201, "at-rtmp"},
  {202, "at-nbp"},
  {204, "at-echo"},
  {206, "at-zis"},
  {209, "qmtp"},
  {210, "z39.50"},
  {213, "ipx"},
  {220, "imap3"},
  {245, "link"},
  {270, "gist"},
  {347, "fatserv"},
  {363, "rsvp_tunnel"},
  {366, "odmr"},
  {369, "rpc2portmap"},
  {370, "codaauth2"},
  {372, "ulistproc"},
  {389, "ldap"},
  {400, "osb-sd"},
  {427, "svrloc"},
  {434, "mobileip-agent"},
  {435, "mobilip-mn"},
  {443, "https"},
  {444, "snpp"},
  {445, "microsoft-ds"},
  {464, "kpasswd"},
  {468, "photuris"},
  {487, "saft"},
  {488, "gss-http"},
  {496, "pim-rp-disc"},
  {500, "isakmp"},
  {535, "iiop"},
  {538, "gdomap"},
  {546, "dhcpv6-client"},
  {547, "dhcpv6-server"},
  {554, "rtsp"},
  {563, "nntps"},
  {565, "whoami"},
  {587, "submission"},
  {610, "npmp-local"},
  {611, "npmp-gui"},
  {612, "hmmp-ind"},
  {631, "ipp"},
  {636, "ldaps"},
  {674, "acap"},
  {694, "ha-cluster"},
  {749, "kerberos-adm"},
  {750, "kerberos-iv"},
  {765, "webster"},
  {767, "phonebook"},
  {873, "rsync"},
  {875, "rquotad"},
  {992, "telnets"},
  {993, "imaps"},
  {994, "ircs"},
  {995, "pop3s"},
  {1900, "ssdp"}
};

/*
 * search the service type according service port 
 * (80: http, 53: dns, ftp: 20,21, ...)
 * return the index of the service in services[] array.
 * return -1 if no service corresponding to the port
 */
int index_of_service(uint16_t port) {
  int low = 0;
  int high = SERVICE_COUNT - 1;
  int mid;

  if (port > services[SERVICE_COUNT - 1].port ||
      port < services[0].port) {
    return -1;
  }

  while (low <= high) {
    mid = (low + high) / 2;

    if (services[mid].port == port) {
      return mid;
    }
    else if (services[mid].port < port) {
      low = mid + 1;
    }
    else {
      high = mid - 1;
    }
  }

  return -1;
}

