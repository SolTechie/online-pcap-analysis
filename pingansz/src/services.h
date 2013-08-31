#ifndef _PINGANSZ_SERVICES_H_
#define _PINGANSZ_SERVICES_H_ 1

typedef struct service_s {
  uint16_t  port;
  char      name[65];
  //char      description[129];
} service_t;

#define SERVICE_COUNT   119
extern service_t services[];

int index_of_service(uint16_t port);

#endif  /* _PINGANSZ_SERVICES_H_ */
