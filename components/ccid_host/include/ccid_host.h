#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define CCID_CAP 4352
#define CCID_HEADER 10
typedef struct { uint8_t type,slot,seq,status,error,chain; const uint8_t *data;size_t n; } ccid_message;
int ccid_encode(uint8_t type,uint8_t seq,const uint8_t specific[3],const uint8_t *p,size_t n,uint8_t *out,size_t cap);
int ccid_decode(const uint8_t *p,size_t n,uint8_t type,uint8_t seq,ccid_message *m);
uint32_t ccid_le32(const uint8_t *p);
typedef int (*ccid_apdu_link)(void *,uint16_t,const uint8_t *,size_t,uint8_t *,size_t *,uint8_t *);
int ccid_apdu_exchange(ccid_apdu_link link,void *ctx,bool extended,size_t max_payload,const uint8_t *tx,size_t txn,uint8_t *rx,size_t *rxn);
/* T=1 protocol engine; link exchanges one TPDU using PC_to_RDR_XfrBlock. */
typedef int (*t1_link)(void *,const uint8_t *,size_t,uint8_t *,size_t *);
typedef struct { uint8_t send_seq,recv_seq,ifsc;bool crc; } ccid_t1;
int ccid_t1_atr(ccid_t1 *s,const uint8_t *atr,size_t n);
int ccid_t1_exchange(ccid_t1 *s,t1_link link,void *ctx,const uint8_t *in,size_t n,uint8_t *out,size_t *outn);
int ccid_host_init(void);
void ccid_host_poll(void);
bool ccid_host_present(void);
uint32_t ccid_host_generation(void);
int ccid_host_open(void);
void ccid_host_close(void);
int ccid_host_power_on(uint8_t *atr,size_t *n);
int ccid_host_power_off(void);
int ccid_host_slot_status(uint8_t *status);
int ccid_host_exchange(void *ctx,const uint8_t *tx,size_t txn,uint8_t *rx,size_t *rxn);
const char *ccid_host_detail(void);
