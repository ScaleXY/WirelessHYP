#pragma once
#include "epass2003.h"
#include <stdbool.h>
#include <stdint.h>
/* Persisted independently from the PIN. 'time' is elapsed microseconds since
 * that boot (there is no wall clock without a network/RTC). */
typedef struct { uint32_t version;int32_t code;uint64_t time_us; } pin_marker;
typedef struct {
    void *ctx;
    bool (*present)(void *);uint32_t (*generation)(void *);void (*reset)(void *);
    int (*prepare)(void *);int (*verify)(void *,const char *);
    int (*public_key)(void *,uint8_t[65]);int (*sign)(void *,const uint8_t[32],uint8_t[64]);
    uint16_t (*sw)(void *);uint64_t (*time_us)(void *);
    int (*save_marker)(void *,const pin_marker *); /* NULL clears, durable commit required */
    void (*became_ready)(void *,const uint8_t[65],bool changed);
} signer_ops;
typedef struct {
    signer_ops ops;pin_marker marker;bool rejected,ready,pin_set,first_seen;
    uint32_t generation;char pin[65];uint8_t point[65],first_point[65];int last_error;
} signer_service;
void signer_init(signer_service *s,const signer_ops *ops,const char *pin,const pin_marker *marker);
void signer_invalidate(signer_service *s);
int signer_open(signer_service *s);
int signer_run(signer_service *s,const uint8_t *digest,uint8_t sig[64]); /* digest NULL = pubkey */
int signer_set_pin(signer_service *s,const char *pin); /* caller durably saves PIN before this */
