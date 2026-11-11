/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Minimal ePass2003 driver derived from OpenSC 3856d69, card-epass2003.c.
 * Copyright (C) 2008 Weitao Sun; 2011 Xiaoshuo Wu. See LICENSE. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
enum { EP_IO=-1, EP_FORMAT=-2, EP_CRYPTO=-3, EP_KEY_NOT_FOUND=-4,
       EP_PIN_REJECTED=-5, EP_ABSENT=-6, EP_UNSUPPORTED=-7, EP_STORAGE=-8 };
#define EP_MAX 4096
void ep_zero(void *p, size_t n);
int ep_cipher(bool aes, bool triple, bool decrypt, const uint8_t *key,
              size_t keylen, const uint8_t *iv, const uint8_t *in, size_t n, uint8_t *out);
int ep_aes_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
int ep_sha1(const uint8_t *in, size_t n, uint8_t out[20]);
int ep_random(uint8_t *out, size_t n);
void ep_des_block(const uint8_t key[8], bool decrypt, const uint8_t in[8], uint8_t out[8]);
int ep_cmac(const uint8_t key[16], const uint8_t *in, size_t n, uint8_t out[16]);
typedef struct { bool aes, fips, active; uint8_t enc[16], mac[16], icv[16]; } ep_sm;
typedef struct {
    uint8_t cla, ins, p1, p2;
    const uint8_t *data; size_t lc;
    bool response; unsigned le; /* 0 means short Le=00, as in OpenSC */
} ep_apdu;
int ep_sm_wrap(ep_sm *sm, const ep_apdu *apdu, uint8_t *out, size_t *n);
int ep_sm_unwrap(ep_sm *sm, const uint8_t *in, size_t n, uint8_t *out, size_t *outn, uint16_t *sw);
int ep_sm_derive(ep_sm *sm, const uint8_t host[8], const uint8_t *init, size_t n, uint8_t external[16]);
typedef struct { uint8_t tag; const uint8_t *v; size_t n, total; } ep_tlv;
int ep_tlv_next(const uint8_t **p, size_t *n, ep_tlv *t);
int ep_tlv_find(const uint8_t *p, size_t n, uint8_t tag, ep_tlv *t);
typedef struct { uint8_t bytes[16]; size_t n; unsigned index, count; bool has_count; } ep_path;
typedef struct { ep_path path; uint8_t auth[16]; size_t authn; unsigned ref; bool has_ref; } ep_key;
int ep_p15_odf(const uint8_t *p, size_t n, uint8_t tag, ep_path *path);
int ep_p15_key(const uint8_t *p, size_t n, ep_key *key);
int ep_p15_pin(const uint8_t *p, size_t n, const uint8_t *auth, size_t authn, uint8_t *ref);
int ep_point(const uint8_t *p, size_t n, uint8_t point[65]);
int ep_low_s(uint8_t signature[64]);
typedef int (*ep_exchange)(void *ctx, const uint8_t *tx, size_t txn, uint8_t *rx, size_t *rxn);
typedef struct {
    ep_exchange exchange; void *ctx; ep_sm sm; uint16_t sw;
    uint8_t pin_ref; ep_key private_key; ep_path public_path;
    uint8_t point[65];
} ep_card;
void ep_card_init(ep_card *c, ep_exchange exchange, void *ctx);
int ep_card_prepare(ep_card *c); /* SM and PKCS#15 reference discovery, no PIN attempt */
int ep_card_verify(ep_card *c, const char *pin); /* exactly one external auth, no retries query */
int ep_card_public(ep_card *c);
int ep_card_sign(ep_card *c, const uint8_t digest[32], uint8_t signature[64]);
bool ep_pin_sw(uint16_t sw);
