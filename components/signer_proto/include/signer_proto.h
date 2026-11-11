#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define PROTO_LINE_MAX 512
typedef enum {OP_SIGN,OP_PUBKEY,OP_STATUS,OP_SET_PIN,OP_SET_ADMIN_PASSWORD} proto_op;
typedef struct { bool has_id;int64_t id;proto_op op;uint8_t digest[32];char pin[65];char password[65]; } proto_request;
int proto_digest(const char *s,uint8_t out[32]);
/* Strict flat JSON; duplicate/unknown fields, fractional IDs, NULs and
 * overlong strings are rejected. On error, a valid parsed id is retained. */
const char *proto_parse(const char *line,proto_request *r);
void proto_hex(const uint8_t *p,size_t n,char *out);
int proto_error(char *out,size_t n,const proto_request *r,bool fatal,const char *error);
int proto_public(char *out,size_t n,const proto_request *r,bool ready,const uint8_t point[65]);
int proto_signature(char *out,size_t n,const proto_request *r,const uint8_t sig[64],double ms);
int proto_status(char *out,size_t n,const proto_request *r,const char *token,bool pin_set,bool rejected);
int proto_ok(char *out,size_t n,const proto_request *r);
