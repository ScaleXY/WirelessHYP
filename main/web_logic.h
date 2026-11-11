#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define WIFI_MAX 8
typedef struct {
  int id;
  char ssid[33], password[64];
  int priority;
  bool hidden, last_connected;
} hyp_profile;
typedef struct {
  char ssid[33];
  int rssi, channel, auth;
} hyp_network;
typedef struct {
  char token[33];
  uint64_t touched;
} hyp_session;
typedef struct {
  hyp_session sessions[4];
  unsigned failures;
  uint64_t locked_until;
} hyp_auth;
typedef struct {
  char key[24], text[129];
  enum { J_STRING, J_NUMBER, J_BOOL } type;
  int number;
  bool boolean;
} hyp_field;
typedef struct {
  hyp_field fields[8];
  unsigned count;
} hyp_json;
const char *hyp_validate(const hyp_profile *p);
int hyp_select(const hyp_profile *p, int count, const hyp_network *n, int nn,
               unsigned tried);
bool hyp_equal(const char *a, const char *b);
int hyp_session_find(hyp_auth *a, const char *token, uint64_t now);
void hyp_session_add(hyp_auth *a, const char *token, uint64_t now);
unsigned hyp_lock_remaining(hyp_auth *a, uint64_t now);
void hyp_login_result(hyp_auth *a, bool ok, uint64_t now);
int hyp_gate(bool get, bool public_api, bool csrf, bool authenticated);
bool hyp_should_seed(bool exists, bool seeded, const char *value);
bool hyp_json_parse(const char *text, hyp_json *out);
const hyp_field *hyp_field_get(const hyp_json *j, const char *key);
