#include "json_out.h"
#include "signer_proto.h"
#include "web_logic.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
  hyp_profile p[3] = {{.ssid = "a", .priority = 5},
                      {.ssid = "b", .priority = 5},
                      {.ssid = "hidden", .priority = 100, .hidden = true}};
  hyp_network n[2] = {{.ssid = "a", .rssi = -60}, {.ssid = "b", .rssi = -40}};
  assert(!hyp_validate(&p[0]));
  strcpy(p[0].password, "short");
  assert(hyp_validate(&p[0]));
  p[0].password[0] = 0;
  assert(hyp_select(p, 3, n, 2, 0) == 1);
  p[0].priority = 6;
  assert(hyp_select(p, 3, n, 2, 0) == 0);
  assert(hyp_select(p, 3, n, 2, 3) == 2);
  assert(hyp_select(p, 3, n, 2, 7) == -1);
  p[0].hidden = true;
  assert(hyp_select(p, 3, n, 2, 0) == 1);
  p[0].hidden = false;
  hyp_auth a = {0};
  for (int i = 0; i < 5; i++)
    hyp_login_result(&a, false, 100);
  assert(hyp_lock_remaining(&a, 100) == 60);
  assert(!hyp_lock_remaining(&a, 160));
  const char *t = "0123456789abcdef0123456789abcdef";
  hyp_session_add(&a, t, 200);
  assert(hyp_session_find(&a, t, 201) >= 0);
  assert(hyp_session_find(&a, t, 43401) == -1);
  for (int i = 0; i < 16; i++) {
    bool get = i & 1, pub = i & 2, csrf = i & 4, aut = i & 8;
    assert(hyp_gate(get, pub, csrf, aut) == (!get && !csrf  ? 403
                                             : !pub && !aut ? 401
                                                            : 0));
  }
  assert(hyp_equal("hello", "hello"));
  assert(!hyp_equal("hello", "hell"));
  assert(!hyp_equal("x", "y"));
  assert(hyp_should_seed(false, false, "test"));
  assert(!hyp_should_seed(true, false, "test"));
  assert(!hyp_should_seed(false, true, "test"));
  assert(!hyp_should_seed(false, false, ""));
  hyp_json j;
  assert(hyp_json_parse(
      "{\"ssid\":\"a\",\"password\":\"\",\"priority\":100,\"hidden\":true}",
      &j));
  assert(hyp_field_get(&j, "hidden")->boolean);
  assert(hyp_field_get(&j, "priority")->number == 100);
  assert(hyp_json_parse("{\"current\":\"oldpassword\",\"new\":\"newpassword\"}",
                        &j));
  assert(hyp_json_parse("{\"id\":2}", &j));
  assert(hyp_json_parse("{\"password\":\"a\\\"b\"}", &j));
  assert(hyp_json_parse("{\"ssid\":\"\\u00e9\\ud83d\\ude00\"}", &j));
  assert(strlen(hyp_field_get(&j, "ssid")->text) == 6);
  assert(!hyp_json_parse("{\"id\":2147483648}", &j));
  assert(!hyp_json_parse("{\"ssid\":\"\\ud800\"}", &j));
  const char *bad[] = {"{\"id\":1,\"id\":2}", "{\"id\":1.5}",
                       "{\"id\":01}",         "{\"id\":null}",
                       "{\"id\":[]}",         "{}x",
                       "{\"id\":true,}",      "{\"password\":\"\\u0000\"}"};
  for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++)
    assert(!hyp_json_parse(bad[i], &j));
  proto_request r;
  assert(!proto_parse(
      "{\"id\":1,\"op\":\"set_admin_password\",\"password\":\"testpass\"}",
      &r));
  assert(r.op == OP_SET_ADMIN_PASSWORD);
  assert(proto_parse("{\"op\":\"set_admin_password\",\"password\":\"short\"}",
                     &r));
  cJSON *out = cJSON_CreateObject();
  cJSON_AddStringToObject(out, "ssid", "a\"b\\c\n");
  cJSON_AddBoolToObject(out, "connected", false);
  char *encoded = cJSON_PrintUnformatted(out);
  assert(encoded && hyp_json_parse(encoded, &j));
  assert(!strcmp(hyp_field_get(&j, "ssid")->text, "a\"b\\c\n"));
  free(encoded);
  cJSON_Delete(out);
  puts("PASS web logic: profiles, priority/RSSI/hidden selection, "
       "sessions/lockout, auth/CSRF, JSON, credential seed decisions, UART "
       "admin");
  return 0;
}
