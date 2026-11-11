#include "web.h"
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "json_out.h"
#include "mdns.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "web_logic.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static SemaphoreHandle_t mu, scan_mu;
static nvs_handle_t nv;
static bool usable, connected, ap_active, servers, attempting;
static int active = -1, requested = -1, next_id = 1;
static hyp_profile profiles[WIFI_MAX];
static int count;
static hyp_auth auth;
static char admin[65], name[32], mac_text[18], ip[16], ap_ip[16];
static esp_netif_t *sta_net, *ap_net;
static uint64_t started, connected_at, next_attempt, attempt_at;
static unsigned tried, backoff;
static bool switching;
static struct {
  bool present, ready, pin_set, rejected;
  uint8_t point[65];
  bool usb_host;
  int usb_devices;
  uint16_t vid, pid;
  char usb_detail[96], open_error[128];
} token;
extern unsigned char hyp_cert[], hyp_key[];
extern char hyp_fingerprint[];
extern bool hyp_cert_init(nvs_handle_t nv);
extern const unsigned char page_start[] asm("_binary_index_html_start");
extern const unsigned char page_end[] asm("_binary_index_html_end");
#if CONFIG_HYP_WEB_HTTP_SERVE
#define HTTP_MODE "serve"
#elif CONFIG_HYP_WEB_HTTP_OFF
#define HTTP_MODE "off"
#else
#define HTTP_MODE "redirect"
#endif
#define LOCK() xSemaphoreTake(mu, portMAX_DELAY)
#define UNLOCK() xSemaphoreGive(mu)
static uint64_t now(void) { return (uint64_t)esp_timer_get_time() / 1000000; }
void hyp_web_publish(bool p, bool r, bool pin, bool rejected,
                     const uint8_t point[65]) {
  if (!mu)
    return;
  LOCK();
  token.present = p;
  token.ready = r;
  token.pin_set = pin;
  token.rejected = rejected;
  memcpy(token.point, point, 65);
  UNLOCK();
}
void hyp_web_publish_diag(bool host, int devices, uint16_t vid, uint16_t pid,
                          const char *usb_detail, const char *open_error) {
  if (!mu)
    return;
  LOCK();
  token.usb_host = host;
  token.usb_devices = devices;
  token.vid = vid;
  token.pid = pid;
  snprintf(token.usb_detail, sizeof(token.usb_detail), "%s", usb_detail ? usb_detail : "");
  snprintf(token.open_error, sizeof(token.open_error), "%s", open_error ? open_error : "");
  UNLOCK();
}
bool hyp_admin_set(const char *p) {
  size_t n = strlen(p);
  if (n < 8 || n > 64 || !mu || !usable)
    return false;
  LOCK();
  bool ok = nvs_set_blob(nv, "admin", p, n + 1) == ESP_OK &&
            nvs_set_u8(nv, "admin_seeded", 1) == ESP_OK &&
            nvs_commit(nv) == ESP_OK;
  if (ok) {
    memcpy(admin, p, n + 1);
    memset(&auth, 0, sizeof(auth));
  }
  UNLOCK();
  return ok;
}
static void headers(httpd_req_t *r) {
  httpd_resp_set_hdr(r, "Content-Security-Policy",
                     "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                     "script-src 'self' 'unsafe-inline'; img-src 'self' data:");
  httpd_resp_set_hdr(r, "X-Frame-Options", "DENY");
  httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");
  httpd_resp_set_hdr(r, "Referrer-Policy", "no-referrer");
  if (!strncmp(r->uri, "/api/", 5))
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
}
static esp_err_t reply(httpd_req_t *r, int status, cJSON *j) {
  const char *s = status == 200   ? "200 OK"
                  : status == 201 ? "201 Created"
                  : status == 202 ? "202 Accepted"
                  : status == 400 ? "400 Bad Request"
                  : status == 401 ? "401 Unauthorized"
                  : status == 403 ? "403 Forbidden"
                  : status == 404 ? "404 Not Found"
                  : status == 409 ? "409 Conflict"
                  : status == 413 ? "413 Payload Too Large"
                  : status == 429 ? "429 Too Many Requests"
                                  : "500 Internal Server Error";
  httpd_resp_set_status(r, s);
  httpd_resp_set_type(r, "application/json");
  char *text = cJSON_PrintUnformatted(j);
  esp_err_t e = httpd_resp_send(
      r, text ? text : "{\"error\":\"out of memory\"}", HTTPD_RESP_USE_STRLEN);
  free(text);
  cJSON_Delete(j);
  return e;
}
static esp_err_t error(httpd_req_t *r, int code, const char *s) {
  cJSON *j = cJSON_CreateObject();
  cJSON_AddStringToObject(j, "error", s);
  return reply(r, code, j);
}
static esp_err_t okay(httpd_req_t *r, int code) {
  cJSON *j = cJSON_CreateObject();
  cJSON_AddBoolToObject(j, "ok", true);
  return reply(r, code, j);
}
static cJSON *profile_json(int k) {
  hyp_profile *p = &profiles[k];
  cJSON *j = cJSON_CreateObject();
  cJSON_AddNumberToObject(j, "id", p->id);
  cJSON_AddStringToObject(j, "ssid", p->ssid);
  cJSON_AddNumberToObject(j, "priority", p->priority);
  cJSON_AddBoolToObject(j, "hidden", p->hidden);
  cJSON_AddBoolToObject(j, "has_password", p->password[0] != 0);
  cJSON_AddBoolToObject(j, "active", connected && active == p->id);
  return j;
}
static bool save_profiles(void) {
  return nvs_set_blob(nv, "profiles", profiles, sizeof(profiles)) == ESP_OK &&
         nvs_set_i32(nv, "count", count) == ESP_OK &&
         nvs_set_i32(nv, "next_id", next_id) == ESP_OK &&
         nvs_commit(nv) == ESP_OK;
}
static int scan(hyp_network *out, int max) {
  if (xSemaphoreTake(scan_mu, pdMS_TO_TICKS(5000)) != pdTRUE)
    return -1;
  wifi_scan_config_t cfg = {.show_hidden = false,
                            .scan_time.active = {.min = 80, .max = 120}};
  esp_err_t e = esp_wifi_scan_start(&cfg, true);
  uint16_t n = 64;
  wifi_ap_record_t *records = calloc(n, sizeof(*records));
  if (!records) {
    xSemaphoreGive(scan_mu);
    return -1;
  }
  if (e == ESP_OK)
    e = esp_wifi_scan_get_ap_records(&n, records);
  int used = 0;
  if (e == ESP_OK)
    for (unsigned i = 0; i < n; i++) {
      if (!records[i].ssid[0])
        continue;
      int k;
      for (k = 0; k < used; k++)
        if (!strcmp(out[k].ssid, (char *)records[i].ssid))
          break;
      if (k == used) {
        if (used == max)
          continue;
        used++;
      } else if (out[k].rssi >= records[i].rssi)
        continue;
      memcpy(out[k].ssid, records[i].ssid, 32);
      out[k].ssid[32] = 0;
      out[k].rssi = records[i].rssi;
      out[k].channel = records[i].primary;
      out[k].auth = records[i].authmode;
    }
  free(records);
  xSemaphoreGive(scan_mu);
  return e == ESP_OK ? used : -1;
}
static const char *auth_name(int a) {
  switch (a) {
  case WIFI_AUTH_OPEN:
    return "open";
  case WIFI_AUTH_WEP:
    return "wep";
  case WIFI_AUTH_WPA_PSK:
    return "wpa";
  case WIFI_AUTH_WPA2_PSK:
    return "wpa2";
  case WIFI_AUTH_WPA3_PSK:
    return "wpa3";
  case WIFI_AUTH_WPA2_WPA3_PSK:
    return "wpa2/wpa3";
  case WIFI_AUTH_WPA2_ENTERPRISE:
    return "enterprise";
  default:
    return "other";
  }
}
static void reboot_task(void *arg) {
  (void)arg;
  vTaskDelay(pdMS_TO_TICKS(500));
  esp_restart();
}
static cJSON *status_json(void) {
  cJSON *j = cJSON_CreateObject(), *d = cJSON_AddObjectToObject(j, "device"),
        *w = cJSON_AddObjectToObject(j, "wifi"),
        *t = cJSON_AddObjectToObject(j, "token"),
        *web = cJSON_AddObjectToObject(j, "web");
  cJSON_AddStringToObject(d, "name", name);
  cJSON_AddStringToObject(d, "version", esp_app_get_description()->version);
  cJSON_AddNumberToObject(d, "uptime_s", now());
  cJSON_AddStringToObject(d, "mac", mac_text);
  cJSON_AddStringToObject(w, "mode",
                          ap_active ? (connected ? "apsta" : "apsta") : "sta");
  cJSON_AddBoolToObject(w, "connected", connected);
  wifi_ap_record_t ap;
  bool has = connected && esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
  if (has) {
    cJSON_AddStringToObject(w, "ssid", (char *)ap.ssid);
    cJSON_AddNumberToObject(w, "rssi", ap.rssi);
    cJSON_AddStringToObject(w, "ip", ip);
  } else {
    cJSON_AddNullToObject(w, "ssid");
    cJSON_AddNullToObject(w, "rssi");
    cJSON_AddNullToObject(w, "ip");
  }
  cJSON_AddBoolToObject(w, "ap_active", ap_active);
  cJSON_AddStringToObject(w, "ap_ssid", name);
  if (ap_active)
    cJSON_AddStringToObject(w, "ap_ip", ap_ip);
  else
    cJSON_AddNullToObject(w, "ap_ip");
  cJSON_AddStringToObject(t, "state",
                          token.present ? (token.ready ? "ready" : "present")
                                        : "absent");
  cJSON_AddBoolToObject(t, "pin_set", token.pin_set);
  cJSON_AddBoolToObject(t, "pin_rejected", token.rejected);
  cJSON *u = cJSON_AddObjectToObject(t, "usb");
  cJSON_AddBoolToObject(u, "host", token.usb_host);
  cJSON_AddNumberToObject(u, "devices", token.usb_devices);
  if (token.vid || token.pid) {
    char id[10];
    snprintf(id, sizeof(id), "%04x:%04x", token.vid, token.pid);
    cJSON_AddStringToObject(u, "id", id);
  } else
    cJSON_AddNullToObject(u, "id");
  cJSON_AddStringToObject(u, "detail", token.usb_detail);
  if (token.open_error[0] && !token.ready)
    cJSON_AddStringToObject(t, "error", token.open_error);
  else
    cJSON_AddNullToObject(t, "error");
  if (token.ready) {
    char h[67];
    const char *hex = "0123456789abcdef";
    for (int xy = 0; xy < 2; xy++) {
      h[0] = '0';
      h[1] = 'x';
      for (int i = 0; i < 32; i++) {
        unsigned b = token.point[1 + 32 * xy + i];
        h[2 + 2 * i] = hex[b >> 4];
        h[3 + 2 * i] = hex[b & 15];
      }
      h[66] = 0;
      cJSON_AddStringToObject(t, xy ? "qy" : "qx", h);
    }
  } else {
    cJSON_AddNullToObject(t, "qx");
    cJSON_AddNullToObject(t, "qy");
  }
  cJSON_AddBoolToObject(web, "https", true);
  cJSON_AddStringToObject(web, "http_mode", HTTP_MODE);
  cJSON_AddStringToObject(web, "cert_sha256", hyp_fingerprint);
  return j;
}
static esp_err_t api(httpd_req_t *r, hyp_json *body, int session, bool secure) {
  const char *u = r->uri;
  bool get = r->method == HTTP_GET;
  const hyp_field *f;
  if (get && !strcmp(u, "/api/session")) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddBoolToObject(j, "authenticated", session >= 0);
    cJSON_AddBoolToObject(j, "setup_ap", ap_active);
    return reply(r, 200, j);
  }
  if (r->method == HTTP_POST && !strcmp(u, "/api/login")) {
    unsigned left = hyp_lock_remaining(&auth, now());
    if (left) {
      cJSON *j = cJSON_CreateObject();
      cJSON_AddStringToObject(j, "error", "locked");
      cJSON_AddNumberToObject(j, "retry_after", left);
      return reply(r, 429, j);
    }
    f = hyp_field_get(body, "password");
    bool ok = f && f->type == J_STRING && admin[0] && hyp_equal(admin, f->text);
    hyp_login_result(&auth, ok, now());
    if (!ok)
      return error(r, 401, "bad password");
    unsigned char random[16];
    char value[33], cookie[160];
    esp_fill_random(random, sizeof(random));
    for (int i = 0; i < 16; i++)
      snprintf(value + 2 * i, 3, "%02x", random[i]);
    hyp_session_add(&auth, value, now());
    snprintf(cookie, sizeof(cookie),
             "hyp_session=%s; HttpOnly; SameSite=Strict; Path=/%s", value,
             secure ? "; Secure" : "");
    httpd_resp_set_hdr(r, "Set-Cookie", cookie);
    return okay(r, 200);
  }
  if (r->method == HTTP_POST && !strcmp(u, "/api/logout")) {
    memset(&auth.sessions[session], 0, sizeof(auth.sessions[session]));
    httpd_resp_set_hdr(
        r, "Set-Cookie",
        secure ? "hyp_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/; "
                 "Secure"
               : "hyp_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/");
    return okay(r, 200);
  }
  if (get && !strcmp(u, "/api/status"))
    return reply(r, 200, status_json());
  if (get && !strcmp(u, "/api/wifi/profiles")) {
    cJSON *j = cJSON_CreateObject(), *a = cJSON_AddArrayToObject(j, "profiles");
    cJSON_AddNumberToObject(j, "max", 8);
    for (int i = 0; i < count; i++)
      cJSON_AddItemToArray(a, profile_json(i));
    return reply(r, 200, j);
  }
  if (get && !strcmp(u, "/api/wifi/scan")) {
    hyp_network nets[64] = {0};
    UNLOCK();
    int n = scan(nets, 64);
    LOCK();
    if (n < 0)
      return error(r, 500, "scan unavailable");
    cJSON *j = cJSON_CreateObject(), *a = cJSON_AddArrayToObject(j, "networks");
    for (int i = 0; i < n; i++) {
      cJSON *o = cJSON_CreateObject();
      cJSON_AddStringToObject(o, "ssid", nets[i].ssid);
      cJSON_AddNumberToObject(o, "rssi", nets[i].rssi);
      cJSON_AddNumberToObject(o, "channel", nets[i].channel);
      cJSON_AddStringToObject(o, "auth", auth_name(nets[i].auth));
      bool known = false;
      for (int k = 0; k < count; k++)
        if (!strcmp(profiles[k].ssid, nets[i].ssid))
          known = true;
      cJSON_AddBoolToObject(o, "known", known);
      cJSON_AddItemToArray(a, o);
    }
    return reply(r, 200, j);
  }
  if (r->method == HTTP_POST && !strcmp(u, "/api/wifi/connect")) {
    f = hyp_field_get(body, "id");
    if (!f || f->type != J_NUMBER)
      return error(r, 400, "id required");
    for (int k = 0; k < count; k++)
      if (profiles[k].id == f->number) {
        requested = f->number;
        next_attempt = 0;
        return okay(r, 202);
      }
    return error(r, 404, "profile not found");
  }
  bool create = r->method == HTTP_POST && !strcmp(u, "/api/wifi/profiles");
  if (create || !strncmp(u, "/api/wifi/profiles/", 19)) {
    int k = count;
    if (!create) {
      char *end;
      long id = strtol(u + 19, &end, 10);
      if (*end || id < 1)
        return error(r, 404, "profile not found");
      for (k = 0; k < count; k++)
        if (profiles[k].id == id)
          break;
      if (k == count)
        return error(r, 404, "profile not found");
    }
    hyp_profile backup[8];
    memcpy(backup, profiles, sizeof(backup));
    int old_count = count, old_next = next_id;
    if (r->method == HTTP_DELETE && !create) {
      memmove(profiles + k, profiles + k + 1,
              (size_t)(count - k - 1) * sizeof(*profiles));
      memset(&profiles[--count], 0, sizeof(*profiles));
    } else if (create || r->method == HTTP_PUT) {
      if (create && count == 8)
        return error(r, 409, "profile limit reached");
      hyp_profile p = create ? (hyp_profile){.id = next_id} : profiles[k];
      for (unsigned i = 0; i < body->count; i++) {
        f = &body->fields[i];
        if (!strcmp(f->key, "ssid")) {
          if (f->type != J_STRING || strlen(f->text) > 32)
            return error(r, 400, "invalid ssid");
          strcpy(p.ssid, f->text);
        } else if (!strcmp(f->key, "password")) {
          if (f->type != J_STRING || strlen(f->text) > 63)
            return error(r, 400, "invalid password");
          strcpy(p.password, f->text);
        } else if (!strcmp(f->key, "priority")) {
          if (f->type != J_NUMBER)
            return error(r, 400, "invalid priority");
          p.priority = f->number;
        } else if (!strcmp(f->key, "hidden")) {
          if (f->type != J_BOOL)
            return error(r, 400, "invalid hidden");
          p.hidden = f->boolean;
        } else
          return error(r, 400, "unknown field");
      }
      if (create &&
          (!hyp_field_get(body, "ssid") || !hyp_field_get(body, "password") ||
           !hyp_field_get(body, "priority") || !hyp_field_get(body, "hidden")))
        return error(r, 400, "missing profile field");
      const char *err = hyp_validate(&p);
      if (err)
        return error(r, 400, err);
      for (int i = 0; i < count; i++)
        if (i != k && !strcmp(profiles[i].ssid, p.ssid))
          return error(r, 409, "duplicate SSID");
      profiles[k] = p;
      if (create) {
        count++;
        next_id++;
      }
    } else
      return error(r, 404, "not found");
    tried = 0;
    if (!save_profiles()) {
      memcpy(profiles, backup, sizeof(backup));
      count = old_count;
      next_id = old_next;
      return error(r, 500, "storage failure");
    }
    if (r->method == HTTP_DELETE) {
      if (active == backup[k].id) {
        requested = -2;
        next_attempt = 0;
      }
      return okay(r, 200);
    }
    cJSON *j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "profile", profile_json(k));
    return reply(r, create ? 201 : 200, j);
  }
  if (r->method == HTTP_POST && !strcmp(u, "/api/admin/password")) {
    const hyp_field *cur = hyp_field_get(body, "current"),
                    *newp = hyp_field_get(body, "new");
    if (!cur || cur->type != J_STRING || !newp || newp->type != J_STRING ||
        strlen(newp->text) < 8 || strlen(newp->text) > 64)
      return error(r, 400, "password must be 8-64 characters");
    if (!hyp_equal(admin, cur->text))
      return error(r, 401, "bad password");
    if (nvs_set_blob(nv, "admin", newp->text, strlen(newp->text) + 1) !=
            ESP_OK ||
        nvs_set_u8(nv, "admin_seeded", 1) != ESP_OK || nvs_commit(nv) != ESP_OK)
      return error(r, 500, "storage failure");
    strcpy(admin, newp->text);
    for (int i = 0; i < 4; i++)
      if (i != session)
        memset(&auth.sessions[i], 0, sizeof(auth.sessions[i]));
    return okay(r, 200);
  }
  if (r->method == HTTP_POST && !strcmp(u, "/api/reboot")) {
    esp_err_t e = okay(r, 200);
    xTaskCreate(reboot_task, "reboot", 2048, NULL, 3, NULL);
    return e;
  }
  return error(r, 404, "not found");
}
static esp_err_t handler(httpd_req_t *r) {
  headers(r);
  bool secure = r->user_ctx != NULL;
  if (!secure && !strcmp(HTTP_MODE, "redirect")) {
    httpd_resp_set_status(r, "301 Moved Permanently");
    /* Use the client's Host (IP or name) so it works without mDNS; fall back
     * to the mDNS name if the header is missing or has unexpected chars. */
    char location[96]; /* must outlive httpd_resp_send below */
    char host[64] = {0};
    bool ok = httpd_req_get_hdr_value_str(r, "Host", host, sizeof(host)) == ESP_OK && host[0];
    for (char *p = host; ok && *p; p++) {
      if (*p == ':' && strchr(host, '[') == NULL) { *p = 0; break; } /* drop :80 */
      if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-' || *p == '[' || *p == ']' || *p == ':'))
        ok = false;
    }
    snprintf(location, sizeof(location), "https://%s/", ok && host[0] ? host : "wirelesshyp.local");
    httpd_resp_set_hdr(r, "Location", location);
    return httpd_resp_send(r, NULL, 0);
  }
  if (r->content_len > 1024) {
    httpd_resp_set_hdr(r, "Connection", "close");
    return error(r, 413, "body too large");
  }
  if (!strcmp(r->uri, "/") && r->method == HTTP_GET) {
    httpd_resp_set_type(r, "text/html; charset=utf-8");
    return httpd_resp_send(r, (const char *)page_start,
                           page_end - page_start - 1);
  }
  if (strncmp(r->uri, "/api/", 5))
    return error(r, 404, "not found");
  char csrf[8] = {0}, cookie[512] = {0}, value[33] = {0};
  httpd_req_get_hdr_value_str(r, "X-HYP", csrf, sizeof(csrf));
  httpd_req_get_hdr_value_str(r, "Cookie", cookie, sizeof(cookie));
  char *p = cookie;
  while (*p) {
    while (*p == ' ' || *p == ';')
      p++;
    char *end = strchr(p, ';');
    size_t n = end ? (size_t)(end - p) : strlen(p);
    if (n == 44 && !strncmp(p, "hyp_session=", 12)) {
      memcpy(value, p + 12, 32);
      break;
    }
    if (!end)
      break;
    p = end + 1;
  }
  LOCK();
  int session = hyp_session_find(&auth, value, now());
  bool public_api =
      (r->method == HTTP_GET && !strcmp(r->uri, "/api/session")) ||
      (r->method == HTTP_POST && !strcmp(r->uri, "/api/login"));
  int gate = hyp_gate(r->method == HTTP_GET, public_api, !strcmp(csrf, "1"),
                      session >= 0);
  UNLOCK();
  if (gate)
    return error(r, gate,
                 gate == 403 ? "CSRF header required" : "unauthorized");
  char text[1025] = {0};
  size_t read = 0;
  while (read < r->content_len) {
    int n = httpd_req_recv(r, text + read, r->content_len - read);
    if (n <= 0)
      return error(r, 400, "incomplete body");
    read += (size_t)n;
  }
  hyp_json body = {0};
  if (r->content_len &&
      (memchr(text, 0, r->content_len) || !hyp_json_parse(text, &body))) {
    memset(text, 0, sizeof(text));
    return error(r, 400, "bad JSON");
  }
  memset(text, 0, sizeof(text));
  LOCK();
  session = hyp_session_find(&auth, value, now());
  esp_err_t result;
  if (!public_api && session < 0)
    result = error(r, 401, "unauthorized");
  else
    result = api(r, &body, session, secure);
  UNLOCK();
  memset(&body, 0, sizeof(body));
  memset(cookie, 0, sizeof(cookie));
  return result;
}
static esp_err_t framework_error(httpd_req_t *r, httpd_err_code_t code) {
  headers(r);
  httpd_resp_set_hdr(r, "Connection", "close");
  static const char *statuses[HTTPD_ERR_CODE_MAX] = {
      [HTTPD_500_INTERNAL_SERVER_ERROR] = "500 Internal Server Error",
      [HTTPD_501_METHOD_NOT_IMPLEMENTED] = "501 Not Implemented",
      [HTTPD_505_VERSION_NOT_SUPPORTED] = "505 HTTP Version Not Supported",
      [HTTPD_400_BAD_REQUEST] = "400 Bad Request",
      [HTTPD_401_UNAUTHORIZED] = "401 Unauthorized",
      [HTTPD_403_FORBIDDEN] = "403 Forbidden",
      [HTTPD_404_NOT_FOUND] = "404 Not Found",
      [HTTPD_405_METHOD_NOT_ALLOWED] = "405 Method Not Allowed",
      [HTTPD_408_REQ_TIMEOUT] = "408 Request Timeout",
      [HTTPD_411_LENGTH_REQUIRED] = "411 Length Required",
      [HTTPD_413_CONTENT_TOO_LARGE] = "413 Payload Too Large",
      [HTTPD_414_URI_TOO_LONG] = "414 URI Too Long",
      [HTTPD_431_REQ_HDR_FIELDS_TOO_LARGE] =
          "431 Request Header Fields Too Large"};
  httpd_resp_set_status(r, code < HTTPD_ERR_CODE_MAX && statuses[code]
                               ? statuses[code]
                               : "500 Internal Server Error");
  httpd_resp_set_type(r, "application/json");
  return httpd_resp_send(r, "{\"error\":\"request rejected\"}",
                         HTTPD_RESP_USE_STRLEN);
}
static void register_handlers(httpd_handle_t h, bool secure) {
  for (int e = 0; e < HTTPD_ERR_CODE_MAX; e++)
    ESP_ERROR_CHECK(
        httpd_register_err_handler(h, (httpd_err_code_t)e, framework_error));
  const httpd_method_t methods[] = {HTTP_GET,    HTTP_POST,  HTTP_PUT,
                                    HTTP_DELETE, HTTP_PATCH, HTTP_OPTIONS,
                                    HTTP_HEAD};
  for (unsigned i = 0; i < sizeof(methods) / sizeof(*methods); i++) {
    httpd_uri_t u = {.uri = "/*",
                     .method = methods[i],
                     .handler = handler,
                     .user_ctx = secure ? (void *)1 : NULL};
    ESP_ERROR_CHECK(httpd_register_uri_handler(h, &u));
  }
}
static void start_servers(void) {
  if (servers || !admin[0])
    return;
  if (!hyp_cert_init(nv)) {
    ESP_LOGE("web", "Certificate initialization failed; servers disabled");
    return;
  }
  httpd_handle_t h;
  httpd_ssl_config_t c = HTTPD_SSL_CONFIG_DEFAULT();
  c.httpd.uri_match_fn = httpd_uri_match_wildcard;
  c.httpd.stack_size = 16384;
  c.httpd.lru_purge_enable = true;
  c.servercert = hyp_cert;
  c.servercert_len = strlen((char *)hyp_cert) + 1;
  c.prvtkey_pem = hyp_key;
  c.prvtkey_len = strlen((char *)hyp_key) + 1;
  if (httpd_ssl_start(&h, &c) != ESP_OK) {
    ESP_LOGE("web", "HTTPS start failed");
    return;
  }
  register_handlers(h, true);
  servers = true;
  if (strcmp(HTTP_MODE, "off")) {
    httpd_config_t plain = HTTPD_DEFAULT_CONFIG();
    plain.uri_match_fn = httpd_uri_match_wildcard;
    plain.stack_size = 12288;
    plain.lru_purge_enable = true;
    if (httpd_start(&h, &plain) == ESP_OK)
      register_handlers(h, false);
    else
      ESP_LOGE("web", "HTTP start failed");
  }
}
static void event(void *arg, esp_event_base_t base, int32_t id, void *data) {
  (void)arg;
  LOCK();
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    if (switching) {
      switching = false;
      UNLOCK();
      return;
    }
    if (connected)
      started = now(); /* outage start: AP fallback waits 30 s from here */
    connected = false;
    attempting = false;
    next_attempt = now() + (1u << (backoff < 5 ? backoff++ : 5));
  } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *e = data;
    snprintf(ip, sizeof(ip), IPSTR, IP2STR(&e->ip_info.ip));
    connected = true;
    attempting = false;
    connected_at = now();
    backoff = 0;
    for (int i = 0; i < count; i++)
      profiles[i].last_connected = profiles[i].id == active;
    if (!save_profiles())
      ESP_LOGE("wifi", "Could not persist last connected profile");
  }
  UNLOCK();
}
static void ap_start(void) {
  if (ap_active || !admin[0])
    return;
  if (strlen(admin) == 64) {
    ESP_LOGE("wifi", "SoftAP requires an admin passphrase of 8-63 characters");
    return;
  }
  wifi_config_t c = {0};
  strcpy((char *)c.ap.ssid, name);
  c.ap.ssid_len = strlen(name);
  memcpy(c.ap.password, admin, strlen(admin));
  c.ap.authmode = WIFI_AUTH_WPA2_PSK;
  c.ap.max_connection = 4;
  if (esp_wifi_set_mode(WIFI_MODE_APSTA) == ESP_OK &&
      esp_wifi_set_config(WIFI_IF_AP, &c) == ESP_OK) {
    ap_active = true;
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(ap_net, &info) == ESP_OK)
      snprintf(ap_ip, sizeof(ap_ip), IPSTR, IP2STR(&info.ip));
  }
}
static void wifi_task(void *arg) {
  (void)arg;
  hyp_network nets[64];
  for (;;) {
    LOCK();
    uint64_t t = now();
    static uint64_t next_server_try;
    if (admin[0] && !servers && t >= next_server_try) {
      start_servers();
      next_server_try = t + 30;
    }
    if (!connected && (count == 0 || t - started >= 30))
      ap_start();
    if (connected && ap_active && t - connected_at >= 60) {
      if (esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK)
        ap_active = false;
    }
    if (attempting && t - attempt_at >= 12) {
      esp_wifi_disconnect();
      attempting = false;
      next_attempt = t + 1;
    }
    if (connected && requested == -2) {
      if (esp_wifi_disconnect() == ESP_OK)
        switching = true;
      connected = false;
      started = now();
      active = -1;
    }
    bool run = requested != -1 ||
               (!connected && !attempting && t >= next_attempt && count);
    if (run) {
      int manual = requested;
      requested = -1;
      UNLOCK();
      memset(nets, 0, sizeof(nets));
      int nn = manual >= 0 ? 0 : scan(nets, 64);
      LOCK();
      int k = -1;
      if (manual >= 0) {
        for (int i = 0; i < count; i++)
          if (profiles[i].id == manual)
            k = i;
      } else {
        k = hyp_select(profiles, count, nets, nn < 0 ? 0 : nn, tried);
        if (k < 0) {
          tried = 0;
          k = hyp_select(profiles, count, nets, nn < 0 ? 0 : nn, 0);
        }
      }
      if (k >= 0) {
        tried |= 1u << k;
        wifi_config_t c = {0};
        memcpy(c.sta.ssid, profiles[k].ssid, strlen(profiles[k].ssid));
        memcpy(c.sta.password, profiles[k].password,
               strlen(profiles[k].password));
        c.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
        if ((connected || attempting) && esp_wifi_disconnect() == ESP_OK)
          switching = true;
        active = profiles[k].id;
        if (connected)
          started = now();
        connected = false;
        if (esp_wifi_set_config(WIFI_IF_STA, &c) == ESP_OK &&
            esp_wifi_connect() == ESP_OK) {
          attempting = true;
          attempt_at = now();
        }
      }
      if (!attempting)
        next_attempt = now() + 5;
    }
    UNLOCK();
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
void hyp_web_init(void) {
  mu = xSemaphoreCreateMutex();
  scan_mu = xSemaphoreCreateMutex();
  if (!mu || !scan_mu)
    return;
  usable = nvs_open("hyp_web", NVS_READWRITE, &nv) == ESP_OK;
  if (!usable) {
    ESP_LOGE("web", "NVS unavailable; networking disabled");
    return;
  }
  size_t n = sizeof(admin);
  esp_err_t e = nvs_get_blob(nv, "admin", admin, &n);
  uint8_t seeded = 0;
  esp_err_t se = nvs_get_u8(nv, "admin_seeded", &seeded);
  if ((se != ESP_OK && se != ESP_ERR_NVS_NOT_FOUND) ||
      (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND) ||
      (e == ESP_OK &&
       (n < 9 || n > 65 || admin[n - 1] || strlen(admin) != n - 1))) {
    usable = false;
    return;
  }
  if (hyp_should_seed(e == ESP_OK, seeded, CONFIG_HYP_WEB_ADMIN_PASSWORD))
    hyp_admin_set(CONFIG_HYP_WEB_ADMIN_PASSWORD);
  int32_t v = 0;
  e = nvs_get_i32(nv, "count", &v);
  if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND)
    return;
  if (v < 0 || v > 8)
    return;
  count = v;
  n = sizeof(profiles);
  if (count && nvs_get_blob(nv, "profiles", profiles, &n) != ESP_OK)
    return;
  if (count && n != sizeof(profiles))
    return;
  for (int i = 0; i < count; i++)
    if (!memchr(profiles[i].ssid, 0, 33) ||
        !memchr(profiles[i].password, 0, 64) || hyp_validate(&profiles[i]))
      return;
  v = 1;
  nvs_get_i32(nv, "next_id", &v);
  for (int i = 0; i < count; i++)
    if (profiles[i].id >= v)
      v = profiles[i].id + 1;
  next_id = v < 1 ? 1 : v;
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(name, sizeof(name), "WirelessHYP-%02X%02X", mac[4], mac[5]);
  snprintf(mac_text, sizeof(mac_text), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
           mac[1], mac[2], mac[3], mac[4], mac[5]);
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  sta_net = esp_netif_create_default_wifi_sta();
  ap_net = esp_netif_create_default_wifi_ap();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(
      esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event, NULL));
  ESP_ERROR_CHECK(
      esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event, NULL));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());
  if (mdns_init() == ESP_OK) {
    mdns_hostname_set("wirelesshyp");
    mdns_instance_name_set(name);
    mdns_service_add(NULL, "_https", "_tcp", 443, NULL, 0);
  }
  if (admin[0])
    start_servers();
  else
    ESP_LOGW("web", "Admin password not set; SoftAP and web servers disabled "
                    "until reboot after UART provisioning");
  started = now();
  xTaskCreate(wifi_task, "hyp_wifi", 8192, NULL, 4, NULL);
}
