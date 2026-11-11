#include "web_logic.h"
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
const char *hyp_validate(const hyp_profile *p) {
  size_t s = strlen(p->ssid), n = strlen(p->password);
  if (!s || s > 32)
    return "ssid must be 1-32 bytes";
  if (n && (n < 8 || n > 63))
    return "password must be empty or 8-63 characters";
  if (p->priority < 0 || p->priority > 100)
    return "priority must be 0-100";
  return NULL;
}
int hyp_select(const hyp_profile *p, int count, const hyp_network *n, int nn,
               unsigned tried) {
  int best = -1, br = -1000;
  bool bv = false;
  for (int i = 0; i < count; i++) {
    if (tried & (1u << i))
      continue;
    int r = -1000;
    bool visible = false;
    for (int k = 0; k < nn; k++)
      if (!p[i].hidden && !strcmp(p[i].ssid, n[k].ssid)) {
        visible = true;
        if (n[k].rssi > r)
          r = n[k].rssi;
      }
    if (!visible && !p[i].hidden)
      continue;
    if (best < 0 || (visible && !bv) ||
        (visible == bv && (p[i].priority > p[best].priority ||
                           (p[i].priority == p[best].priority && r > br)))) {
      best = i;
      br = r;
      bv = visible;
    }
  }
  return best;
}
bool hyp_equal(const char *a, const char *b) {
  unsigned diff = 0;
  size_t na = strlen(a), nb = strlen(b);
  diff = (unsigned)(na ^ nb);
  for (size_t i = 0; i < 64; i++) {
    unsigned x = i < na ? (unsigned char)a[i] : 0,
             y = i < nb ? (unsigned char)b[i] : 0;
    diff |= x ^ y;
  }
  return diff == 0;
}
int hyp_session_find(hyp_auth *a, const char *t, uint64_t now) {
  for (int i = 0; i < 4; i++) {
    if (a->sessions[i].token[0] && now - a->sessions[i].touched >= 43200)
      memset(&a->sessions[i], 0, sizeof(a->sessions[i]));
    if (t && a->sessions[i].token[0] && hyp_equal(t, a->sessions[i].token)) {
      a->sessions[i].touched = now;
      return i;
    }
  }
  return -1;
}
void hyp_session_add(hyp_auth *a, const char *t, uint64_t now) {
  int k = 0;
  for (int i = 0; i < 4; i++)
    if (!a->sessions[i].token[0] ||
        a->sessions[i].touched < a->sessions[k].touched)
      k = i;
  memcpy(a->sessions[k].token, t, 33);
  a->sessions[k].touched = now;
}
unsigned hyp_lock_remaining(hyp_auth *a, uint64_t now) {
  return a->locked_until > now ? (unsigned)(a->locked_until - now) : 0;
}
void hyp_login_result(hyp_auth *a, bool ok, uint64_t now) {
  if (ok)
    a->failures = 0;
  else if (++a->failures >= 5) {
    a->locked_until = now + 60;
    a->failures = 0;
  }
}
int hyp_gate(bool get, bool public_api, bool csrf, bool authenticated) {
  if (!get && !csrf)
    return 403;
  if (!public_api && !authenticated)
    return 401;
  return 0;
}
bool hyp_should_seed(bool exists, bool seeded, const char *value) {
  return !exists && !seeded && value && *value;
}
static void ws(const char **p) {
  while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n')
    ++*p;
}
static bool hex4(const char **p, unsigned *v) {
  *v = 0;
  for (int i = 0; i < 4; i++) {
    unsigned char c = (unsigned char)**p;
    if (!c)
      return false;
    ++*p;
    int h = c >= '0' && c <= '9'   ? c - '0'
            : c >= 'a' && c <= 'f' ? c - 'a' + 10
            : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                   : -1;
    if (h < 0)
      return false;
    *v = *v * 16 + (unsigned)h;
  }
  return true;
}
static bool str(const char **p, char *s, size_t cap) {
  if (*(*p)++ != '"')
    return false;
  size_t n = 0;
  while (**p && **p != '"') {
    unsigned char bytes[4], c = (unsigned char)*(*p)++;
    size_t len = 1;
    bytes[0] = c;
    if (c < 32)
      return false;
    if (c == '\\') {
      c = (unsigned char)*(*p)++;
      if (!c)
        return false;
      if (c == 'u') {
        unsigned v;
        if (!hex4(p, &v) || !v)
          return false;
        if (v >= 0xd800 && v <= 0xdbff) {
          if (**p != '\\')
            return false;
          ++*p;
          if (**p != 'u')
            return false;
          ++*p;
          unsigned lo;
          if (!hex4(p, &lo) || lo < 0xdc00 || lo > 0xdfff)
            return false;
          v = 0x10000 + ((v - 0xd800) << 10) + (lo - 0xdc00);
        } else if (v >= 0xdc00 && v <= 0xdfff)
          return false;
        if (v < 0x80)
          bytes[0] = (unsigned char)v;
        else if (v < 0x800) {
          len = 2;
          bytes[0] = 0xc0 | (v >> 6);
          bytes[1] = 0x80 | (v & 63);
        } else if (v < 0x10000) {
          len = 3;
          bytes[0] = 0xe0 | (v >> 12);
          bytes[1] = 0x80 | ((v >> 6) & 63);
          bytes[2] = 0x80 | (v & 63);
        } else {
          len = 4;
          bytes[0] = 0xf0 | (v >> 18);
          bytes[1] = 0x80 | ((v >> 12) & 63);
          bytes[2] = 0x80 | ((v >> 6) & 63);
          bytes[3] = 0x80 | (v & 63);
        }
      } else {
        switch (c) {
        case '"':
        case '\\':
        case '/':
          bytes[0] = c;
          break;
        case 'b':
          bytes[0] = '\b';
          break;
        case 'f':
          bytes[0] = '\f';
          break;
        case 'n':
          bytes[0] = '\n';
          break;
        case 'r':
          bytes[0] = '\r';
          break;
        case 't':
          bytes[0] = '\t';
          break;
        default:
          return false;
        }
      }
    }
    if (n + len >= cap)
      return false;
    memcpy(s + n, bytes, len);
    n += len;
  }
  if (**p != '"')
    return false;
  ++*p;
  s[n] = 0;
  return true;
}
const hyp_field *hyp_field_get(const hyp_json *j, const char *key) {
  for (unsigned i = 0; i < j->count; i++)
    if (!strcmp(j->fields[i].key, key))
      return &j->fields[i];
  return NULL;
}
bool hyp_json_parse(const char *p, hyp_json *j) {
  memset(j, 0, sizeof(*j));
  if (strlen(p) > 1024)
    return false;
  ws(&p);
  if (*p++ != '{')
    return false;
  ws(&p);
  if (*p != '}')
    for (;;) {
      if (j->count == 8)
        return false;
      hyp_field *f = &j->fields[j->count];
      if (!str(&p, f->key, sizeof(f->key)) || hyp_field_get(j, f->key))
        return false;
      ws(&p);
      if (*p++ != ':')
        return false;
      ws(&p);
      if (*p == '"') {
        f->type = J_STRING;
        if (!str(&p, f->text, sizeof(f->text)))
          return false;
      } else if (!strncmp(p, "true", 4) || !strncmp(p, "false", 5)) {
        f->type = J_BOOL;
        f->boolean = *p == 't';
        p += f->boolean ? 4 : 5;
      } else {
        f->type = J_NUMBER;
        const char *start = p;
        if (*p == '-')
          p++;
        if (!isdigit((unsigned char)*p))
          return false;
        if (*p == '0')
          p++;
        else
          while (isdigit((unsigned char)*p))
            p++;
        if (p - start > 11)
          return false;
        long long v = strtoll(start, NULL, 10);
        if (v < INT_MIN || v > INT_MAX)
          return false;
        f->number = (int)v;
      }
      j->count++;
      ws(&p);
      if (*p != ',')
        break;
      p++;
      ws(&p);
    }
  if (*p++ != '}')
    return false;
  ws(&p);
  return !*p;
}
