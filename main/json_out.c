#define _POSIX_C_SOURCE 200809L
#include "json_out.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
cJSON *cJSON_CreateObject(void) {
  cJSON *j = calloc(1, sizeof(*j));
  return j;
}
void cJSON_Delete(cJSON *j) {
  while (j) {
    cJSON *n = j->next;
    cJSON_Delete(j->child);
    free(j->key);
    free(j->value);
    free(j);
    j = n;
  }
}
void cJSON_AddItemToArray(cJSON *j, cJSON *v) {
  if (!j) {
    cJSON_Delete(v);
    return;
  }
  cJSON **p = &j->child;
  while (*p)
    p = &(*p)->next;
  *p = v;
}
void cJSON_AddItemToObject(cJSON *j, const char *key, cJSON *v) {
  if (v)
    v->key = strdup(key);
  cJSON_AddItemToArray(j, v);
}
cJSON *cJSON_AddObjectToObject(cJSON *j, const char *key) {
  cJSON *v = cJSON_CreateObject();
  cJSON_AddItemToObject(j, key, v);
  return v;
}
cJSON *cJSON_AddArrayToObject(cJSON *j, const char *key) {
  cJSON *v = cJSON_AddObjectToObject(j, key);
  if (v)
    v->type = 1;
  return v;
}
void cJSON_AddStringToObject(cJSON *j, const char *key, const char *s) {
  cJSON *v = cJSON_CreateObject();
  if (v) {
    v->type = 2;
    v->value = strdup(s);
  }
  cJSON_AddItemToObject(j, key, v);
}
static void literal(cJSON *j, const char *key, const char *s) {
  cJSON *v = cJSON_CreateObject();
  if (v) {
    v->type = 3;
    v->value = strdup(s);
  }
  cJSON_AddItemToObject(j, key, v);
}
void cJSON_AddNumberToObject(cJSON *j, const char *key, double n) {
  char s[32];
  snprintf(s, sizeof(s), "%.0f", n);
  literal(j, key, s);
}
void cJSON_AddBoolToObject(cJSON *j, const char *key, bool b) {
  literal(j, key, b ? "true" : "false");
}
void cJSON_AddNullToObject(cJSON *j, const char *key) {
  literal(j, key, "null");
}
typedef struct {
  char *s;
  size_t n, cap;
  bool failed;
} output;
static void put(output *o, const char *s) {
  size_t n = strlen(s);
  if (o->failed)
    return;
  if (o->n + n + 1 > o->cap) {
    size_t cap = (o->n + n + 1) * 2;
    char *p = realloc(o->s, cap);
    if (!p) {
      o->failed = true;
      return;
    }
    o->s = p;
    o->cap = cap;
  }
  memcpy(o->s + o->n, s, n + 1);
  o->n += n;
}
static void quoted(output *o, const char *s) {
  put(o, "\"");
  for (; *s; s++) {
    char b[8];
    unsigned char c = *s;
    if (c == '"' || c == '\\') {
      b[0] = '\\';
      b[1] = c;
      b[2] = 0;
    } else if (c < 32)
      snprintf(b, sizeof(b), "\\u%04x", c);
    else {
      b[0] = c;
      b[1] = 0;
    }
    put(o, b);
  }
  put(o, "\"");
}
static void render(output *o, cJSON *j) {
  if (!j) {
    put(o, "null");
    return;
  }
  if (j->type == 2) {
    quoted(o, j->value ? j->value : "");
    return;
  }
  if (j->type == 3) {
    put(o, j->value ? j->value : "null");
    return;
  }
  put(o, j->type == 1 ? "[" : "{");
  for (cJSON *v = j->child; v; v = v->next) {
    if (v != j->child)
      put(o, ",");
    if (j->type == 0) {
      quoted(o, v->key ? v->key : "");
      put(o, ":");
    }
    render(o, v);
  }
  put(o, j->type == 1 ? "]" : "}");
}
char *cJSON_PrintUnformatted(cJSON *j) {
  output o = {0};
  render(&o, j);
  if (o.failed) {
    free(o.s);
    return NULL;
  }
  return o.s;
}
