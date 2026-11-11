#pragma once
#include <stdbool.h>
typedef struct json_node {
  char *key, *value;
  int type;
  struct json_node *child, *next;
} cJSON;
cJSON *cJSON_CreateObject(void);
void cJSON_Delete(cJSON *j);
cJSON *cJSON_AddObjectToObject(cJSON *j, const char *key);
cJSON *cJSON_AddArrayToObject(cJSON *j, const char *key);
void cJSON_AddItemToObject(cJSON *j, const char *key, cJSON *v);
void cJSON_AddItemToArray(cJSON *j, cJSON *v);
void cJSON_AddStringToObject(cJSON *j, const char *key, const char *s);
void cJSON_AddNumberToObject(cJSON *j, const char *key, double n);
void cJSON_AddBoolToObject(cJSON *j, const char *key, bool b);
void cJSON_AddNullToObject(cJSON *j, const char *key);
char *cJSON_PrintUnformatted(cJSON *j);
