#pragma once
#include <stdbool.h>
#include <stdint.h>
void hyp_web_init(void);
bool hyp_admin_set(const char *password);
void hyp_web_publish(bool present, bool ready, bool pin_set, bool rejected,
                     const uint8_t point[65]);
