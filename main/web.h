#pragma once
#include <stdbool.h>
#include <stdint.h>
void hyp_web_init(void);
bool hyp_admin_set(const char *password);
void hyp_web_publish(bool present, bool ready, bool pin_set, bool rejected,
                     const uint8_t point[65]);
/* USB/token diagnostics shown when the token isn't ready. */
void hyp_web_publish_diag(bool usb_host, int usb_devices, uint16_t vid,
                          uint16_t pid, const char *usb_detail,
                          const char *open_error);
