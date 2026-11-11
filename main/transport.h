#pragma once
#include <stddef.h>
/* Transport boundary: one ordered line in/out; no protocol or token logic. */
int transport_init(void);
/* 0 no line, 1 complete, -1 overlong/binary line discarded */
int transport_read_line(char *line,size_t cap);
int transport_write_line(const char *line);
void transport_logs_init(void);
