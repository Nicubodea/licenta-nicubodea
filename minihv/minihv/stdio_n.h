#ifndef _STDIO_H
#define _STDIO_H
#include "minihv.h"

#define START_CONSOLE   0x000B8000
#define END_CONSOLE     0x000B8FA0
#define SECOND_ROW      0x000B80A0
#define END_SECOND_ROW  0x000B8F00
void prelog(char* file, int line, char * x, ...);
void printf(PBYTE format, ...);
void sprintf(PBYTE str, const PBYTE format, ...);
void memcpys(void* source, void* destination, unsigned __int64 num);
void write_string_port(char* string);
char* to_string(unsigned __int64 x, char* buffer);
int memcmps(char* source, char* source2);
void printf_f(const PBYTE format, void* argv[]);
int sprintf_f(PBYTE str, const PBYTE format, void* argv[]);
void log_message(char* x);

#define LOG(patt, ...) prelog(__FILE__, __LINE__, patt, __VA_ARGS__);

#endif