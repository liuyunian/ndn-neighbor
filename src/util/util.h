#ifndef UTIL_H_
#define UTIL_H_

#include <string>

/**
 * 字符串
 * stringFunc.cpp
*/
void Rtrim(char *string);
void Ltrim(char *string);

/**
 * 日志
*/
#include <stdarg.h> // va_list va_start va_end

void log_set_level(int level);
void log_err(int err_level, const char * fmt, ...);
void log_fatal(int fat_level, const char * fmt, ...);
void log_warn(const char * fmt, ...);
void log_info(const char * fmt, ...);
void log_debug(const char * fmt, ...);

static void 
err_doit(int log_level, int errno_flag, const char * fmt, va_list ap);
static void 
info_doit(int log_level, const char * fmt, va_list ap);

/**
 * 网络
*/
void getMacAddress(std::string interface, uint8_t * macAddr);

#endif