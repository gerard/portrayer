#ifndef _LOGGING_H_
#define _LOGGING_H_

#define LOG_EMERG   0
#define LOG_ALERT   1
#define LOG_CRIT    2
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
#define LOG_INFO    6
#define LOG_DEBUG   7

#define __EMERG(fmt, ...)   __LOG(LOG_EMERG,   __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);
#define __ALERT(fmt, ...)   __LOG(LOG_ALERT,   __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);
#define __CRIT(fmt, ...)    __LOG(LOG_CRIT,    __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);
#define __ERR(fmt, ...)     __LOG(LOG_ERR,     __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);
#define __WARNING(fmt, ...) __LOG(LOG_WARNING, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);
#define __NOTICE(fmt, ...)  __LOG(LOG_NOTICE,  __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);
#define __INFO(fmt, ...)    __LOG(LOG_INFO,    __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);
#define __DEBUG(fmt, ...)   __LOG(LOG_DEBUG,   __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);

#define EMERG(fmt, ...)     __EMERG(fmt "\n", ##__VA_ARGS__)
#define ALERT(fmt, ...)     __ALERT(fmt "\n", ##__VA_ARGS__)
#define CRIT(fmt, ...)      __CRIT(fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...)       __ERR(fmt "\n", ##__VA_ARGS__)
#define WARNING(fmt, ...)   __WARNING(fmt "\n", ##__VA_ARGS__)
#define NOTICE(fmt, ...)    __NOTICE(fmt "\n", ##__VA_ARGS__)
#define INFO(fmt, ...)      __INFO(fmt "\n", ##__VA_ARGS__)
#define DEBUG(fmt, ...)     __DEBUG(fmt "\n", ##__VA_ARGS__)

void __LOG(int level, const char *file, const char *func, int linechar, char *fmt, ...);
int logging_initialize(const char *fname, FILE *logging_fp);

#endif
