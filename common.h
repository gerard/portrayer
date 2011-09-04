#ifndef _COMMON_H_
#define _COMMON_H_

#define EXIT_WITH_FAILURE_STR(__str)       do {             \
    char *s = __str ? __str : strerror(errno);              \
    fprintf(stderr, "%s [%s:%d]\n", s, __FILE__, __LINE__); \
    exit(EXIT_FAILURE);                                     \
} while (0)

#define EXIT_WITH_FAILURE       EXIT_WITH_FAILURE_STR(NULL)
#define DEBUG(...)              fprintf(stderr, __VA_ARGS__)

#endif
