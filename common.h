#ifndef _COMMON_H_
#define _COMMON_H_

#define EXIT_WITH_FAILURE_STR(__str)       do {             \
    ERR("%s", __str ? __str : strerror(errno));             \
    exit(EXIT_FAILURE);                                     \
} while (0)

#define EXIT_WITH_FAILURE       EXIT_WITH_FAILURE_STR(NULL)

#endif
