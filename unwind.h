#ifndef _UNWIND_H_
#define _UNWIND_H_

#include <stdint.h>
#include <sys/types.h>

int unwind_prepare(char *file);
int32_t unwind_find_caller_offset(pid_t pid, const void const *rip);

#endif
