/**
 * The idea with the logging module is that logging can be easily fine-tuned
 * using the logging.conf file.  This is highly inneficient, but for
 * performance the best is to disable logging altogether anyway and the
 * benefits for debugging and traceability are there.
 */

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "logging.h"
#define LOGGING_CONF_DEFAULT_FILE   "logging.conf"


struct logging_block {
    char file[128];
    char func[128];
    int level;
    struct logging_block *next;
};

static struct logging_block *logging_block_head;
static int logging_default_loglevel = LOG_INFO;
static FILE *logging_fp;
static FILE *config_fp;

static const char *loglevel_str[] = {
    [LOG_EMERG]     = "[emerg]",
    [LOG_ALERT]     = "[alert]",
    [LOG_CRIT]      = "[crit] ",
    [LOG_ERR]       = "[err]  ",
    [LOG_WARNING]   = "[warn] ",
    [LOG_NOTICE]    = "[notic]",
    [LOG_INFO]      = "[info] ",
    [LOG_DEBUG]     = "[debug]",
};


static int get_level_from_str(char *level_str)
{
    for (int i = LOG_EMERG; i <= LOG_DEBUG; i++) {
        if (strncmp(loglevel_str[i]+1, level_str, strlen(level_str)) != 0) continue;
        return i;
    }

    WARNING("Unknown loglevel string: %s", level_str);
    return -1;
}

int logging_initialize(const char *fname, FILE *logfile)
{
    logging_fp = logfile ? logfile : stderr;
    config_fp = fopen(fname ? fname : LOGGING_CONF_DEFAULT_FILE, "r");
    if (!config_fp) {
        INFO("No logging configuration found");
        return 0;
    }

    struct logging_block **lbref = &logging_block_head;
    char level_str[128];

    while (!feof(config_fp)) {
        struct logging_block *block = malloc(sizeof(struct logging_block));
        fscanf(config_fp, "%[^:]:%[^:]:%s\n", block->file, block->func, level_str);
        if (block->file[0] == '#') {
            free(block);
            continue;
        }

        block->level = get_level_from_str(level_str);
        *lbref = block;
        lbref = &(block->next);
    }

    fclose(config_fp);
    return 0;
}

static bool logging_enabled_on(int level, const char *file, const char *func, int line)
{
    struct logging_block *lb;

    for (lb = logging_block_head; lb != NULL; lb = lb->next) {
        if (lb->level < level) continue;
        if (lb->file[0] != '*' && strcmp(lb->file, file) != 0) continue;
        if (lb->func[0] != '*' && strcmp(lb->func, func) != 0) continue;

        return true;
    }

    return false;
}

void __LOG(int level, const char *file, const char *func, int line, char *fmt, ...)
{
    if (level > logging_default_loglevel && !logging_enabled_on(level, file, func, line)) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    fprintf(logging_fp, "%s[%12s] ", loglevel_str[level], file);
    fprintf(logging_fp, "(%24s:%4d) ", func, line);
    vfprintf(logging_fp, fmt, ap);
    va_end(ap);
}
