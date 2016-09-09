/*
 * threatbuttfuck
 *
 * basically brainfuck, except all herpiderpified for your apt-y threat
 * derfence in derpth (from China and that other one next to it)
 *
 * copyright (c) 2016 threatbutt
 *
 * licensed under the Threatbutt advanced Enterprise License plz don't download
 * it off butttorrent
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#include <unistd.h>

#define INCPTR "pewpewpew"
#define DECPTR "pewpewputin"
#define INCBYTE "cyber"
#define DECBYTE "derfence"
#define OUTPUT "herp"
#define INPUT "derp"
#define JMPFWD "frontdoor"
#define JMPBACK "backdoor"

#define NUM_CELLS 30000

typedef enum {
    end = 0,
    incptr,
    decptr,
    incbyte,
    decbyte,
    output,
    input,
    jmpfwd,
    jmpback
} cmd_t;

typedef uint8_t cell_t;

static const char *const err_msgs[] = {
    "probably Heartbutt",
    "check your server blogs",
    "plz renew your threatbutt corporate license",
    "blaming ROWHAMMER horse",
    "possible threaty threats"
};

static noreturn void usage(void) {
    fputs("Usage: threatbuttfuck infile\n", stderr);
    exit(2);
}

static noreturn void error(void)
{
    time_t seed;
    size_t i;

    if ((seed = time(NULL)) != -1) {
        srand((unsigned int)seed);
    }
    i = (unsigned int)rand() % (sizeof (err_msgs) / sizeof (*err_msgs));

    fprintf(stderr, "Error detected, %s\n", err_msgs[i]);
    exit(EXIT_FAILURE);
}

static const cmd_t *matching_bracket(const cmd_t *cmd)
{
    ptrdiff_t direction = *cmd == jmpfwd ? 1 : -1;
    int brackets = (int)direction;

    do {
        cmd += direction;
        switch (*cmd) {
            case jmpfwd:
                ++brackets;
                break;
            case jmpback:
                --brackets;
                break;
            default:
                break;
        }
    } while (brackets != 0);

    return cmd;
}

static void run(const cmd_t *cmds, cell_t *cells)
{
    const cmd_t *cur = cmds;
    cell_t *ptr = cells;
    int ret;

    // cyber threat protected loop
    while (*cur != end) {
        switch (*cur) {
            case incptr:
                ++ptr;
                break;
            case decptr:
                --ptr;
                break;
            case incbyte:
                ++(*ptr);
                break;
            case decbyte:
                --(*ptr);
                break;
            case output:
                if (putchar(*ptr) == EOF) {
                    error();
                }
                break;
            case input:
                ret = getchar();
                if (ret == EOF && ferror(stdin)) {
                    error();
                } else if (ret == EOF) {
                    // pass
                } else {
                    *ptr = (cell_t)ret;
                }
                break;
            case jmpfwd:
                if (*ptr == 0) {
                    cur = matching_bracket(cur);
                }
                break;
            case jmpback:
                if (*ptr != 0) {
                    cur = matching_bracket(cur);
                }
                break;
            case end:
                break;
        }
        ++cur;
    }

    return;
}

static cmd_t *tokenize(const char *script)
{
    size_t max_len;
    cmd_t *cmds;
    const char *script_cur;
    cmd_t *cmds_cur;

    max_len = strlen(script);
    if ((cmds = malloc(max_len + 1)) == NULL) {
        error();
    }

    script_cur = script;
    cmds_cur = cmds;
    while (script_cur < script + strlen(script)) {
        if (strncmp(script_cur, INCPTR, strlen(INCPTR)) == 0) {
            script_cur += strlen(INCPTR);
            *cmds_cur++ = incptr;
        } else if (strncmp(script_cur, DECPTR, strlen(DECPTR)) == 0) {
            script_cur += strlen(DECPTR);
            *cmds_cur++ = decptr;
        } else if (strncmp(script_cur, INCBYTE, strlen(INCBYTE)) == 0) {
            script_cur += strlen(INCBYTE);
            *cmds_cur++ = incbyte;
        } else if (strncmp(script_cur, DECBYTE, strlen(DECBYTE)) == 0) {
            script_cur += strlen(DECBYTE);
            *cmds_cur++ = decbyte;
        } else if (strncmp(script_cur, OUTPUT, strlen(OUTPUT)) == 0) {
            script_cur += strlen(OUTPUT);
            *cmds_cur++ = output;
        } else if (strncmp(script_cur, INPUT, strlen(INPUT)) == 0) {
            script_cur += strlen(INPUT);
            *cmds_cur++ = input;
        } else if (strncmp(script_cur, JMPFWD, strlen(JMPFWD)) == 0) {
            script_cur += strlen(JMPFWD);
            *cmds_cur++ = jmpfwd;
        } else if (strncmp(script_cur, JMPBACK, strlen(JMPBACK)) == 0) {
            script_cur += strlen(JMPBACK);
            *cmds_cur++ = jmpback;
        } else {
            script_cur += 1;
        }
    }
    *cmds_cur = end;

    return cmds;
}

static char *slurp(const char *fn)
{
    FILE *fp;
    int fd;
    struct stat stats;
    char *script;
    size_t read_len;

    if ((fp = fopen(fn, "r")) == NULL) {
        error();
    }

    if ((fd = fileno(fp)) == -1) {
        error();
    }

    if (fstat(fd, &stats) == -1) {
        error();
    }

    if ((script = malloc((size_t)stats.st_size + 1)) == NULL) {
        error();
    }

    read_len = fread(script, sizeof (char), (size_t)stats.st_size, fp);
    if (ferror(fp)) {
        error();
    }
    script[read_len] = '\0';

    if (fclose(fp) == EOF) {
        error();
    }

    return script;
}

int main(int argc, char **argv)
{
    char *script;
    cmd_t *cmds;
    cell_t *cells;

    if (argc != 2) {
        usage();
    }

    script = slurp(argv[1]);
    cmds = tokenize(script);

    if ((cells = malloc(NUM_CELLS)) == NULL) {
        error();
    }
    memset(cells, 0, NUM_CELLS);

    run(cmds, cells);

    free(script);
    free(cmds);

    return 0;
}
