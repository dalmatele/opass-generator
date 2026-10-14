/*
 * omen_level_check.c
 *
 * Safe utility for inspecting pcfg-go-style level files.
 * It validates config.txt and reports line counts / malformed records.
 * It does NOT generate password candidates or invoke Hashcat.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -std=c11 -o omen-level-check omen_level_check.c
 *
 * Run:
 *   ./omen-level-check --ip IP.level --cp CP.level --config config.txt
 */

#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_CAP 65536

typedef struct {
    unsigned long lines;
    unsigned long blank_lines;
    unsigned long valid_records;
    unsigned long malformed_records;
    size_t max_value_len;
} Stats;

static char *trim(char *s) {
    char *end;
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* A record is either a bare token (e.g. GHT), or an integer followed by a token. */
static int valid_level_record(char *line, size_t *value_len) {
    char *p = trim(line);
    char *q;
    char *endptr;
    long ignored_weight;

    if (*p == '\0' || *p == '#') return 0;

    errno = 0;
    ignored_weight = strtol(p, &endptr, 10);
    (void)ignored_weight;

    if (endptr != p && errno != ERANGE && isspace((unsigned char)*endptr)) {
        p = endptr;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') return -1;
    }

    q = p;
    while (*q && !isspace((unsigned char)*q)) q++;
    if (q == p) return -1;
    *value_len = (size_t)(q - p);

    while (*q && isspace((unsigned char)*q)) q++;
    return (*q == '\0') ? 1 : -1;
}

static int inspect_level(const char *path, const char *label, Stats *st) {
    FILE *fp = fopen(path, "r");
    char line[LINE_CAP];

    if (!fp) {
        fprintf(stderr, "ERROR: cannot open %s '%s': %s\n",
                label, path, strerror(errno));
        return 0;
    }

    memset(st, 0, sizeof(*st));
    while (fgets(line, sizeof(line), fp)) {
        size_t len = 0;
        int rc;
        st->lines++;

        if (!strchr(line, '\n') && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {}
            st->malformed_records++;
            fprintf(stderr, "WARN: %s:%lu: line exceeds %d bytes\n",
                    path, st->lines, LINE_CAP - 1);
            continue;
        }

        char copy[LINE_CAP];
        memcpy(copy, line, strlen(line) + 1);
        char *p = trim(copy);
        if (*p == '\0') {
            st->blank_lines++;
            continue;
        }
        if (*p == '#') continue;

        rc = valid_level_record(copy, &len);
        if (rc == 1) {
            st->valid_records++;
            if (len > st->max_value_len) st->max_value_len = len;
        } else {
            st->malformed_records++;
            fprintf(stderr, "WARN: %s:%lu: unexpected record format\n",
                    path, st->lines);
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "ERROR: read failure in '%s'\n", path);
        fclose(fp);
        return 0;
    }
    fclose(fp);

    printf("%s: %s\n", label, path);
    printf("  lines:              %lu\n", st->lines);
    printf("  valid records:      %lu\n", st->valid_records);
    printf("  blank lines:        %lu\n", st->blank_lines);
    printf("  malformed records:  %lu\n", st->malformed_records);
    printf("  longest token:      %zu bytes\n", st->max_value_len);
    return st->malformed_records == 0;
}

static int inspect_config(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[LINE_CAP];
    int ngram = -1;
    int saw_utf8 = 0;

    if (!fp) {
        fprintf(stderr, "ERROR: cannot open config '%s': %s\n",
                path, strerror(errno));
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';' ||
            *p == '[') continue;

        if (strncmp(p, "ngram", 5) == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                char *v = trim(eq + 1);
                char *endptr;
                long n = strtol(v, &endptr, 10);
                while (*endptr && isspace((unsigned char)*endptr)) endptr++;
                if (endptr != v && *endptr == '\0' && n > 0 && n <= 64)
                    ngram = (int)n;
            }
        } else if (strncmp(p, "encoding", 8) == 0) {
            char *eq = strchr(p, '=');
            if (eq && strcmp(trim(eq + 1), "utf-8") == 0)
                saw_utf8 = 1;
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "ERROR: read failure in config '%s'\n", path);
        fclose(fp);
        return 0;
    }
    fclose(fp);

    printf("config: %s\n", path);
    printf("  ngram:              ");
    if (ngram > 0) printf("%d\n", ngram);
    else printf("missing or invalid\n");
    printf("  encoding utf-8:     %s\n", saw_utf8 ? "yes" : "not confirmed");

    return ngram > 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --ip IP.level --cp CP.level --config config.txt\n", prog);
}

int main(int argc, char **argv) {
    const char *ip_path = NULL, *cp_path = NULL, *config_path = NULL;
    Stats ip_stats, cp_stats;
    int i, ok = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc)
            ip_path = argv[++i];
        else if (strcmp(argv[i], "--cp") == 0 && i + 1 < argc)
            cp_path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            config_path = argv[++i];
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!ip_path || !cp_path || !config_path) {
        usage(argv[0]);
        return 2;
    }

    if (!inspect_config(config_path)) ok = 0;
    if (!inspect_level(ip_path, "IP.level", &ip_stats)) ok = 0;
    if (!inspect_level(cp_path, "CP.level", &cp_stats)) ok = 0;

    if (ok)
        puts("Validation: OK");
    else
        puts("Validation: completed with errors or warnings");

    return ok ? 0 : 1;
}
