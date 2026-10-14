/*
 * Streaming generator for pcfg-go OMEN IP.level / CP.level models.
 *
 * Build:
 *   cc -O3 -Wall -Wextra -Wpedantic -std=c11 -o omen-generator omen_generator.c
 *
 * Examples:
 *   ./omen-generator --ip data/IP.level --cp data/CP.level \
 *       --config data/config.txt --min-len 8 --max-len 12
 *   ./omen-generator --ip data/IP.level --cp data/CP.level \
 *       --config data/config.txt --max-len 12 |
 *       hashcat -m 0 hashes.txt --stdin
 *
 * Candidates go to stdout. Diagnostics and progress go to stderr.
 */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_NGRAM 64
#define DEFAULT_SESSION "omen.session"
#define CHECKPOINT_SECONDS 5
#define OUTPUT_BUFFER_SIZE (1024U * 1024U)

typedef struct {
    char *data;
    size_t size;
    uint64_t hash;
} FileData;

typedef struct {
    uint32_t offset;
    uint32_t line;
    uint8_t level;
} IpEntry;

typedef struct {
    uint32_t offset;
    uint16_t prefix_bytes;
    uint8_t level;
} CpEntry;

typedef struct {
    FileData file;
    IpEntry *entries;
    size_t count;
    size_t capacity;
    size_t min_level;
    size_t max_level;
} IpModel;

typedef struct {
    FileData file;
    CpEntry *entries;
    size_t count;
    size_t capacity;
    size_t min_level;
    size_t max_level;
} CpModel;

typedef struct {
    const char *path;
    int enabled;
    int resume;
    int complete;
    size_t min_len;
    size_t max_len;
    size_t current_len;
    size_t current_level;
    uint32_t current_line;
    size_t start_len;
    size_t start_level;
    uint32_t start_line;
    uint64_t ip_hash;
    uint64_t cp_hash;
    uint64_t config_hash;
    time_t last_save;
    uint64_t candidates;
} Session;

static volatile sig_atomic_t interrupted = 0;
static const FileData *sort_cp_file;

static void handle_signal(int signal_number) {
    (void)signal_number;
    interrupted = 1;
}

static uint64_t hash_bytes(const unsigned char *data, size_t size) {
    uint64_t hash = UINT64_C(14695981039346656037);
    size_t i;
    for (i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int read_file(const char *path, FileData *file) {
    FILE *fp = fopen(path, "rb");
    long file_size;
    size_t read_size;

    if (!fp) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return 0;
    }
    if (fseek(fp, 0, SEEK_END) != 0 || (file_size = ftell(fp)) < 0 ||
        fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "ERROR: cannot determine size of '%s'\n", path);
        fclose(fp);
        return 0;
    }
    if ((uintmax_t)file_size > UINT32_MAX) {
        fprintf(stderr, "ERROR: '%s' is larger than the supported 4 GiB limit\n",
                path);
        fclose(fp);
        return 0;
    }

    file->size = (size_t)file_size;
    file->data = malloc(file->size + 1);
    if (!file->data) {
        fprintf(stderr, "ERROR: out of memory reading '%s'\n", path);
        fclose(fp);
        return 0;
    }
    read_size = fread(file->data, 1, file->size, fp);
    if (read_size != file->size || ferror(fp)) {
        fprintf(stderr, "ERROR: failed reading '%s'\n", path);
        free(file->data);
        file->data = NULL;
        fclose(fp);
        return 0;
    }
    file->data[file->size] = '\0';
    file->hash = hash_bytes((const unsigned char *)file->data, file->size);
    fclose(fp);
    return 1;
}

static int utf8_char_size(const unsigned char *s, size_t remaining,
                          size_t *char_size) {
    unsigned char a;
    if (remaining == 0) return 0;
    a = s[0];
    if (a <= 0x7f) {
        *char_size = 1;
        return 1;
    }
    if (a >= 0xc2 && a <= 0xdf) {
        if (remaining < 2 || (s[1] & 0xc0) != 0x80) return 0;
        *char_size = 2;
        return 1;
    }
    if (a >= 0xe0 && a <= 0xef) {
        if (remaining < 3 || (s[1] & 0xc0) != 0x80 ||
            (s[2] & 0xc0) != 0x80) return 0;
        if ((a == 0xe0 && s[1] < 0xa0) ||
            (a == 0xed && s[1] >= 0xa0)) return 0;
        *char_size = 3;
        return 1;
    }
    if (a >= 0xf0 && a <= 0xf4) {
        if (remaining < 4 || (s[1] & 0xc0) != 0x80 ||
            (s[2] & 0xc0) != 0x80 || (s[3] & 0xc0) != 0x80)
            return 0;
        if ((a == 0xf0 && s[1] < 0x90) ||
            (a == 0xf4 && s[1] >= 0x90)) return 0;
        *char_size = 4;
        return 1;
    }
    return 0;
}

static int utf8_count(const char *s, size_t bytes, size_t *count) {
    size_t offset = 0;
    size_t chars = 0;
    while (offset < bytes) {
        size_t char_size;
        if (!utf8_char_size((const unsigned char *)s + offset,
                            bytes - offset, &char_size))
            return 0;
        offset += char_size;
        chars++;
    }
    *count = chars;
    return 1;
}

static int utf8_prefix_size(const char *s, size_t bytes, size_t chars,
                            size_t *prefix_size) {
    size_t offset = 0;
    size_t count;
    for (count = 0; count < chars; count++) {
        size_t char_size;
        if (offset >= bytes ||
            !utf8_char_size((const unsigned char *)s + offset,
                            bytes - offset, &char_size))
            return 0;
        offset += char_size;
    }
    *prefix_size = offset;
    return 1;
}

static char *trim_ascii(char *s) {
    char *end;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

static int parse_config(const char *path, int *ngram, FileData *file) {
    char *cursor;
    int found = 0;

    if (!read_file(path, file)) return 0;
    cursor = file->data;
    while (cursor < file->data + file->size) {
        char *end = memchr(cursor, '\n',
                           (size_t)(file->data + file->size - cursor));
        char saved;
        char *line;
        char *equal;
        if (!end) end = file->data + file->size;
        saved = *end;
        *end = '\0';
        line = trim_ascii(cursor);
        if (*line && *line != '#' && *line != ';' && *line != '[') {
            equal = strchr(line, '=');
            if (equal) {
                char *key_end = equal;
                char *value;
                while (key_end > line &&
                       (key_end[-1] == ' ' || key_end[-1] == '\t'))
                    *--key_end = '\0';
                value = trim_ascii(equal + 1);
                if (strcmp(line, "ngram") == 0) {
                    char *number_end;
                    long value_num;
                    errno = 0;
                    value_num = strtol(value, &number_end, 10);
                    while (*number_end == ' ' || *number_end == '\t')
                        number_end++;
                    if (errno == 0 && number_end != value &&
                        *number_end == '\0' && value_num >= 2 &&
                        value_num <= MAX_NGRAM) {
                        *ngram = (int)value_num;
                        found = 1;
                    } else {
                        fprintf(stderr, "ERROR: invalid ngram in '%s'\n", path);
                        *end = saved;
                        return 0;
                    }
                } else if (strcmp(line, "encoding") == 0 &&
                           strcmp(value, "utf-8") != 0 &&
                           strcmp(value, "UTF-8") != 0) {
                    fprintf(stderr,
                            "ERROR: only UTF-8 models are supported; found '%s'\n",
                            value);
                    *end = saved;
                    return 0;
                }
            }
        }
        *end = saved;
        cursor = end + (saved == '\n' ? 1 : 0);
    }
    if (!found) {
        fprintf(stderr, "ERROR: ngram is missing from '%s'\n", path);
        return 0;
    }
    return 1;
}

static int parse_level_line(char *line, size_t line_len, int *level,
                            char **token, size_t *token_len) {
    char *tab = memchr(line, '\t', line_len);
    char *number_end;
    long parsed;
    size_t start = 0;
    size_t end = line_len;

    if (!tab) return 0;
    errno = 0;
    parsed = strtol(line, &number_end, 10);
    if (errno != 0 || number_end != tab || parsed < 0 || parsed > 255)
        return 0;
    start = (size_t)(tab - line) + 1;
    if (end > start && line[end - 1] == '\r') end--;
    if (end == start) return 0;
    line[end] = '\0';
    *level = (int)parsed;
    *token = line + start;
    *token_len = end - start;
    return 1;
}

static int append_ip(IpModel *model, uint32_t offset, uint32_t line,
                     uint8_t level) {
    IpEntry *new_entries;
    size_t new_capacity;
    if (model->count == model->capacity) {
        new_capacity = model->capacity ? model->capacity * 2 : 1024;
        if (new_capacity < model->capacity ||
            new_capacity > SIZE_MAX / sizeof(*model->entries))
            return 0;
        new_entries = realloc(model->entries,
                              new_capacity * sizeof(*model->entries));
        if (!new_entries) return 0;
        model->entries = new_entries;
        model->capacity = new_capacity;
    }
    model->entries[model->count].offset = offset;
    model->entries[model->count].line = line;
    model->entries[model->count].level = level;
    if (model->count == 0 || level < model->min_level)
        model->min_level = level;
    model->count++;
    if (level > model->max_level) model->max_level = level;
    return 1;
}

static int append_cp(CpModel *model, uint32_t offset, uint16_t prefix_bytes,
                     uint8_t level) {
    CpEntry *new_entries;
    size_t new_capacity;
    if (model->count == model->capacity) {
        new_capacity = model->capacity ? model->capacity * 2 : 1024;
        if (new_capacity < model->capacity ||
            new_capacity > SIZE_MAX / sizeof(*model->entries))
            return 0;
        new_entries = realloc(model->entries,
                              new_capacity * sizeof(*model->entries));
        if (!new_entries) return 0;
        model->entries = new_entries;
        model->capacity = new_capacity;
    }
    model->entries[model->count].offset = offset;
    model->entries[model->count].prefix_bytes = prefix_bytes;
    model->entries[model->count].level = level;
    if (model->count == 0 || level < model->min_level)
        model->min_level = level;
    model->count++;
    if (level > model->max_level) model->max_level = level;
    return 1;
}

static int load_ip_model(const char *path, size_t prefix_chars,
                         IpModel *model) {
    size_t offset = 0;
    uint32_t line_no = 0;
    memset(model, 0, sizeof(*model));
    if (!read_file(path, &model->file)) return 0;

    while (offset < model->file.size) {
        size_t line_start = offset;
        size_t line_len;
        char *line;
        int level;
        char *token;
        size_t token_len;
        size_t chars;
        while (offset < model->file.size && model->file.data[offset] != '\n')
            offset++;
        line_len = offset - line_start;
        if (offset < model->file.size) model->file.data[offset++] = '\0';
        line_no++;
        if (line_no > UINT32_MAX) {
            fprintf(stderr, "ERROR: too many lines in '%s'\n", path);
            return 0;
        }
        if (line_len && model->file.data[line_start + line_len - 1] == '\r')
            line_len--;
        line = model->file.data + line_start;
        if (line_len == 0 || line[0] == '#') continue;
        if (!parse_level_line(line, line_len, &level, &token, &token_len) ||
            !utf8_count(token, token_len, &chars) || chars != prefix_chars) {
            fprintf(stderr, "ERROR: invalid IP record at %s:%" PRIu32
                            " (expected %zu UTF-8 characters)\n",
                    path, line_no, prefix_chars);
            return 0;
        }
        if (!append_ip(model, (uint32_t)(token - model->file.data), line_no,
                       (uint8_t)level)) {
            fprintf(stderr, "ERROR: out of memory loading '%s'\n", path);
            return 0;
        }
    }
    if (model->count == 0) {
        fprintf(stderr, "ERROR: no IP records found in '%s'\n", path);
        return 0;
    }
    return 1;
}

static int load_cp_model(const char *path, size_t ngram, CpModel *model) {
    size_t offset = 0;
    uint32_t line_no = 0;
    memset(model, 0, sizeof(*model));
    if (!read_file(path, &model->file)) return 0;

    while (offset < model->file.size) {
        size_t line_start = offset;
        size_t line_len;
        char *line;
        int level;
        char *token;
        size_t token_len;
        size_t chars;
        size_t prefix_bytes;
        while (offset < model->file.size && model->file.data[offset] != '\n')
            offset++;
        line_len = offset - line_start;
        if (offset < model->file.size) model->file.data[offset++] = '\0';
        line_no++;
        if (line_len && model->file.data[line_start + line_len - 1] == '\r')
            line_len--;
        line = model->file.data + line_start;
        if (line_len == 0 || line[0] == '#') continue;
        if (!parse_level_line(line, line_len, &level, &token, &token_len) ||
            !utf8_count(token, token_len, &chars) || chars != ngram ||
            !utf8_prefix_size(token, token_len, ngram - 1, &prefix_bytes) ||
            prefix_bytes > UINT16_MAX) {
            fprintf(stderr, "ERROR: invalid CP record at %s:%" PRIu32
                            " (expected %zu UTF-8 characters)\n",
                    path, line_no, ngram);
            return 0;
        }
        if (!append_cp(model, (uint32_t)(token - model->file.data),
                       (uint16_t)prefix_bytes, (uint8_t)level)) {
            fprintf(stderr, "ERROR: out of memory loading '%s'\n", path);
            return 0;
        }
    }
    if (model->count == 0) {
        fprintf(stderr, "ERROR: no CP records found in '%s'\n", path);
        return 0;
    }
    return 1;
}

static int compare_cp(const void *left_ptr, const void *right_ptr) {
    const CpEntry *left = left_ptr;
    const CpEntry *right = right_ptr;
    const char *left_token = sort_cp_file->data + left->offset;
    const char *right_token = sort_cp_file->data + right->offset;
    size_t left_len = strlen(left_token);
    size_t right_len = strlen(right_token);
    size_t left_suffix = left_len - left->prefix_bytes;
    size_t right_suffix = right_len - right->prefix_bytes;
    size_t common_suffix;
    size_t common = left->prefix_bytes < right->prefix_bytes
                        ? left->prefix_bytes : right->prefix_bytes;
    int cmp = memcmp(left_token, right_token, common);
    if (cmp != 0) return cmp;
    if (left->prefix_bytes != right->prefix_bytes)
        return left->prefix_bytes < right->prefix_bytes ? -1 : 1;
    if (left->level != right->level)
        return left->level < right->level ? -1 : 1;
    common_suffix = left_suffix < right_suffix ? left_suffix : right_suffix;
    cmp = memcmp(left_token + left->prefix_bytes,
                 right_token + right->prefix_bytes, common_suffix);
    if (cmp != 0) return cmp;
    if (left_suffix != right_suffix)
        return left_suffix < right_suffix ? -1 : 1;
    return 0;
}

static int compare_prefix(const CpEntry *entry, const char *prefix,
                          size_t prefix_bytes, const CpModel *model) {
    const char *token = model->file.data + entry->offset;
    size_t common = entry->prefix_bytes < prefix_bytes
                        ? entry->prefix_bytes : prefix_bytes;
    int cmp = memcmp(token, prefix, common);
    if (cmp != 0) return cmp;
    if (entry->prefix_bytes == prefix_bytes) return 0;
    return entry->prefix_bytes < prefix_bytes ? -1 : 1;
}

static void find_cp_range(const CpModel *model, const char *prefix,
                          size_t prefix_bytes, size_t *first, size_t *last) {
    size_t low = 0;
    size_t high = model->count;
    size_t mid;
    while (low < high) {
        mid = low + (high - low) / 2;
        if (compare_prefix(&model->entries[mid], prefix, prefix_bytes,
                           model) < 0)
            low = mid + 1;
        else
            high = mid;
    }
    *first = low;
    high = model->count;
    while (low < high) {
        mid = low + (high - low) / 2;
        if (compare_prefix(&model->entries[mid], prefix, prefix_bytes,
                           model) <= 0)
            low = mid + 1;
        else
            high = mid;
    }
    *last = low;
}

static int level_bounds(const IpModel *ip, const CpModel *cp,
                        size_t target_len, size_t root_len,
                        size_t *minimum, size_t *maximum) {
    size_t transitions = target_len - root_len;
    if ((cp->min_level &&
         transitions > (SIZE_MAX - ip->min_level) / cp->min_level) ||
        (cp->max_level &&
         transitions > (SIZE_MAX - ip->max_level) / cp->max_level))
        return 0;
    *minimum = ip->min_level + transitions * cp->min_level;
    *maximum = ip->max_level + transitions * cp->max_level;
    return 1;
}

static int score_is_reachable(size_t score, size_t accumulated,
                              size_t remaining_steps, size_t min_level,
                              size_t max_level) {
    size_t remaining_score;
    size_t min_remaining;
    size_t max_remaining;
    if (score < accumulated) return 0;
    remaining_score = score - accumulated;
    if (min_level && remaining_steps > SIZE_MAX / min_level)
        return 0;
    min_remaining = remaining_steps * min_level;
    max_remaining = max_level &&
                    remaining_steps > SIZE_MAX / max_level
                        ? SIZE_MAX : remaining_steps * max_level;
    return remaining_score >= min_remaining &&
           remaining_score <= max_remaining;
}

static int parse_size(const char *text, size_t *value) {
    char *end;
    uintmax_t parsed;
    errno = 0;
    parsed = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        parsed > SIZE_MAX || parsed == 0)
        return 0;
    *value = (size_t)parsed;
    return 1;
}

static int read_session(Session *session, size_t ngram_min_len) {
    FILE *fp = fopen(session->path, "r");
    char line[256];
    unsigned int version;
    unsigned long long ip_hash = 0, cp_hash = 0, config_hash = 0;
    unsigned long long min_len = 0, max_len = 0, current_len = 0;
    unsigned long long current_level = 0, current_line = 0;
    unsigned int complete = 0;
    unsigned int fields = 0;

    if (!fp) {
        fprintf(stderr, "ERROR: cannot open session '%s': %s\n",
                session->path, strerror(errno));
        return 0;
    }
    if (!fgets(line, sizeof(line), fp) ||
        sscanf(line, "OMEN_SESSION_%u", &version) != 1 || version != 2) {
        fprintf(stderr, "ERROR: unsupported session file '%s'\n",
                session->path);
        fclose(fp);
        return 0;
    }
    while (fgets(line, sizeof(line), fp)) {
        char key[64];
        char value[128];
        if (sscanf(line, "%63[^=]=%127s", key, value) != 2) continue;
        if (strcmp(key, "ip_hash") == 0)
            fields |= sscanf(value, "%llx", &ip_hash) == 1 ? 1U << 0 : 0;
        else if (strcmp(key, "cp_hash") == 0)
            fields |= sscanf(value, "%llx", &cp_hash) == 1 ? 1U << 1 : 0;
        else if (strcmp(key, "config_hash") == 0)
            fields |= sscanf(value, "%llx", &config_hash) == 1 ? 1U << 2 : 0;
        else if (strcmp(key, "min_len") == 0)
            fields |= sscanf(value, "%llu", &min_len) == 1 ? 1U << 3 : 0;
        else if (strcmp(key, "max_len") == 0)
            fields |= sscanf(value, "%llu", &max_len) == 1 ? 1U << 4 : 0;
        else if (strcmp(key, "length") == 0)
            fields |= sscanf(value, "%llu", &current_len) == 1 ? 1U << 5 : 0;
        else if (strcmp(key, "level") == 0)
            fields |= sscanf(value, "%llu", &current_level) == 1 ? 1U << 6 : 0;
        else if (strcmp(key, "ip_line") == 0)
            fields |= sscanf(value, "%llu", &current_line) == 1 ? 1U << 7 : 0;
        else if (strcmp(key, "complete") == 0)
            fields |= sscanf(value, "%u", &complete) == 1 ? 1U << 8 : 0;
    }
    if (ferror(fp)) {
        fprintf(stderr, "ERROR: failed reading session '%s'\n",
                session->path);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    if (fields != (1U << 9) - 1 || complete > 1) {
        fprintf(stderr, "ERROR: incomplete session file '%s'\n", session->path);
        return 0;
    }
    if (ip_hash != session->ip_hash || cp_hash != session->cp_hash ||
        config_hash != session->config_hash) {
        fprintf(stderr,
                "ERROR: session model does not match the current input files\n");
        return 0;
    }
    if (min_len != session->min_len || max_len != session->max_len) {
        fprintf(stderr,
                "ERROR: min/max length options do not match the saved session\n");
        return 0;
    }
    if (complete) {
        fprintf(stderr, "ERROR: session '%s' is already complete\n",
                session->path);
        return 0;
    }
    if (current_len < ngram_min_len || current_len < session->min_len ||
        current_line == 0 ||
        current_line > UINT32_MAX) {
        fprintf(stderr, "ERROR: invalid progress in session '%s'\n",
                session->path);
        return 0;
    }
    if (session->max_len && current_len > session->max_len) {
        fprintf(stderr, "ERROR: session length is outside the configured range\n");
        return 0;
    }
    session->start_len = (size_t)current_len;
#if SIZE_MAX < ULLONG_MAX
    if (current_len > SIZE_MAX) {
        fprintf(stderr, "ERROR: invalid length in session '%s'\n",
                session->path);
        return 0;
    }
    if (current_level > SIZE_MAX) {
        fprintf(stderr, "ERROR: invalid level in session '%s'\n",
                session->path);
        return 0;
    }
#endif
    session->start_level = (size_t)current_level;
    session->start_line = (uint32_t)current_line;
    session->resume = 1;
    return 1;
}

static int save_session(Session *session, int complete) {
    char *temp_path;
    size_t temp_len;
    int fd;
    FILE *fp;
    int ok = 1;

    if (!session->enabled) return 1;
    temp_len = strlen(session->path) + sizeof(".tmp.XXXXXX");
    temp_path = malloc(temp_len);
    if (!temp_path) {
        fprintf(stderr, "ERROR: out of memory creating session checkpoint\n");
        return 0;
    }
    snprintf(temp_path, temp_len, "%s.tmp.XXXXXX", session->path);
    fd = mkstemp(temp_path);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot create checkpoint for '%s': %s\n",
                session->path, strerror(errno));
        free(temp_path);
        return 0;
    }
    fp = fdopen(fd, "w");
    if (!fp) {
        fprintf(stderr, "ERROR: cannot open temporary checkpoint: %s\n",
                strerror(errno));
        close(fd);
        unlink(temp_path);
        free(temp_path);
        return 0;
    }
    if (fprintf(fp,
                "OMEN_SESSION_2\n"
                "ip_hash=%016" PRIx64 "\n"
                "cp_hash=%016" PRIx64 "\n"
                "config_hash=%016" PRIx64 "\n"
                "min_len=%zu\n"
                "max_len=%zu\n"
                "ip_line=%" PRIu32 "\n"
                "length=%zu\n"
                "level=%zu\n"
                "complete=%d\n",
                session->ip_hash, session->cp_hash, session->config_hash,
                session->min_len, session->max_len, session->current_line,
                session->current_len, session->current_level, complete) < 0 ||
        fflush(fp) != 0 || fsync(fd) != 0)
        ok = 0;
    if (fclose(fp) != 0) ok = 0;
    if (ok && rename(temp_path, session->path) != 0) ok = 0;
    if (!ok) {
        fprintf(stderr, "ERROR: failed writing session '%s': %s\n",
                session->path, strerror(errno));
        unlink(temp_path);
    } else {
        session->last_save = time(NULL);
    }
    free(temp_path);
    return ok;
}

static int save_session_if_due(Session *session) {
    time_t now;
    if (!session->enabled) return 1;
    now = time(NULL);
    if (session->last_save == 0 ||
        now - session->last_save >= CHECKPOINT_SECONDS)
        return save_session(session, 0);
    return 1;
}

static int emit_candidate(const char *candidate, size_t bytes,
                          Session *session) {
    if (fwrite(candidate, 1, bytes, stdout) != bytes ||
        fputc('\n', stdout) == EOF) {
        fprintf(stderr, "ERROR: writing candidate output failed: %s\n",
                strerror(errno));
        return 0;
    }
    session->candidates++;
    if ((session->candidates & 0x3fffU) == 0 &&
        !save_session_if_due(session))
        return 0;
    return 1;
}

static int generate_for_root(const CpModel *cp, const char *root,
                             size_t root_bytes, size_t root_chars,
                             size_t target_chars, size_t ngram,
                             size_t root_level, size_t target_level,
                             size_t min_cp_level, size_t max_cp_level,
                             char *candidate, size_t *positions,
                             size_t *next, size_t *end, size_t *path_levels,
                             Session *session) {
    size_t depth = root_chars;
    size_t i;
    size_t steps = 0;

    if (!score_is_reachable(target_level, root_level,
                            target_chars - root_chars, min_cp_level,
                            max_cp_level))
        return 1;
    memcpy(candidate, root, root_bytes);
    candidate[root_bytes] = '\0';
    positions[0] = 0;
    for (i = 0; i < root_chars; i++) {
        size_t char_size;
        if (!utf8_char_size((const unsigned char *)candidate + positions[i],
                            root_bytes - positions[i], &char_size))
            return 0;
        positions[i + 1] = positions[i] + char_size;
    }
    path_levels[root_chars] = root_level;
    if (root_chars == target_chars)
        return root_level == target_level
                   ? emit_candidate(candidate, root_bytes, session) : 1;

    find_cp_range(cp, candidate, root_bytes, &next[depth], &end[depth]);
    while (depth >= root_chars) {
        if ((++steps & 0x3fffU) == 0) {
            if (interrupted) return 2;
            if (!save_session_if_due(session)) return 0;
        }
        if (depth == target_chars) {
            if (path_levels[depth] == target_level &&
                !emit_candidate(candidate, positions[depth], session))
                return 0;
            depth--;
            continue;
        }
        if (next[depth] >= end[depth]) {
            if (depth == root_chars) break;
            depth--;
            continue;
        }
        {
            const CpEntry *entry = &cp->entries[next[depth]++];
            const char *token = cp->file.data + entry->offset;
            size_t token_bytes = strlen(token);
            size_t append_bytes = token_bytes - entry->prefix_bytes;
            size_t current_bytes = positions[depth];
            size_t new_level;
            size_t remaining_steps;
            size_t first, last;
            if (append_bytes == 0 ||
                current_bytes > SIZE_MAX - append_bytes) {
                fprintf(stderr, "ERROR: invalid CP continuation\n");
                return 0;
            }
            if (path_levels[depth] > target_level ||
                entry->level > target_level - path_levels[depth])
                continue;
            new_level = path_levels[depth] + entry->level;
            remaining_steps = target_chars - depth - 1;
            if (!score_is_reachable(target_level, new_level,
                                    remaining_steps, min_cp_level,
                                    max_cp_level))
                continue;
            memcpy(candidate + current_bytes,
                   token + entry->prefix_bytes, append_bytes);
            candidate[current_bytes + append_bytes] = '\0';
            positions[depth + 1] = current_bytes + append_bytes;
            path_levels[depth + 1] = new_level;
            depth++;
            if (depth < target_chars) {
                find_cp_range(cp, candidate + positions[depth - (ngram - 1)],
                              positions[depth] -
                                  positions[depth - (ngram - 1)],
                              &first, &last);
                next[depth] = first;
                end[depth] = last;
            }
        }
    }
    return interrupted ? 2 : 1;
}

static void usage(const char *program) {
    fprintf(stderr,
        "Usage: %s --ip IP.level --cp CP.level --config config.txt [options]\n"
        "Options:\n"
        "  --min-len N      Minimum password length in UTF-8 characters\n"
        "  --max-len N      Maximum password length (default: unlimited)\n"
        "  --session FILE   Checkpoint file (default: %s)\n"
        "  --resume         Resume from the saved checkpoint\n"
        "  --no-session     Disable checkpointing\n"
        "  --check          Validate the model without generating candidates\n"
        "  --help           Show this help\n"
        "\n"
        "Candidates are emitted by ascending total OMEN level within each length.\n"
        "Output is streamed to stdout; send it to Hashcat with --stdin.\n",
        program, DEFAULT_SESSION);
}

int main(int argc, char **argv) {
    const char *ip_path = NULL;
    const char *cp_path = NULL;
    const char *config_path = NULL;
    const char *session_path = DEFAULT_SESSION;
    int ngram = 0;
    size_t requested_min = 0;
    size_t requested_max = 0;
    size_t min_len;
    size_t root_chars;
    int min_set = 0;
    int max_set = 0;
    int check_only = 0;
    int no_session = 0;
    int resume = 0;
    int i;
    int result = 1;
    FileData config_file = {0};
    IpModel ip = {0};
    CpModel cp = {0};
    Session session = {0};
    char *candidate = NULL;
    size_t *positions = NULL;
    size_t *next = NULL;
    size_t *end = NULL;
    size_t *path_levels = NULL;
    struct sigaction action;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc)
            ip_path = argv[++i];
        else if (strcmp(argv[i], "--cp") == 0 && i + 1 < argc)
            cp_path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            config_path = argv[++i];
        else if (strcmp(argv[i], "--min-len") == 0 && i + 1 < argc) {
            if (!parse_size(argv[++i], &requested_min)) {
                fprintf(stderr, "ERROR: --min-len must be a positive integer\n");
                return 2;
            }
            min_set = 1;
        } else if (strcmp(argv[i], "--max-len") == 0 && i + 1 < argc) {
            if (!parse_size(argv[++i], &requested_max)) {
                fprintf(stderr, "ERROR: --max-len must be a positive integer\n");
                return 2;
            }
            max_set = 1;
        } else if (strcmp(argv[i], "--session") == 0 && i + 1 < argc)
            session_path = argv[++i];
        else if (strcmp(argv[i], "--resume") == 0)
            resume = 1;
        else if (strcmp(argv[i], "--no-session") == 0)
            no_session = 1;
        else if (strcmp(argv[i], "--check") == 0)
            check_only = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!ip_path || !cp_path || !config_path ||
        (min_set && max_set && requested_min > requested_max) ||
        (resume && no_session) || (check_only && resume)) {
        usage(argv[0]);
        return 2;
    }

    if (!parse_config(config_path, &ngram, &config_file)) goto cleanup;
    root_chars = (size_t)ngram - 1;
    if (!load_ip_model(ip_path, root_chars, &ip) ||
        !load_cp_model(cp_path, (size_t)ngram, &cp))
        goto cleanup;
    if (check_only) {
        printf("Validation: OK\n");
        printf("  ngram:              %d\n", ngram);
        printf("  IP records:         %zu\n", ip.count);
        printf("  CP records:         %zu\n", cp.count);
        result = 0;
        goto cleanup;
    }

    min_len = min_set ? requested_min : root_chars;
    if (min_len < root_chars) min_len = root_chars;
    if (max_set && requested_max < root_chars) {
        fprintf(stderr, "WARNING: max length is shorter than the model prefix\n");
        result = 0;
        goto cleanup;
    }
    session.path = session_path;
    session.enabled = !no_session;
    session.min_len = min_len;
    session.max_len = max_set ? requested_max : 0;
    session.ip_hash = ip.file.hash;
    session.cp_hash = cp.file.hash;
    session.config_hash = config_file.hash;
    session.start_len = min_len;
    session.start_line = ip.entries[0].line;
    if (!level_bounds(&ip, &cp, min_len, root_chars,
                      &session.start_level, &session.current_level)) {
        fprintf(stderr, "ERROR: score range overflows at length %zu\n", min_len);
        goto cleanup;
    }
    if (resume) {
        if (!read_session(&session, root_chars)) goto cleanup;
        {
            size_t level_min, level_max;
            if (!level_bounds(&ip, &cp, session.start_len, root_chars,
                              &level_min, &level_max) ||
                session.start_level < level_min ||
                session.start_level > level_max) {
                fprintf(stderr, "ERROR: saved OMEN level is outside the range\n");
                goto cleanup;
            }
        }
        {
            size_t index;
            int found_line = 0;
            for (index = 0; index < ip.count; index++) {
                if (ip.entries[index].line == session.start_line) {
                    found_line = 1;
                    break;
                }
            }
            if (!found_line) {
                fprintf(stderr, "ERROR: saved IP.level line is not a model record\n");
                goto cleanup;
            }
        }
        fprintf(stderr, "Resuming at IP.level line %" PRIu32
                        ", password length %zu, total level %zu\n",
                session.start_line, session.start_len, session.start_level);
    } else if (session.enabled) {
        session.current_len = min_len;
        session.current_line = ip.entries[0].line;
        session.current_level = session.start_level;
        if (!save_session(&session, 0)) goto cleanup;
    }

    sort_cp_file = &cp.file;
    qsort(cp.entries, cp.count, sizeof(*cp.entries), compare_cp);

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        fprintf(stderr, "ERROR: cannot install signal handlers: %s\n",
                strerror(errno));
        goto cleanup;
    }
    (void)signal(SIGPIPE, SIG_IGN);
    if (setvbuf(stdout, NULL, _IOFBF, OUTPUT_BUFFER_SIZE) != 0) {
        fprintf(stderr, "WARNING: using default stdout buffering\n");
    }

    {
        size_t length = session.start_len;
        int first_length = 1;
        for (;;) {
            size_t level_min, level_max, level;
            size_t score_start;
            size_t steps;
            int resume_current_score = first_length && resume;
            size_t resume_ip_index = 0;
            size_t ip_index;
            if (!level_bounds(&ip, &cp, length, root_chars,
                              &level_min, &level_max)) {
                fprintf(stderr, "ERROR: score range overflows at length %zu\n",
                        length);
                goto cleanup;
            }
            score_start = resume_current_score
                              ? session.start_level : level_min;
            if (score_start < level_min || score_start > level_max) {
                fprintf(stderr, "ERROR: saved OMEN level is outside the range\n");
                goto cleanup;
            }
            if (resume_current_score) {
                for (resume_ip_index = 0; resume_ip_index < ip.count;
                     resume_ip_index++) {
                    if (ip.entries[resume_ip_index].line == session.start_line)
                        break;
                }
                if (resume_ip_index == ip.count) {
                    fprintf(stderr,
                            "ERROR: saved IP.level line is not a model record\n");
                    goto cleanup;
                }
            }
            steps = length - root_chars;
            session.current_len = length;
            session.current_level = score_start;
            session.current_line = resume_current_score
                                       ? session.start_line
                                       : ip.entries[0].line;
            if (!save_session(&session, 0)) goto cleanup;
            if (length > SIZE_MAX / 4 - 1 ||
                length > SIZE_MAX / sizeof(*positions) - 1 ||
                length > SIZE_MAX / sizeof(*path_levels) - 1) {
                fprintf(stderr, "ERROR: password length is too large\n");
                goto cleanup;
            }
            candidate = malloc(length * 4 + 1);
            positions = malloc((length + 1) * sizeof(*positions));
            next = malloc((length + 1) * sizeof(*next));
            end = malloc((length + 1) * sizeof(*end));
            path_levels = malloc((length + 1) * sizeof(*path_levels));
            if (!candidate || !positions || !next || !end || !path_levels) {
                fprintf(stderr, "ERROR: out of memory at length %zu\n", length);
                goto cleanup;
            }
            level = score_start;
            for (;;) {
                size_t first_ip = resume_current_score ? resume_ip_index : 0;
                session.current_level = level;
                for (ip_index = first_ip; ip_index < ip.count; ip_index++) {
                    const IpEntry *entry = &ip.entries[ip_index];
                    const char *root = ip.file.data + entry->offset;
                    size_t root_bytes = strlen(root);
                    int generated;
                    session.current_line = entry->line;
                    if (!save_session_if_due(&session)) goto cleanup;
                    if (interrupted) {
                        if (!save_session(&session, 0)) goto cleanup;
                        fprintf(stderr,
                                "\nInterrupted at IP.level line %" PRIu32
                                ", password length %zu, total level %zu; "
                                "checkpoint saved\n",
                                session.current_line, session.current_len,
                                session.current_level);
                        result = 130;
                        goto cleanup;
                    }
                    if (!score_is_reachable(level, entry->level, steps,
                                            cp.min_level, cp.max_level))
                        continue;
                    generated = generate_for_root(
                        &cp, root, root_bytes, root_chars, length,
                        (size_t)ngram, entry->level, level, cp.min_level,
                        cp.max_level, candidate, positions, next, end,
                        path_levels, &session);
                    if (generated == 0) goto cleanup;
                    if (generated == 2 || interrupted) {
                        if (!save_session(&session, 0)) goto cleanup;
                        fprintf(stderr,
                                "\nInterrupted at IP.level line %" PRIu32
                                ", password length %zu, total level %zu; "
                                "checkpoint saved\n",
                                session.current_line, session.current_len,
                                session.current_level);
                        result = 130;
                        goto cleanup;
                    }
                    if ((session.candidates & 0x3fffffU) == 0 &&
                        session.candidates != 0)
                        fprintf(stderr,
                                "\rlength=%zu level=%zu IP.line=%" PRIu32
                                " candidates=%" PRIu64,
                                length, level, entry->line,
                                session.candidates);
                }
                resume_current_score = 0;
                if (level == level_max) break;
                level++;
                session.current_level = level;
                session.current_line = ip.entries[0].line;
                if (!save_session_if_due(&session)) goto cleanup;
            }
            free(candidate); candidate = NULL;
            free(positions); positions = NULL;
            free(next); next = NULL;
            free(end); end = NULL;
            free(path_levels); path_levels = NULL;
            if (fflush(stdout) != 0) {
                fprintf(stderr, "ERROR: flushing candidate output failed: %s\n",
                        strerror(errno));
                goto cleanup;
            }
            fprintf(stderr,
                    "\rlength=%zu complete (total levels %zu..%zu); "
                    "candidates=%" PRIu64 "\n",
                    length, level_min, level_max, session.candidates);
            if (max_set && length >= requested_max) break;
            if (length == SIZE_MAX) {
                fprintf(stderr, "ERROR: reached maximum representable length\n");
                goto cleanup;
            }
            length++;
            first_length = 0;
            resume = 0;
            if (!level_bounds(&ip, &cp, length, root_chars,
                              &level_min, &level_max)) {
                fprintf(stderr, "ERROR: score range overflows at length %zu\n",
                        length);
                goto cleanup;
            }
            session.current_len = length;
            session.current_level = level_min;
            session.current_line = ip.entries[0].line;
            if (!save_session(&session, 0)) goto cleanup;
            if (interrupted) {
                if (!save_session(&session, 0)) goto cleanup;
                result = 130;
                goto cleanup;
            }
        }
    }
    if (!save_session(&session, 1)) goto cleanup;
    fprintf(stderr, "Generation complete; total candidates=%" PRIu64 "\n",
            session.candidates);
    result = 0;

cleanup:
    free(candidate);
    free(positions);
    free(next);
    free(end);
    free(path_levels);
    free(ip.entries);
    free(ip.file.data);
    free(cp.entries);
    free(cp.file.data);
    free(config_file.data);
    return result;
}
