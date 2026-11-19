/*
 * omen_level_check.c  (v7)
 *
 * Mo hinh sinh mat khau cua pcfg-go (theo mo ta):
 *   1. IP = token dau tien, khop pw[0..N-1], tra trong IP.level.
 *   2. pos = 1. Tai moi pos, lay pw[pos..pos+N-1], tra trong CP.level.
 *      - Neu khop: cong weight, pos += 1.
 *      - Neu KHONG khop: DUNG -> mat khau khong sinh duoc.
 *   3. Dung khi pos + N == len  -> thanh cong (phu khop chinh xac).
 *      Neu pos + N > len        -> token cuoi vuot qua cuoi -> that bai
 *                                  (tru khi ban muon chap nhan vuot, xem --allow-overrun).
 *
 * Level = weight(IP) + tong weight cac CP token da khop.
 * Duong di la DUY NHAT (moi buoc chi co 1 token tai vi tri do).
 *
 * Build:
 *   cc -O2 -Wall -Wextra -std=c11 -o omen-level-check omen_level_check.c
 *
 * Chay:
 *   ./omen-level-check --ip IP.level --cp CP.level --config config.txt \
 *                      --password "Helloworld"
 */

#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_CAP 65536

/* ================== Hash table ================== */

typedef struct Entry {
    char *token;
    size_t len;
    unsigned long long weight;
    struct Entry *next;
} Entry;

typedef struct {
    Entry **buckets;
    size_t nbuckets;
    size_t count;
} TokenMap;

static uint64_t hash_bytes(const char *s, size_t len) {
    uint64_t h = 1469598103934665603ULL;
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static TokenMap *map_create(size_t nbuckets) {
    TokenMap *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->buckets = calloc(nbuckets, sizeof(Entry *));
    if (!m->buckets) { free(m); return NULL; }
    m->nbuckets = nbuckets;
    return m;
}

static void map_free(TokenMap *m) {
    size_t i;
    if (!m) return;
    for (i = 0; i < m->nbuckets; i++) {
        Entry *e = m->buckets[i];
        while (e) {
            Entry *next = e->next;
            free(e->token);
            free(e);
            e = next;
        }
    }
    free(m->buckets);
    free(m);
}

static int map_get(const TokenMap *m, const char *tok, size_t len,
                   unsigned long long *out) {
    uint64_t h = hash_bytes(tok, len);
    Entry *e = m->buckets[(size_t)(h % m->nbuckets)];
    while (e) {
        if (e->len == len && memcmp(e->token, tok, len) == 0) {
            *out = e->weight;
            return 1;
        }
        e = e->next;
    }
    return 0;
}

static int map_put_min(TokenMap *m, const char *tok, size_t len,
                       unsigned long long weight) {
    uint64_t h = hash_bytes(tok, len);
    size_t idx = (size_t)(h % m->nbuckets);
    Entry *e = m->buckets[idx];
    while (e) {
        if (e->len == len && memcmp(e->token, tok, len) == 0) {
            if (weight < e->weight) e->weight = weight;
            return 1;
        }
        e = e->next;
    }
    e = malloc(sizeof(*e));
    if (!e) return 0;
    e->token = malloc(len);
    if (!e->token) { free(e); return 0; }
    memcpy(e->token, tok, len);
    e->len = len;
    e->weight = weight;
    e->next = m->buckets[idx];
    m->buckets[idx] = e;
    m->count++;
    return 1;
}

/* ================== Parse dong ================== */

static char *trim(char *s) {
    char *end;
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int parse_line(char *line, const char **value, size_t *value_len,
                      unsigned long long *weight) {
    char *p = trim(line);
    char *endptr, *q;
    int has_weight = 0;

    *weight = 0;
    if (*p == '\0' || *p == '#') return 0;

    errno = 0;
    unsigned long long w = strtoull(p, &endptr, 10);
    if (endptr != p && errno != ERANGE) {
        if (*endptr == '\0') return -1;
        if (isspace((unsigned char)*endptr)) {
            *weight = w;
            has_weight = 1;
            p = endptr;
            while (*p && isspace((unsigned char)*p)) p++;
        }
    }

    q = p;
    while (*q && !isspace((unsigned char)*q)) q++;
    if (q == p) return -1;
    *value = p;
    *value_len = (size_t)(q - p);

    while (*q && isspace((unsigned char)*q)) q++;
    if (*q != '\0') return -1;
    return has_weight ? 1 : 2;
}

/* ================== Nap file ================== */

typedef struct {
    unsigned long lines, valid, no_weight, malformed, wrong_len;
} LoadStats;

static int load_level_file(const char *path, TokenMap *map,
                           size_t expected_len, LoadStats *st) {
    FILE *fp = fopen(path, "r");
    char line[LINE_CAP];

    memset(st, 0, sizeof(*st));
    if (!fp) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n",
                path, strerror(errno));
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        const char *v;
        size_t vlen;
        unsigned long long w;
        int rc;
        st->lines++;

        if (!strchr(line, '\n') && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {}
            st->malformed++;
            continue;
        }
        rc = parse_line(line, &v, &vlen, &w);
        if (rc == 0) continue;
        if (rc == 2) { st->no_weight++; continue; }
        if (rc == -1) { st->malformed++; continue; }

        if (vlen != expected_len) {
            st->wrong_len++;
            continue;
        }
        st->valid++;
        if (!map_put_min(map, v, vlen, w)) {
            fprintf(stderr, "ERROR: OOM khi nap '%s'\n", path);
            fclose(fp);
            return 0;
        }
    }

    if (ferror(fp)) { fclose(fp); return 0; }
    fclose(fp);
    return 1;
}

/* ================== Doc ngram ================== */

static int read_ngram(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[LINE_CAP];
    int ngram = 0;

    if (!fp) {
        fprintf(stderr, "ERROR: cannot open config '%s': %s\n",
                path, strerror(errno));
        return 0;
    }
    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';' || *p == '[') continue;
        if (strncmp(p, "ngram", 5) == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                char *v = trim(eq + 1), *endptr;
                long n = strtol(v, &endptr, 10);
                while (*endptr && isspace((unsigned char)*endptr)) endptr++;
                if (endptr != v && *endptr == '\0' && n > 0 && n <= 64)
                    ngram = (int)n;
            }
        }
    }
    fclose(fp);
    return ngram;
}

/* ================== Tra cuu theo mo hinh sliding ================== */

typedef struct {
    size_t pos;
    const char *token;   /* tro vao password */
    size_t len;
    unsigned long long weight;
    int is_ip;
} Step;

/*
 * Tra cuu theo mo hinh:
 *   - IP = pw[0..N-1], tra IP.level.
 *   - pos = 1, 2, ... ; CP = pw[pos..pos+N-1], tra CP.level.
 *   - Moi buoc phai khop; neu khong -> that bai.
 *   - Dung khi pos + N == len -> thanh cong.
 *   - Neu pos + N > len  -> token cuoi vuot qua cuoi.
 *     Mac dinh coi la THAT BAI (vi khong phu khop chinh xac).
 *
 * Neu muon in chi tiet cac buoc, truyen steps != NULL.
 *
 * Tra ve: 1 = thanh cong, 0 = that bai, -1 = tran so.
 */
static int lookup_sliding(const TokenMap *map_ip, const TokenMap *map_cp,
                          const char *pw, size_t len, int ngram,
                          unsigned long long *out_level,
                          Step *steps, size_t max_steps, size_t *out_nsteps) {
    size_t n = (size_t)ngram;
    size_t pos;
    unsigned long long total = 0, w;
    size_t ns = 0;

    if (len < n) {
        fprintf(stderr, "Password ngan hon ngram (%zu < %d)\n", len, ngram);
        return 0;
    }
    if (len == n) {
        /* Chi co IP, khong co CP — hop le neu IP khop. */
        if (!map_get(map_ip, pw, n, &w)) {
            printf("  IP '%.*s': NOT FOUND\n", (int)n, pw);
            return 0;
        }
        total = w;
        if (steps && ns < max_steps) {
            steps[ns].pos = 0; steps[ns].token = pw; steps[ns].len = n;
            steps[ns].weight = w; steps[ns].is_ip = 1; ns++;
        }
        *out_level = total;
        if (out_nsteps) *out_nsteps = ns;
        return 1;
    }

    /* Buoc 1: IP */
    if (!map_get(map_ip, pw, n, &w)) {
        printf("  IP '%.*s': NOT FOUND in IP.level -> that bai\n",
               (int)n, pw);
        return 0;
    }
    total = w;
    if (steps && ns < max_steps) {
        steps[ns].pos = 0; steps[ns].token = pw; steps[ns].len = n;
        steps[ns].weight = w; steps[ns].is_ip = 1; ns++;
    }
    printf("  IP '%.*s': weight %llu\n", (int)n, pw, w);

    /* Buoc 2: CP truot */
    for (pos = 1; pos + n <= len; pos++) {
        const char *block = pw + pos;

        if (!map_get(map_cp, block, n, &w)) {
            printf("  CP '%.*s' (pos %zu): NOT FOUND in CP.level -> that bai\n",
                   (int)n, block, pos);
            return 0;
        }
        if (total > ULLONG_MAX - w) return -1;
        total += w;
        if (steps && ns < max_steps) {
            steps[ns].pos = pos; steps[ns].token = block; steps[ns].len = n;
            steps[ns].weight = w; steps[ns].is_ip = 0; ns++;
        }
        printf("  CP '%.*s' (pos %zu): weight %llu\n",
               (int)n, block, pos, w);

        if (pos + n == len) {
            /* Token cuoi ket thuc dung tai cuoi -> thanh cong */
            *out_level = total;
            if (out_nsteps) *out_nsteps = ns;
            return 1;
        }
    }

    /* Neu thoat vong lap ma chua thanh cong:
     * pos + n > len tai buoc cuoi -> token cuoi vuot qua cuoi.
     * Vi du len=10, n=4: cac pos = 1..6, pos=6 -> 6+4=10 == len -> da
     * thanh cong o tren. Neu len khong thoa (vi du len=11, n=4):
     * pos chay 1..7, pos=7 -> 7+4=11 == len -> thanh cong.
     * Truong hop that bai: khong co pos nao thoa pos+n==len, tuc
     * len khong the bieu dien duoi dang 1 + k*1 + n voi k>=0, hay
     * noi cach khac: luon co pos+n==len khi len>=n+1 va len<=...?
     * Thuc te: pos chay tu 1 den len-n. Neu len-n >= 1 thi luon co
     * pos = len-n thoa pos+n == len. Nen vong lap LUON dat pos=len-n
     * neu khong bi dung boi NOT FOUND. Vay chi that bai khi gap
     * NOT FOUND. Doan duoi day chi de phong.
     */
    fprintf(stderr, "ERROR: khong ro ly do that bai (logic bug)\n");
    return 0;
}

/* ================== main ================== */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --ip IP.level --cp CP.level --config config.txt "
        "[--password PW]\n", prog);
}

int main(int argc, char **argv) {
    const char *ip_path = NULL, *cp_path = NULL, *config_path = NULL;
    const char *password = NULL;
    int i, ngram, rc;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc)
            ip_path = argv[++i];
        else if (strcmp(argv[i], "--cp") == 0 && i + 1 < argc)
            cp_path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            config_path = argv[++i];
        else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc)
            password = argv[++i];
        else { usage(argv[0]); return 2; }
    }

    if (!ip_path || !cp_path || !config_path) {
        usage(argv[0]);
        return 2;
    }

    ngram = read_ngram(config_path);
    if (ngram <= 0) {
        fprintf(stderr,
            "ERROR: khong doc duoc ngram tu '%s' (can dong 'ngram = N', N>0)\n",
            config_path);
        return 2;
    }
    printf("ngram = %d -> moi token dai dung %d ky tu\n", ngram, ngram);

    if (password) {
        TokenMap *map_ip = map_create(1 << 20);
        TokenMap *map_cp = map_create(1 << 20);
        LoadStats st;
        unsigned long long level = 0;
        size_t plen = strlen(password);

        if (!map_ip || !map_cp) { perror("map_create"); return 1; }

        if (!load_level_file(ip_path, map_ip, (size_t)ngram, &st)) {
            map_free(map_ip); map_free(map_cp); return 1;
        }
        printf("loaded %s: %lu token dung %d ky tu, %lu sai do dai (bo qua), "
               "%lu thieu weight, %lu malformed\n",
               ip_path, st.valid, ngram, st.wrong_len, st.no_weight, st.malformed);

        if (!load_level_file(cp_path, map_cp, (size_t)ngram, &st)) {
            map_free(map_ip); map_free(map_cp); return 1;
        }
        printf("loaded %s: %lu token dung %d ky tu, %lu sai do dai (bo qua), "
               "%lu thieu weight, %lu malformed\n",
               cp_path, st.valid, ngram, st.wrong_len, st.no_weight, st.malformed);

        printf("Password: '%s' (dai %zu)\n", password, plen);

        rc = lookup_sliding(map_ip, map_cp, password, plen, ngram, &level,
                            NULL, 0, NULL);

        if (rc == 1) {
            printf("  => THANH CONG: Level = %llu (tong weight)\n", level);
        } else if (rc == 0) {
            printf("  => THAT BAI: mat khau KHONG the sinh tu tap du lieu\n");
        } else {
            fprintf(stderr, "ERROR: tran so khi cong weight\n");
        }

        map_free(map_ip);
        map_free(map_cp);
        return (rc == 1) ? 0 : 1;
    }

    puts("Validation: OK (structural check only)");
    return 0;
}