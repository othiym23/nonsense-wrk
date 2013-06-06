// Copyright (C) 2012 - Will Glozer.  All rights reserved.
// Copyright (C) 2013 - Forrest L Norvell.  All rights reserved.

#include "wrk.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

#include "aprintf.h"
#include "stats.h"
#include "units.h"
#include "zmalloc.h"
#include "tinymt64.h"

static struct config {
    struct addrinfo addr;
    uint64_t threads;
    uint64_t connections;
    uint64_t duration;
    uint64_t timeout;
    bool     latency;
} cfg;

static struct {
    stats *latency;
    stats *requests;
    pthread_mutex_t mutex;
} statistics;

static volatile sig_atomic_t stop = 0;

static void handler(int sig) {
    stop = 1;
}

static void usage() {
    printf("Usage: wrk <options> [<host>[:<port>]]                \n"
           "  Options:                                            \n"
           "    -c, --connections <N>  Connections to keep open   \n"
           "    -d, --duration    <T>  Duration of test           \n"
           "    -t, --threads     <N>  Number of threads to use   \n"
           "                                                      \n"
           "        --latency          Print latency statistics   \n"
           "        --timeout     <T>  Socket/request timeout     \n"
           "    -v, --version          Print version details      \n"
           "                                                      \n"
           "  Numeric arguments may include a SI unit (1k, 1M, 1G)\n"
           "  Time arguments may include a time unit (2s, 2m, 2h)\n");
}

int main(int argc, char **argv) {
    struct addrinfo *addrs, *addr;
    char *host = "127.0.0.1";
    char *port = "1337";
    int rc;

    if (parse_args(&cfg, &host, &port, argc, argv)) {
        usage();
        exit(1);
    }

    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };

    if ((rc = getaddrinfo(host, port, &hints, &addrs)) != 0) {
        const char *msg = gai_strerror(rc);
        fprintf(stderr, "unable to resolve %s:%s: %s\n", host, port, msg);
        exit(1);
    }

    for (addr = addrs; addr != NULL; addr = addr->ai_next) {
        int fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (fd == -1) continue;
        rc = connect(fd, addr->ai_addr, addr->ai_addrlen);
        close(fd);
        if (rc == 0) break;
    }

    if (addr == NULL) {
        char *msg = strerror(errno);
        fprintf(stderr, "unable to connect to %s:%s: %s\n", host, port, msg);
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    cfg.addr = *addr;

    pthread_mutex_init(&statistics.mutex, NULL);
    statistics.latency  = stats_alloc(SAMPLES);
    statistics.requests = stats_alloc(SAMPLES);

    thread *threads = zcalloc(cfg.threads * sizeof(thread));
    uint64_t connections = cfg.connections / cfg.threads;
    uint64_t stop_at     = time_us() + (cfg.duration * 1000000);

    for (uint64_t i = 0; i < cfg.threads; i++) {
        thread *t = &threads[i];
        t->connections = connections;
        t->stop_at     = stop_at;

        if (pthread_create(&t->thread, NULL, &thread_main, t)) {
            char *msg = strerror(errno);
            fprintf(stderr, "unable to create thread %"PRIu64" %s\n", i, msg);
            exit(2);
        }
    }

    struct sigaction sa = {
        .sa_handler = handler,
        .sa_flags   = 0,
    };
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    char *time = format_time_s(cfg.duration);
    printf("Running %s test @ %s:%s\n", time, host, port);
    printf("  %"PRIu64" threads and %"PRIu64" connections\n", cfg.threads, cfg.connections);

    uint64_t start    = time_us();
    uint64_t complete = 0;
    uint64_t bytes    = 0;
    errors errors     = { 0 };

    for (uint64_t i = 0; i < cfg.threads; i++) {
        thread *t = &threads[i];
        pthread_join(t->thread, NULL);

        complete += t->complete;
        bytes    += t->bytes;

        errors.connect   += t->errors.connect;
        errors.handshake += t->errors.handshake;
        errors.read      += t->errors.read;
        errors.validate  += t->errors.validate;
        errors.write     += t->errors.write;
        errors.timeout   += t->errors.timeout;
    }

    uint64_t runtime_us = time_us() - start;
    long double runtime_s   = runtime_us / 1000000.0;
    long double req_per_s   = complete   / runtime_s;
    long double bytes_per_s = bytes      / runtime_s;

    print_stats_header();
    print_stats("Latency", statistics.latency, format_time_us);
    print_stats("Req/Sec", statistics.requests, format_metric);
    if (cfg.latency) print_stats_latency(statistics.latency);

    char *runtime_msg = format_time_us(runtime_us);

    printf("  %"PRIu64" requests in %s, %sB read\n", complete, runtime_msg, format_binary(bytes));
    if (errors.connect || errors.handshake || errors.read ||
        errors.validate || errors.write || errors.timeout) {
        printf("  Socket errors: connect %d, handshake %d, read %d, validate %d, write %d, timeout %d\n",
               errors.connect, errors.handshake, errors.read, errors.validate, errors.write, errors.timeout);
    }

    if (errors.handshake) {
        printf("  Bad handshakes from server: %d\n", errors.handshake);
    }

    printf("Requests/sec: %9.2Lf\n", req_per_s);
    printf("Transfer/sec: %10sB\n", format_binary(bytes_per_s));

    return 0;
}

void *thread_main(void *arg) {
    thread *thread = arg;

    aeEventLoop *loop = aeCreateEventLoop(10 + cfg.connections * 3);
    thread->cs   = zmalloc(thread->connections * sizeof(connection));
    thread->loop = loop;
    tinymt64_init(&thread->rand, time_us());
    thread->latency = stats_alloc(100000);

    connection *c = thread->cs;

    for (uint64_t i = 0; i < thread->connections; i++, c++) {
        c->thread = thread;
        random_hash(&thread->rand, c->hash);
        connect_socket(thread, c);
    }

    aeCreateTimeEvent(loop, CALIBRATE_DELAY_MS, calibrate, thread, NULL);
    aeCreateTimeEvent(loop, TIMEOUT_INTERVAL_MS, check_timeouts, thread, NULL);

    thread->start = time_us();
    aeMain(loop);

    aeDeleteEventLoop(loop);
    zfree(thread->cs);

    uint64_t max = thread->latency->max;
    stats_free(thread->latency);

    pthread_mutex_lock(&statistics.mutex);
    for (uint64_t i = 0; i < thread->missed; i++) {
        stats_record(statistics.latency, max);
    }
    pthread_mutex_unlock(&statistics.mutex);

    return NULL;
}

static int connect_socket(thread *thread, connection *c) {
    struct addrinfo addr = cfg.addr;
    struct aeEventLoop *loop = thread->loop;
    int fd, flags;

    fd = socket(addr.ai_family, addr.ai_socktype, addr.ai_protocol);

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (connect(fd, addr.ai_addr, addr.ai_addrlen) == -1) {
        if (errno != EINPROGRESS) goto error;
    }

    flags = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));

    if (aeCreateFileEvent(loop, fd, AE_READABLE, socket_handshake, c) != AE_OK) {
        goto error;
    }

    c->fd = fd;

    return fd;

  error:
    thread->errors.connect++;
    close(fd);
    return -1;
}

static int reconnect_socket(thread *thread, connection *c) {
    aeDeleteFileEvent(thread->loop, c->fd, AE_WRITABLE | AE_READABLE);
    close(c->fd);
    return connect_socket(thread, c);
}

static int calibrate(aeEventLoop *loop, long long id, void *data) {
    thread *thread = data;

    uint64_t elapsed_ms = (time_us() - thread->start) / 1000;
    uint64_t req_per_ms = thread->requests / elapsed_ms;

    if (!req_per_ms) return CALIBRATE_DELAY_MS / 2;

    thread->rate  = (req_per_ms * SAMPLE_INTERVAL_MS) / 10;
    thread->start = time_us();
    thread->requests = 0;
    stats_reset(thread->latency);

    aeCreateTimeEvent(loop, SAMPLE_INTERVAL_MS, sample_rate, thread, NULL);

    return AE_NOMORE;
}

static int sample_rate(aeEventLoop *loop, long long id, void *data) {
    thread *thread = data;

    uint64_t elapsed_ms = (time_us() - thread->start) / 1000;
    uint64_t requests = (thread->requests / elapsed_ms) * 1000;
    uint64_t missed = thread->rate - MIN(thread->rate, thread->latency->limit);
    uint64_t count = thread->rate - missed;

    pthread_mutex_lock(&statistics.mutex);
    stats_sample(statistics.latency, &thread->rand, count, thread->latency);
    stats_record(statistics.requests, requests);
    pthread_mutex_unlock(&statistics.mutex);

    uint64_t max = thread->latency->max;
    thread->missed  += missed;
    thread->requests = 0;
    thread->start    = time_us();
    stats_reset(thread->latency);
    thread->latency->max = max;

    return SAMPLE_INTERVAL_MS;
}

static int validate_response(connection *c) {
    char *source, *ret_hash, *nonce, *freeme;
    char scratch[512];

    unsigned char vhash[SHA_LENGTH];
    int valid = 0;

    /* printf("c->buf = %s.\n", c->buf); */
    freeme = source = strdup(c->buf);
    ret_hash = strsep(&source, ":");
    nonce = source;
    /* printf("nonce = %s.\n", nonce); */

    /* no colon: nope */
    if (nonce != NULL) {
        /* returned hash != sent hash: nope */
        if (memcmp(ret_hash, c->hash, SHA_LENGTH * 2) == 0) {
            strcpy(scratch, ret_hash);
            strcat(scratch, nonce);
            sha256(scratch, strlen(scratch), vhash);

            /* is the work proved? */
            if (vhash[SHA_LENGTH - 1] == 0) {
                valid = 1;
                strcpy(c->last_hash, c->hash);
                hexillate(vhash, c->hash, SHA_LENGTH);
            }
            else {
                printf("%s is not a valid proof of work.\n", c->buf);
            }
        }
        else {
            printf("received payload %s doesn't match sent payload %s.\n", ret_hash, c->hash);
        }
    }
    else {
        printf("input %s is missing a nonce.\n", c->buf);
    }

    free(freeme);
    return valid;
}

static int check_timeouts(aeEventLoop *loop, long long id, void *data) {
    thread *thread = data;
    connection *c  = thread->cs;
    uint64_t now   = time_us();

    uint64_t maxAge = now - (cfg.timeout * 1000);

    for (uint64_t i = 0; i < thread->connections; i++, c++) {
        if (maxAge > c->start) {
            thread->errors.timeout++;
        }
    }

    if (stop || now >= thread->stop_at) {
        aeStop(loop);
    }

    return TIMEOUT_INTERVAL_MS;
}

static void socket_handshake(aeEventLoop *loop, int fd, void *data, int mask) {
    connection *c = data;
    char scratch[512];
    ssize_t n;

    if ((n = read(fd, scratch, sizeof(scratch))) <= 0) goto error;
    if (memcmp("ok\n", scratch, 3) != 0) goto error;

    if (aeCreateFileEvent(loop, fd, AE_WRITABLE, socket_writeable, c) != AE_OK) {
        goto error;
    }

    if (aeCreateFileEvent(loop, fd, AE_READABLE, socket_readable, c) != AE_OK) {
        goto error;
    }

    return;

  error:
    c->thread->errors.handshake++;
    reconnect_socket(c->thread, c);
}

static void socket_writeable(aeEventLoop *loop, int fd, void *data, int mask) {
    connection *c = data;

    if (write(fd, c->hash, SHA_LENGTH * 2) < SHA_LENGTH * 2) goto error;
    c->start = time_us();
    aeDeleteFileEvent(loop, fd, AE_WRITABLE);

    return;

  error:
    c->thread->errors.write++;
    reconnect_socket(c->thread, c);
}

static void socket_readable(aeEventLoop *loop, int fd, void *data, int mask) {
    connection *c = data;
    thread *thread = c->thread;
    uint64_t now;
    ssize_t n;

    if ((n = read(fd, c->buf, sizeof(c->buf))) <= 0) goto error;
    c->buf[n] = '\0';

    now = time_us();
    if (!validate_response(c)) goto invalid;
    thread->bytes += n;
    thread->complete++;
    thread->requests++;

    stats_record(thread->latency, now - c->start);

    if (now >= thread->stop_at) {
        aeStop(thread->loop);
	close(fd);
    }
    else {
        reconnect_socket(c->thread, c);
    }

    return;

  invalid:
    c->thread->errors.validate++;
    reconnect_socket(c->thread, c);
    return;

  error:
    c->thread->errors.read++;
    reconnect_socket(c->thread, c);
}

static uint64_t time_us() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (t.tv_sec * 1000000) + t.tv_usec;
}


static struct option longopts[] = {
    { "connections", required_argument, NULL, 'c' },
    { "duration",    required_argument, NULL, 'd' },
    { "threads",     required_argument, NULL, 't' },
    { "latency",     no_argument,       NULL, 'L' },
    { "timeout",     required_argument, NULL, 'T' },
    { "help",        no_argument,       NULL, 'h' },
    { "version",     no_argument,       NULL, 'v' },
    { NULL,          0,                 NULL,  0  }
};

static int parse_args(struct config *cfg, char **host, char **port, int argc, char **argv) {
    char c, *host_str;

    memset(cfg, 0, sizeof(struct config));
    cfg->threads     = 2;
    cfg->connections = 10;
    cfg->duration    = 10;
    cfg->timeout     = SOCKET_TIMEOUT_MS;

    while ((c = getopt_long(argc, argv, "t:c:d:H:M:B:T:Lrv?", longopts, NULL)) != -1) {
        switch (c) {
            case 't':
                if (scan_metric(optarg, &cfg->threads)) return -1;
                break;
            case 'c':
                if (scan_metric(optarg, &cfg->connections)) return -1;
                break;
            case 'd':
                if (scan_time(optarg, &cfg->duration)) return -1;
                break;
            case 'L':
                cfg->latency = true;
                break;
            case 'T':
                if (scan_time(optarg, &cfg->timeout)) return -1;
                cfg->timeout *= 1000;
                break;
            case 'v':
                printf("wrk-nonsense %s [%s] ", VERSION, aeGetApiName());
                printf("Copyright (C) 2012 Will Glozer (hackt up by Forrest L Norvell)\n");
                break;
            case 'r':
                fprintf(stderr, "wrk 2.0.0+ uses -d instead of -r\n");
            case 'h':
            case '?':
            case ':':
            default:
                return -1;
        }
    }

    if (!cfg->threads || !cfg->duration) return -1;

    if (!cfg->connections || cfg->connections < cfg->threads) {
        fprintf(stderr, "number of connections must be >= threads\n");
        return -1;
    }

    if (argc > 1 && optind < argc) {
        host_str = strdup(argv[optind]);
        *host = strsep(&host_str, ":");
        *port = host_str;
    }

    return 0;
}

static void print_stats_header() {
    printf("  Thread Stats%6s%11s%8s%12s\n", "Avg", "Stdev", "Max", "+/- Stdev");
}

static void print_units(long double n, char *(*fmt)(long double), int width) {
    char *msg = fmt(n);
    int len = strlen(msg), pad = 2;

    if (isalpha(msg[len-1])) pad--;
    if (isalpha(msg[len-2])) pad--;
    width -= pad;

    printf("%*.*s%.*s", width, width, msg, pad, "  ");

    free(msg);
}

static void print_stats(char *name, stats *stats, char *(*fmt)(long double)) {
    uint64_t max = stats->max;
    long double mean  = stats_summarize(stats);
    long double stdev = stats_stdev(stats, mean);

    printf("    %-10s", name);
    print_units(mean,  fmt, 8);
    print_units(stdev, fmt, 10);
    print_units(max,   fmt, 9);
    printf("%8.2Lf%%\n", stats_within_stdev(stats, mean, stdev, 1));
}

static void print_stats_latency(stats *stats) {
    long double percentiles[] = { 50.0, 75.0, 90.0, 99.0 };
    printf("  Latency Distribution\n");
    for (size_t i = 0; i < sizeof(percentiles) / sizeof(long double); i++) {
        long double p = percentiles[i];
        uint64_t n = stats_percentile(stats, p);
        printf("%7.0Lf%%", p);
        print_units(n, format_time_us, 10);
        printf("\n");
    }
}
