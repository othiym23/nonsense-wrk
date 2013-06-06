#ifndef WRK_H
#define WRK_H

#include "config.h"
#include <pthread.h>
#include <inttypes.h>
#include <sys/types.h>

#include "stats.h"
#include "ae.h"
#include "tinymt64.h"
#include "hash.h"

#define VERSION  "2.1.0"
#define RECVBUF  8192
#define SAMPLES  100000000

#define SOCKET_TIMEOUT_MS   2000
#define SAMPLE_INTERVAL_MS  10
#define CALIBRATE_DELAY_MS  500
#define TIMEOUT_INTERVAL_MS 2000

typedef struct {
    uint32_t connect;
    uint32_t handshake;
    uint32_t read;
    uint32_t write;
    uint32_t validate;
    uint32_t timeout;
} errors;

typedef struct {
    pthread_t thread;
    aeEventLoop *loop;
    uint64_t connections;
    uint64_t stop_at;
    uint64_t complete;
    uint64_t requests;
    uint64_t bytes;
    uint64_t start;
    uint64_t rate;
    uint64_t missed;
    stats *latency;
    tinymt64_t rand;
    errors errors;
    struct connection *cs;
} thread;

typedef struct connection {
    thread *thread;
    int fd;
    uint64_t start;
    char buf[RECVBUF];
    char last_hash[SHA_LENGTH * 2];
    char hash[SHA_LENGTH * 2];
} connection;

struct config;

static void *thread_main(void *);
static int connect_socket(thread *, connection *);
static int reconnect_socket(thread *, connection *);

static int calibrate(aeEventLoop *, long long, void *);
static int sample_rate(aeEventLoop *, long long, void *);
static int check_timeouts(aeEventLoop *, long long, void *);

static void socket_handshake(aeEventLoop *, int, void *, int);
static void socket_writeable(aeEventLoop *, int, void *, int);
static void socket_readable(aeEventLoop *, int, void *, int);
static int validate_response(connection *c);

static uint64_t time_us();

static int parse_args(struct config *, char **, char **, int, char **);
static void print_stats_header();
static void print_stats(char *, stats *, char *(*)(long double));
static void print_stats_latency(stats *);

#endif /* WRK_H */
