/* Host-only BPF helper shims. No copied production decision logic. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int kernel_version = 608, emitted, user_reads, invalid_reads;
static int failures, have_io;
static struct network_event captured;
static struct io_call saved_io;
static const unsigned char *segment;
static size_t segment_capacity;
static const void *unreadable_kernel;

static int host_field_exists(const char *field) {
    if (strstr(field, "iter_type")) return kernel_version >= 514;
    if (strstr(field, "__iov")) return kernel_version >= 604;
    if (strstr(field, "ubuf")) return kernel_version >= 601;
    return 1;
}
static int host_enum(const char *expr, int kind) {
    int ubuf = strstr(expr, "ITER_UBUF") != NULL;
    if (!kind) return !ubuf || kernel_version >= 601;
    if (ubuf) return kernel_version >= 608 ? 0 : 6;
    return kernel_version >= 608 ? 1 : kernel_version >= 514 ? 0 : 4;
}
static __u64 fake_pid(void) { return 0x100000002ULL; }
static __u64 fake_time(void) { return 42; }
static long read_kernel(void *dst, __u32 size, const void *src) {
    if (!src || src == unreadable_kernel) return -1;
    memcpy(dst, src, size); return 0;
}
static long read_user(void *dst, __u32 size, const void *src) {
    user_reads++;
    if (!src) return -1;
    if (segment && (const unsigned char *)src >= segment &&
        (const unsigned char *)src < segment + segment_capacity &&
        size > segment_capacity - ((const unsigned char *)src - segment))
        invalid_reads++;
    memcpy(dst, src, size); return 0;
}
static void *lookup(void *map, const void *key) {
    (void)key;
    return map == &io_calls && have_io ? &saved_io : NULL;
}
static long update(void *map, const void *key, const void *value, __u64 flags) {
    (void)key; (void)flags;
    if (map == &io_calls) { saved_io = *(const struct io_call *)value; have_io = 1; }
    return 0;
}
static long delete(void *map, const void *key) {
    (void)key;
    if (map == &io_calls) have_io = 0;
    return 0;
}
static void *reserve(void *map, __u64 size, __u64 flags) {
    (void)map; (void)flags;
    return size == sizeof(captured) ? &captured : NULL;
}
static void submit(void *data, __u64 flags) { (void)data; (void)flags; emitted++; }
static void discard(void *data, __u64 flags) { (void)data; (void)flags; }
static void reset(void) {
    emitted = user_reads = invalid_reads = have_io = 0;
    segment = NULL; segment_capacity = 0; unreadable_kernel = NULL;
    memset(&captured, 0, sizeof(captured)); memset(&saved_io, 0, sizeof(saved_io));
}
static void check(int condition, const char *label) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s (events=%d reads=%d overreads=%d dest=%u)\n",
                label, emitted, user_reads, invalid_reads, captured.destination_port);
        failures++;
    }
}
static struct sock dns_socket(void) {
    struct sock sk = {};
    sk.__sk_common.skc_family = AF_INET;
    sk.__sk_common.skc_num = 30000;
    sk.__sk_common.skc_dport = __builtin_bswap16(53);
    sk.__sk_common.skc_daddr = 0x0100007f;
    return sk;
}
static unsigned char query[] = {
    0x12,0x34,1,0,0,1,0,0,0,0,0,0,
    6,'p','u','b','l','i','c',4,'t','e','s','t',0,0,1,0,1
};
static void init_iov(struct msghdr *msg, struct iovec *iov, size_t count) {
    memset(msg, 0, sizeof(*msg));
    msg->msg_iter.iter_type = kernel_version >= 608 ? 1 : 0;
    msg->msg_iter.type = 5; /* Linux 5.10 ITER_IOVEC | WRITE */
    msg->msg_iter.__iov = iov;
    msg->msg_iter.count = count;
    msg->msg_iter.nr_segs = 1;
}
static void scatter_gather(void) {
    struct {
        unsigned char header[12];
        unsigned char adjacent[17];
    } first = { .adjacent = {6,'s','e','c','r','e','t',4,'t','e','s','t',0,0,1,0,1} };
    memcpy(first.header, query, sizeof(first.header));
    struct iovec iov[2] = {
        { .iov_base = first.header, .iov_len = sizeof(first.header) },
        { .iov_base = query + 12, .iov_len = sizeof(query) - 12 }
    };
    struct msghdr msg; struct sock sk = dns_socket();
    reset(); init_iov(&msg, iov, sizeof(query)); msg.msg_iter.nr_segs = 2;
    segment = first.header; segment_capacity = sizeof(first.header);
    observe_udp_send(&sk, &msg, sizeof(query));
    if (emitted) fprintf(stderr, "scatter payload name bytes: %.6s.test\n", captured.payload + 13);
    check(invalid_reads == 0, "first iov header must not read adjacent secret.test");
    check(!emitted || (captured.payload_length == sizeof(query) &&
                      !memcmp(captured.payload, query, sizeof(query))),
          "scatter must be rejected or gather actual public.test, never fake a complete prefix");
}
static void iterator_cases(void) {
    struct sock sk = dns_socket(); struct msghdr msg;
    unsigned char padded[64] = {0}; memcpy(padded + 7, query, sizeof(query));
    struct iovec iov = { .iov_base = padded, .iov_len = sizeof(query) + 7 };
    const int versions[] = {510, 514, 515, 601, 604, 608};
    for (unsigned i = 0; i < sizeof(versions)/sizeof(versions[0]); i++) {
        kernel_version = versions[i]; reset(); init_iov(&msg, &iov, sizeof(query));
        msg.msg_iter.iov_offset = 7;
        observe_udp_send(&sk, &msg, sizeof(query));
        if (kernel_version == 510) check(!emitted && !user_reads, "legacy type-bit iterator fails closed");
        else check(emitted == 1 && !memcmp(captured.payload, query, sizeof(query)), "IOVEC offset and relocated enum");
        if (kernel_version >= 601) {
            reset(); msg.msg_iter.iter_type = kernel_version >= 608 ? 0 : 6;
            msg.msg_iter.ubuf = padded;
            observe_udp_send(&sk, &msg, sizeof(query));
            check(emitted == 1 && !memcmp(captured.payload, query, sizeof(query)), "UBUF offset and count");
        }
    }
    kernel_version = 608;
    for (int type = 2; type <= 9; type++) {
        reset(); init_iov(&msg, &iov, sizeof(query)); msg.msg_iter.iter_type = type;
        observe_udp_send(&sk, &msg, sizeof(query));
        check(!emitted && !user_reads, "non-user iterator must not read payload");
    }
    reset(); init_iov(&msg, &iov, sizeof(query)); msg.msg_iter.iov_offset = iov.iov_len + 1;
    observe_udp_send(&sk, &msg, sizeof(query)); check(!emitted && !user_reads, "offset past iov_len");
    reset(); init_iov(&msg, &iov, 12);
    observe_udp_send(&sk, &msg, sizeof(query)); check(!emitted && !user_reads, "datagram exceeds iterator count");
    reset(); init_iov(&msg, &iov, sizeof(query)); msg.msg_iter.nr_segs = 0;
    observe_udp_send(&sk, &msg, sizeof(query)); check(!emitted && !user_reads, "zero segments");
    reset(); init_iov(&msg, &iov, sizeof(query));
    msg.msg_iter.iter_type = 0; msg.msg_iter.ubuf = padded;
    msg.msg_iter.iov_offset = ~0ULL;
    observe_udp_send(&sk, &msg, sizeof(query)); check(!emitted && !user_reads, "UBUF pointer overflow");
    unsigned char large[300] = {0}; memcpy(large, query, sizeof(query));
    iov.iov_base = large; iov.iov_len = sizeof(large);
    reset(); init_iov(&msg, &iov, sizeof(large));
    observe_udp_send(&sk, &msg, sizeof(large));
    check(emitted == 1 && captured.total_length == sizeof(large) &&
          captured.payload_length == MAX_PAYLOAD_SIZE, "bounded payload retains original datagram length");
}
static void io_identity(void) {
    const char text[] = "GET /secret.test HTTP/1.1\r\n";
    struct trace_event_raw_sys_enter enter = { .args = {19, (unsigned long)text, sizeof(text)-1} };
    struct trace_event_raw_sys_exit exit = { .ret = sizeof(text)-1 };
    for (int direction = DIRECTION_SEND; direction <= DIRECTION_RECEIVE; direction++) {
        reset(); remember_io(&enter, direction); finish_io(&exit);
        check(!emitted && !user_reads && !have_io, "regular-file read/write lacks event-time socket identity");
        reset(); remember_io(&enter, direction);
        struct sock sk = dns_socket(); remember_socket_context(&sk); finish_io(&exit);
        check(emitted == 1 && captured.protocol == IPPROTO_TCP && captured.family == AF_INET,
              "valid TCP tuple bridge preserved");
    }
    reset(); enter.args[1] = (unsigned long)query; enter.args[2] = sizeof(query); exit.ret = sizeof(query);
    remember_io(&enter, DIRECTION_RECEIVE);
    struct sock sk = dns_socket(); remember_udp_socket_context(&sk); finish_io(&exit);
    check(emitted == 1 && captured.kind == EVENT_KIND_DNS && captured.protocol == IPPROTO_UDP,
          "valid UDP receive tuple preserved");
}
static void explicit_destination(void) {
    struct sock sk = dns_socket(); struct msghdr msg;
    struct iovec iov = { .iov_base = query, .iov_len = sizeof(query) };
    /* Linux sockaddr_in is 16 bytes even though only its first 8 are read. */
    struct { __u16 family, port; __u32 address; unsigned char zero[8]; } name = {
        .family = AF_INET, .port = __builtin_bswap16(5353), .address = 0x0200007f
    };
    reset(); init_iov(&msg, &iov, sizeof(query)); msg.msg_name = &name; msg.msg_namelen = sizeof(name);
    observe_udp_send(&sk, &msg, sizeof(query));
    check(emitted == 1 && captured.destination_port == 5353 &&
          !memcmp(captured.destination_address, &name.address, 4), "explicit peer overrides connected DNS peer");
    reset(); name.port = __builtin_bswap16(8080); observe_udp_send(&sk, &msg, sizeof(query));
    check(!emitted && !user_reads, "explicit non-DNS destination cannot use stale DNS peer");
    name.port = __builtin_bswap16(53);
    for (int length = -1; length < 16; length++) {
        reset(); msg.msg_namelen = length; observe_udp_send(&sk, &msg, sizeof(query));
        check(!emitted && !user_reads, "short or negative explicit sockaddr fails closed");
    }
    reset(); msg.msg_namelen = 16; name.family = AF_INET6; observe_udp_send(&sk, &msg, sizeof(query));
    check(!emitted && !user_reads, "mismatched explicit family fails closed");
    reset(); name.family = AF_INET; unreadable_kernel = &name; observe_udp_send(&sk, &msg, sizeof(query));
    check(!emitted && !user_reads, "unreadable explicit destination fails closed");
    reset(); unreadable_kernel = &msg.msg_name; observe_udp_send(&sk, &msg, sizeof(query));
    check(!emitted && !user_reads, "unreadable msg_name pointer fails closed");
    reset(); unreadable_kernel = &msg.msg_namelen; observe_udp_send(&sk, &msg, sizeof(query));
    check(!emitted && !user_reads, "unreadable msg_namelen fails closed");
    reset(); name.port = 0; sk.__sk_common.skc_num = 53; observe_udp_send(&sk, &msg, sizeof(query));
    check(!emitted && !user_reads, "zero explicit port rejected even from a DNS source port");
    reset(); name.port = __builtin_bswap16(5353); sk = dns_socket(); sk.__sk_common.skc_dport = 0;
    observe_udp_send(&sk, &msg, sizeof(query));
    check(emitted == 1 && captured.destination_port == 5353, "unconnected explicit UDP destination preserved");
    reset(); sk.__sk_common.skc_family = AF_INET6; observe_udp_send(&sk, &msg, sizeof(query));
    check(!emitted && !user_reads, "unsupported dual-stack explicit destination fails closed");
    sk = dns_socket();
    reset(); msg.msg_name = NULL; msg.msg_namelen = 0; observe_udp_send(&sk, &msg, sizeof(query));
    check(emitted == 1 && captured.destination_port == 53, "connected UDP without explicit destination preserved");
}
int main(int argc, char **argv) {
    bpf_probe_read_user = read_user; bpf_probe_read_kernel = read_kernel;
    bpf_map_lookup_elem = lookup; bpf_map_update_elem = update; bpf_map_delete_elem = delete;
    bpf_ringbuf_reserve = reserve; bpf_ringbuf_submit = submit; bpf_ringbuf_discard = discard;
    bpf_get_current_pid_tgid = fake_pid; bpf_ktime_get_ns = fake_time;
    const char *which = argc > 1 ? argv[1] : "all";
    if (!strcmp(which, "scatter") || !strcmp(which, "all")) { scatter_gather(); iterator_cases(); }
    if (!strcmp(which, "identity") || !strcmp(which, "all")) io_identity();
    if (!strcmp(which, "destination") || !strcmp(which, "all")) explicit_destination();
    printf("host production-helper %s: %s (%d failures); NOT Linux kernel execution\n",
           which, failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
