// SPDX-License-Identifier: GPL-2.0-only
// Bounded TCP SRTT and passive HTTP metadata collection. Kernel events carry
// only timing samples or protocol prefixes needed by the userspace parsers.

typedef unsigned char __u8;
typedef signed int __s32;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define __always_inline inline __attribute__((always_inline))

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_RINGBUF 27

#define BPF_ANY 0

#define BPF_FUNC_MAP_LOOKUP_ELEM 1
#define BPF_FUNC_MAP_UPDATE_ELEM 2
#define BPF_FUNC_MAP_DELETE_ELEM 3
#define BPF_FUNC_KTIME_GET_NS 5
#define BPF_FUNC_GET_CURRENT_PID_TGID 14
#define BPF_FUNC_PROBE_READ_USER 112
#define BPF_FUNC_PROBE_READ_KERNEL 113
#define BPF_FUNC_RINGBUF_OUTPUT 130
#define BPF_FUNC_RINGBUF_RESERVE 131
#define BPF_FUNC_RINGBUF_SUBMIT 132
#define BPF_FUNC_RINGBUF_DISCARD 133

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7

#define EVENT_KIND_CONNECT 1
#define EVENT_KIND_TCP_SAMPLE 2
#define EVENT_KIND_L7_FRAGMENT 3

#define EVENT_SOURCE_KERNEL_PLAINTEXT 1
#define EVENT_SOURCE_OPENSSL 2

#define DIRECTION_SEND 1
#define DIRECTION_RECEIVE 2

#define MAX_PAYLOAD_SIZE 256
#define CLASSIFIER_BYTES 32
#define MAX_HTTP1_LINE MAX_PAYLOAD_SIZE
#define HTTP2_MAX_FRAME_TYPE 0x09
#define HTTP2_MAX_FRAME_LENGTH (1 << 20)
#define SRTT_EMIT_INTERVAL_NS 5000000000ULL
#define SRTT_MIN_INTERVAL_NS 100000000ULL
#define SRTT_MIN_DELTA_US 1000
#define BIO_C_SET_FD 104
#define DROP_RINGBUF_RESERVE 0
#define DROP_RINGBUF_OUTPUT 1
#define DROP_PAYLOAD_READ 2
#define DROP_REASON_COUNT 3

struct trace_entry {
	__u16 type;
	__u8 flags;
	__u8 preempt_count;
	__u32 pid;
};

struct trace_event_raw_inet_sock_set_state {
	struct trace_entry common;
	const void *skaddr;
	__u32 oldstate;
	__u32 newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter {
	struct trace_entry common;
	long id;
	unsigned long args[6];
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_exit {
	struct trace_entry common;
	long id;
	long ret;
} __attribute__((preserve_access_index));

struct in6_addr___local {
	__u8 bytes[16];
};

struct sock_common {
	union {
		struct {
			__u32 skc_daddr;
			__u32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__u16 skc_dport;
			__u16 skc_num;
		};
	};
	__u16 skc_family;
	struct in6_addr___local skc_v6_daddr;
	struct in6_addr___local skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u32 srtt_us;
	__u32 mdev_us;
} __attribute__((preserve_access_index));

// Stable 360-byte ring-buffer ABI mirrored by collector.wireEvent.
struct network_event {
	__u64 timestamp_ns;
	__u64 connection_id;
	__u32 pid;
	__u32 tid;
	__u32 old_state;
	__u32 new_state;
	__u32 srtt_us;
	__u32 rttvar_us;
	__u32 total_length;
	__s32 fd;
	__u16 family;
	__u16 protocol;
	__u16 source_port;
	__u16 destination_port;
	__u16 payload_length;
	__u8 kind;
	__u8 source;
	__u8 direction;
	__u8 flags;
	__u16 reserved16;
	__u8 source_address[16];
	__u8 destination_address[16];
	__u8 payload[MAX_PAYLOAD_SIZE];
	__u64 reserved;
};

_Static_assert(sizeof(struct network_event) == 360, "network_event ABI must be 360 bytes");

struct socket_tuple {
	__u16 family;
	__u16 protocol;
	__u16 local_port;
	__u16 remote_port;
	__u8 local_address[16];
	__u8 remote_address[16];
};

struct io_call {
	__u64 buffer;
	__u32 requested;
	__s32 fd;
	__u8 direction;
	__u8 reserved[7];
	struct socket_tuple tuple;
};

struct ssl_key {
	__u32 pid;
	__u32 reserved;
	__u64 context;
};

struct protocol_key {
	__u32 pid;
	__s32 fd;
	__u8 source;
	__u8 reserved[3];
};

struct ssl_call {
	__u64 context;
	__u64 buffer;
	__u64 size_output;
	__s32 fd;
	__u32 reserved;
	struct socket_tuple tuple;
};

struct srtt_sample_state {
	__u64 emitted_at_ns;
	__u32 srtt_us;
	__u32 reserved;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROP_REASON_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} drop_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct io_call);
} io_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct ssl_key);
	__type(value, __s32);
} ssl_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __s32);
} bio_new_socket_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct ssl_key);
	__type(value, __s32);
} bio_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct protocol_key);
	__type(value, __u8);
} http2_connections SEC(".maps");

#define DECLARE_SSL_CALL_MAP(name) \
	struct { \
		__uint(type, BPF_MAP_TYPE_LRU_HASH); \
		__uint(max_entries, 16384); \
		__type(key, __u64); \
		__type(value, struct ssl_call); \
	} name SEC(".maps")

DECLARE_SSL_CALL_MAP(ssl_read_calls);
DECLARE_SSL_CALL_MAP(ssl_write_calls);
DECLARE_SSL_CALL_MAP(ssl_read_ex_calls);
DECLARE_SSL_CALL_MAP(ssl_write_ex_calls);

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct srtt_sample_state);
} srtt_samples SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_MAP_LOOKUP_ELEM;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
	(void *)BPF_FUNC_MAP_UPDATE_ELEM;
static long (*bpf_map_delete_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_MAP_DELETE_ELEM;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_KTIME_GET_NS;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_GET_CURRENT_PID_TGID;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_PROBE_READ_USER;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_PROBE_READ_KERNEL;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_RINGBUF_OUTPUT;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_RINGBUF_RESERVE;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_RINGBUF_SUBMIT;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)BPF_FUNC_RINGBUF_DISCARD;

static __always_inline void count_drop(__u32 reason) {
	__u64 *counter = bpf_map_lookup_elem(&drop_counters, &reason);
	if (counter != 0)
		*counter += 1;
}

static __always_inline void output_event(struct network_event *event) {
	if (bpf_ringbuf_output(&events, event, sizeof(*event), 0) < 0)
		count_drop(DROP_RINGBUF_OUTPUT);
}

#define bpf_core_read(dst, size, source) \
	bpf_probe_read_kernel((dst), (size), \
		(const void *)__builtin_preserve_access_index(source))

static __always_inline __u16 network_to_host_port(__u16 value) {
	return __builtin_bswap16(value);
}

static __always_inline void set_identity(struct network_event *event) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = (__u32)(pid_tgid >> 32);
	event->tid = (__u32)pid_tgid;
}

static __always_inline int read_socket_tuple(struct socket_tuple *tuple, struct sock *sk) {
	__u16 family = 0;
	__u16 local_port = 0;
	__u16 remote_port_network = 0;
	if (bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family) < 0)
		return -1;
	if (family != AF_INET && family != AF_INET6)
		return -1;
	if (bpf_core_read(&local_port, sizeof(local_port), &sk->__sk_common.skc_num) < 0)
		return -1;
	if (bpf_core_read(&remote_port_network, sizeof(remote_port_network), &sk->__sk_common.skc_dport) < 0)
		return -1;

	tuple->family = family;
	tuple->protocol = IPPROTO_TCP;
	tuple->local_port = local_port;
	tuple->remote_port = network_to_host_port(remote_port_network);

	if (family == AF_INET) {
		__u32 local_address = 0;
		__u32 remote_address = 0;
		if (bpf_core_read(&local_address, sizeof(local_address), &sk->__sk_common.skc_rcv_saddr) < 0)
			return -1;
		if (bpf_core_read(&remote_address, sizeof(remote_address), &sk->__sk_common.skc_daddr) < 0)
			return -1;
		__builtin_memcpy(tuple->local_address, &local_address, 4);
		__builtin_memcpy(tuple->remote_address, &remote_address, 4);
		return 0;
	}

	struct in6_addr___local local_address = {};
	struct in6_addr___local remote_address = {};
	if (bpf_core_read(&local_address, sizeof(local_address), &sk->__sk_common.skc_v6_rcv_saddr) < 0)
		return -1;
	if (bpf_core_read(&remote_address, sizeof(remote_address), &sk->__sk_common.skc_v6_daddr) < 0)
		return -1;
	__builtin_memcpy(tuple->local_address, &local_address, 16);
	__builtin_memcpy(tuple->remote_address, &remote_address, 16);
	return 0;
}

static __always_inline int apply_socket_tuple(struct network_event *event, const struct socket_tuple *tuple,
	__u8 direction) {
	if (tuple->family != AF_INET && tuple->family != AF_INET6)
		return -1;
	event->family = tuple->family;
	event->protocol = tuple->protocol;
	event->direction = direction;
	if (direction == DIRECTION_SEND) {
		event->source_port = tuple->local_port;
		event->destination_port = tuple->remote_port;
		__builtin_memcpy(event->source_address, tuple->local_address, 16);
		__builtin_memcpy(event->destination_address, tuple->remote_address, 16);
	} else {
		event->source_port = tuple->remote_port;
		event->destination_port = tuple->local_port;
		__builtin_memcpy(event->source_address, tuple->remote_address, 16);
		__builtin_memcpy(event->destination_address, tuple->local_address, 16);
	}
	return 0;
}

static __always_inline int fill_socket_tuple(struct network_event *event, struct sock *sk, __u8 direction) {
	struct socket_tuple tuple = {};
	if (read_socket_tuple(&tuple, sk) < 0)
		return -1;
	return apply_socket_tuple(event, &tuple, direction);
}

static __always_inline int starts_http1(const __u8 *data, __u32 length) {
	if (length >= 7 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' &&
		data[3] == 'P' && data[4] == '/' && data[5] == '1' && data[6] == '.')
		return 1;
	if (length >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ')
		return 1;
	if (length >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ')
		return 1;
	if (length >= 4 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ')
		return 1;
	if (length >= 7 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ')
		return 1;
	if (length >= 5 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ')
		return 1;
	if (length >= 8 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' ')
		return 1;
	if (length >= 6 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && data[4] == 'H' && data[5] == ' ')
		return 1;
	if (length >= 6 && data[0] == 'T' && data[1] == 'R' && data[2] == 'A' && data[3] == 'C' && data[4] == 'E' && data[5] == ' ')
		return 1;
	if (length >= 8 && data[0] == 'C' && data[1] == 'O' && data[2] == 'N' && data[3] == 'N' && data[4] == 'E' && data[5] == 'C' && data[6] == 'T' && data[7] == ' ')
		return 1;
	return 0;
}

static __always_inline int starts_http2_preface(const __u8 *data, __u32 length) {
	return length >= 14 && data[0] == 'P' && data[1] == 'R' && data[2] == 'I' && data[3] == ' ' &&
		data[4] == '*' && data[5] == ' ' && data[6] == 'H' && data[7] == 'T' && data[8] == 'T' &&
		data[9] == 'P' && data[10] == '/' && data[11] == '2' && data[12] == '.' && data[13] == '0';
}


static __always_inline __u32 http1_copy_length(const __u8 *data, __u32 total_length) {
	__u32 limit = total_length;
	if (limit > CLASSIFIER_BYTES)
		limit = CLASSIFIER_BYTES;
#pragma unroll
	for (int index = 0; index < CLASSIFIER_BYTES - 1; index++) {
		if ((__u32)(index + 1) >= limit)
			break;
		if (data[index] == '\r' && data[index + 1] == '\n')
			return index + 2;
	}
	return total_length > MAX_HTTP1_LINE ? MAX_HTTP1_LINE : total_length;
}

static __always_inline int classify_user_buffer(__s32 fd, __u8 source, const void *buffer,
	__u32 length, __u32 *copy_length) {
	if (length == 0)
		return 0;
	__u8 data[CLASSIFIER_BYTES] = {};
	__u32 inspected = length > CLASSIFIER_BYTES ? CLASSIFIER_BYTES : length;
	if (bpf_probe_read_user(data, inspected, buffer) < 0)
		return 0;
	if (starts_http1(data, inspected)) {
		*copy_length = http1_copy_length(data, length);
		return 1;
	}
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct protocol_key key = {
		.pid = (__u32)(pid_tgid >> 32),
		.fd = fd,
		.source = source,
	};
	if (starts_http2_preface(data, inspected)) {
		__u8 active = 1;
		bpf_map_update_elem(&http2_connections, &key, &active, BPF_ANY);
		*copy_length = length > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : length;
		return 2;
	}
	__u8 *active = bpf_map_lookup_elem(&http2_connections, &key);
	if (active != 0 && inspected >= 9) {
		__u32 frame_length = ((__u32)data[0] << 16) | ((__u32)data[1] << 8) | (__u32)data[2];
		if (data[3] != 0 && data[3] <= HTTP2_MAX_FRAME_TYPE && frame_length <= HTTP2_MAX_FRAME_LENGTH) {
			*copy_length = length > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : length;
			return 2;
		}
	}
	return 0;
}

static __always_inline int emit_user_fragment(__s32 fd, const void *buffer, __u32 length,
	__u8 direction, __u8 source, __u64 connection_id, const struct socket_tuple *tuple) {
	__u32 copy_length = 0;
	if (fd < 0 || classify_user_buffer(fd, source, buffer, length, &copy_length) == 0)
		return 0;
	if (copy_length == 0 || copy_length > MAX_PAYLOAD_SIZE)
		return 0;

	struct network_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event == 0) {
		count_drop(DROP_RINGBUF_RESERVE);
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	set_identity(event);
	event->connection_id = connection_id;
	event->kind = EVENT_KIND_L7_FRAGMENT;
	event->source = source;
	event->direction = direction;
	event->fd = fd;
	event->total_length = length;
	event->payload_length = copy_length;
	if (tuple != 0)
		apply_socket_tuple(event, tuple, direction);
	if (bpf_probe_read_user(event->payload, copy_length, buffer) < 0) {
		count_drop(DROP_PAYLOAD_READ);
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int remember_io(struct trace_event_raw_sys_enter *ctx, __u8 direction) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct io_call call = {};
	unsigned long fd = 0;
	unsigned long buffer = 0;
	unsigned long requested = 0;
	if (bpf_core_read(&fd, sizeof(fd), &ctx->args[0]) < 0 ||
		bpf_core_read(&buffer, sizeof(buffer), &ctx->args[1]) < 0 ||
		bpf_core_read(&requested, sizeof(requested), &ctx->args[2]) < 0)
		return 0;
	call.fd = (__s32)fd;
	call.buffer = buffer;
	call.requested = requested > 0xffffffffUL ? 0xffffffffU : (__u32)requested;
	call.direction = direction;
	bpf_map_update_elem(&io_calls, &pid_tgid, &call, BPF_ANY);
	return 0;
}

static __always_inline int finish_io(struct trace_event_raw_sys_exit *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct io_call *call = bpf_map_lookup_elem(&io_calls, &pid_tgid);
	if (call == 0)
		return 0;
	struct io_call copy = *call;
	bpf_map_delete_elem(&io_calls, &pid_tgid);
	long result = 0;
	if (bpf_core_read(&result, sizeof(result), &ctx->ret) < 0 || result <= 0)
		return 0;
	if (copy.tuple.family != AF_INET && copy.tuple.family != AF_INET6)
		return 0;
	__u32 length = (__u64)result > copy.requested ? copy.requested : (__u32)result;
	return emit_user_fragment(copy.fd, (const void *)copy.buffer, length, copy.direction,
		EVENT_SOURCE_KERNEL_PLAINTEXT, 0, &copy.tuple);
}

static __always_inline void remember_socket_context(struct sock *sk) {
	struct socket_tuple tuple = {};
	if (read_socket_tuple(&tuple, sk) < 0)
		return;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct io_call *io = bpf_map_lookup_elem(&io_calls, &pid_tgid);
	if (io != 0)
		io->tuple = tuple;
	struct ssl_call *ssl = bpf_map_lookup_elem(&ssl_read_calls, &pid_tgid);
	if (ssl != 0)
		ssl->tuple = tuple;
	ssl = bpf_map_lookup_elem(&ssl_write_calls, &pid_tgid);
	if (ssl != 0)
		ssl->tuple = tuple;
	ssl = bpf_map_lookup_elem(&ssl_read_ex_calls, &pid_tgid);
	if (ssl != 0)
		ssl->tuple = tuple;
	ssl = bpf_map_lookup_elem(&ssl_write_ex_calls, &pid_tgid);
	if (ssl != 0)
		ssl->tuple = tuple;
}

static __always_inline int maybe_emit_srtt(struct sock *sk, __u8 direction) {
	struct tcp_sock *tcp = (struct tcp_sock *)sk;
	__u32 raw_srtt = 0;
	__u32 raw_mdev = 0;
	if (bpf_core_read(&raw_srtt, sizeof(raw_srtt), &tcp->srtt_us) < 0 || raw_srtt == 0)
		return 0;
	bpf_core_read(&raw_mdev, sizeof(raw_mdev), &tcp->mdev_us);
	__u32 srtt = raw_srtt >> 3;
	__u32 rttvar = raw_mdev >> 2;
	if (srtt == 0)
		return 0;

	__u64 socket_key = (__u64)sk;
	__u64 now = bpf_ktime_get_ns();
	struct srtt_sample_state *previous = bpf_map_lookup_elem(&srtt_samples, &socket_key);
	if (previous != 0) {
		__u64 elapsed = now - previous->emitted_at_ns;
		if (elapsed < SRTT_MIN_INTERVAL_NS)
			return 0;
		__u32 delta = previous->srtt_us > srtt ? previous->srtt_us - srtt : srtt - previous->srtt_us;
		__u32 relative_threshold = previous->srtt_us / 10;
		if (relative_threshold < SRTT_MIN_DELTA_US)
			relative_threshold = SRTT_MIN_DELTA_US;
		if (elapsed < SRTT_EMIT_INTERVAL_NS && delta < relative_threshold)
			return 0;
	}

	struct network_event event = {};
	set_identity(&event);
	event.kind = EVENT_KIND_TCP_SAMPLE;
	event.source = EVENT_SOURCE_KERNEL_PLAINTEXT;
	event.srtt_us = srtt;
	event.rttvar_us = rttvar;
	if (fill_socket_tuple(&event, sk, direction) < 0)
		return 0;
	output_event(&event);

	struct srtt_sample_state state = {.emitted_at_ns = now, .srtt_us = srtt};
	bpf_map_update_elem(&srtt_samples, &socket_key, &state, BPF_ANY);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int observe_tcp_connect(struct trace_event_raw_inet_sock_set_state *ctx) {
	__u32 oldstate = 0;
	__u32 newstate = 0;
	__u16 family = 0;
	__u16 protocol = 0;
	if (bpf_core_read(&protocol, sizeof(protocol), &ctx->protocol) < 0 || protocol != IPPROTO_TCP)
		return 0;
	if (bpf_core_read(&oldstate, sizeof(oldstate), &ctx->oldstate) < 0 ||
		bpf_core_read(&newstate, sizeof(newstate), &ctx->newstate) < 0)
		return 0;
	if (newstate == TCP_CLOSE) {
		const void *socket = 0;
		if (bpf_core_read(&socket, sizeof(socket), &ctx->skaddr) == 0) {
			__u64 socket_key = (__u64)socket;
			bpf_map_delete_elem(&srtt_samples, &socket_key);
		}
	}
	if (oldstate != TCP_SYN_SENT || newstate != TCP_ESTABLISHED)
		return 0;
	if (bpf_core_read(&family, sizeof(family), &ctx->family) < 0 ||
		(family != AF_INET && family != AF_INET6))
		return 0;

	struct network_event event = {};
	set_identity(&event);
	event.kind = EVENT_KIND_CONNECT;
	event.source = EVENT_SOURCE_KERNEL_PLAINTEXT;
	event.direction = DIRECTION_SEND;
	event.old_state = oldstate;
	event.new_state = newstate;
	event.family = family;
	event.protocol = protocol;
	bpf_core_read(&event.source_port, sizeof(event.source_port), &ctx->sport);
	bpf_core_read(&event.destination_port, sizeof(event.destination_port), &ctx->dport);
	if (family == AF_INET) {
		if (bpf_core_read(event.source_address, 4, &ctx->saddr) < 0 ||
			bpf_core_read(event.destination_address, 4, &ctx->daddr) < 0)
			return 0;
	} else {
		if (bpf_core_read(event.source_address, 16, &ctx->saddr_v6) < 0 ||
			bpf_core_read(event.destination_address, 16, &ctx->daddr_v6) < 0)
			return 0;
	}
	output_event(&event);
	return 0;
}

SEC("fentry/tcp_sendmsg")
int observe_tcp_sendmsg(__u64 *ctx) {
	struct sock *sk = (struct sock *)ctx[0];
	remember_socket_context(sk);
	return maybe_emit_srtt(sk, DIRECTION_SEND);
}

SEC("fentry/tcp_recvmsg")
int observe_tcp_recvmsg(__u64 *ctx) {
	struct sock *sk = (struct sock *)ctx[0];
	remember_socket_context(sk);
	return maybe_emit_srtt(sk, DIRECTION_RECEIVE);
}

#define DECLARE_IO_ENTER(name, section, direction_value) \
	SEC(section) int name(struct trace_event_raw_sys_enter *ctx) { \
		return remember_io(ctx, direction_value); \
	}

#define DECLARE_IO_EXIT(name, section) \
	SEC(section) int name(struct trace_event_raw_sys_exit *ctx) { \
		return finish_io(ctx); \
	}

DECLARE_IO_ENTER(observe_enter_read, "tracepoint/syscalls/sys_enter_read", DIRECTION_RECEIVE);
DECLARE_IO_EXIT(observe_exit_read, "tracepoint/syscalls/sys_exit_read");
DECLARE_IO_ENTER(observe_enter_write, "tracepoint/syscalls/sys_enter_write", DIRECTION_SEND);
DECLARE_IO_EXIT(observe_exit_write, "tracepoint/syscalls/sys_exit_write");
DECLARE_IO_ENTER(observe_enter_recvfrom, "tracepoint/syscalls/sys_enter_recvfrom", DIRECTION_RECEIVE);
DECLARE_IO_EXIT(observe_exit_recvfrom, "tracepoint/syscalls/sys_exit_recvfrom");
DECLARE_IO_ENTER(observe_enter_sendto, "tracepoint/syscalls/sys_enter_sendto", DIRECTION_SEND);
DECLARE_IO_EXIT(observe_exit_sendto, "tracepoint/syscalls/sys_exit_sendto");

SEC("tracepoint/syscalls/sys_enter_close")
int observe_enter_close(struct trace_event_raw_sys_enter *ctx) {
	unsigned long fd = 0;
	if (bpf_core_read(&fd, sizeof(fd), &ctx->args[0]) < 0)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct protocol_key key = {
		.pid = (__u32)(pid_tgid >> 32),
		.fd = (__s32)fd,
		.source = EVENT_SOURCE_KERNEL_PLAINTEXT,
	};
	bpf_map_delete_elem(&http2_connections, &key);
	key.source = EVENT_SOURCE_OPENSSL;
	bpf_map_delete_elem(&http2_connections, &key);
	return 0;
}

struct pt_regs_x86 {
	__u64 r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	__u64 ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};

struct pt_regs_arm64 {
	__u64 regs[31];
	__u64 sp, pc, pstate;
};

static __always_inline struct ssl_key make_ssl_key(__u64 context) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_key key = {.pid = (__u32)(pid_tgid >> 32), .context = context};
	return key;
}

static __always_inline int remember_ssl_fd(__u64 context, __s32 fd) {
	if (context == 0 || fd < 0)
		return 0;
	struct ssl_key key = make_ssl_key(context);
	bpf_map_update_elem(&ssl_fds, &key, &fd, BPF_ANY);
	return 0;
}

static __always_inline int remember_bio_new_socket(__s32 fd) {
	if (fd < 0)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&bio_new_socket_calls, &pid_tgid, &fd, BPF_ANY);
	return 0;
}

static __always_inline int remember_bio_fd(__u64 bio, __s32 fd) {
	if (bio == 0 || fd < 0)
		return 0;
	struct ssl_key key = make_ssl_key(bio);
	bpf_map_update_elem(&bio_fds, &key, &fd, BPF_ANY);
	return 0;
}

static __always_inline int finish_bio_new_socket(__u64 bio) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 *fd = bpf_map_lookup_elem(&bio_new_socket_calls, &pid_tgid);
	if (fd == 0)
		return 0;
	__s32 copy = *fd;
	bpf_map_delete_elem(&bio_new_socket_calls, &pid_tgid);
	return remember_bio_fd(bio, copy);
}

static __always_inline int remember_bio_int_ctrl(__u64 bio, __u64 command, __s32 fd) {
	if (command != BIO_C_SET_FD)
		return 0;
	return remember_bio_fd(bio, fd);
}

static __always_inline int remember_ssl_bio(__u64 context, __u64 read_bio, __u64 write_bio) {
	struct ssl_key read_key = make_ssl_key(read_bio);
	__s32 *fd = bpf_map_lookup_elem(&bio_fds, &read_key);
	if (fd == 0 && write_bio != read_bio) {
		struct ssl_key write_key = make_ssl_key(write_bio);
		fd = bpf_map_lookup_elem(&bio_fds, &write_key);
	}
	if (fd != 0) {
		__s32 copy = *fd;
		remember_ssl_fd(context, copy);
	}
	bpf_map_delete_elem(&bio_fds, &read_key);
	if (write_bio != read_bio) {
		struct ssl_key write_key = make_ssl_key(write_bio);
		bpf_map_delete_elem(&bio_fds, &write_key);
	}
	return 0;
}

static __always_inline int forget_bio(__u64 bio) {
	struct ssl_key key = make_ssl_key(bio);
	bpf_map_delete_elem(&bio_fds, &key);
	return 0;
}

static __always_inline int forget_ssl_fd(__u64 context) {
	struct ssl_key key = make_ssl_key(context);
	bpf_map_delete_elem(&ssl_fds, &key);
	return 0;
}

static __always_inline int remember_ssl_call(void *map, __u64 context, __u64 buffer, __u64 size_output) {
	struct ssl_key key = make_ssl_key(context);
	__s32 *fd = bpf_map_lookup_elem(&ssl_fds, &key);
	if (fd == 0)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_call call = {.context = context, .buffer = buffer, .size_output = size_output, .fd = *fd};
	bpf_map_update_elem(map, &pid_tgid, &call, BPF_ANY);
	return 0;
}

static __always_inline int finish_ssl_call(void *map, long result, int extended, __u8 direction) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct ssl_call *call = bpf_map_lookup_elem(map, &pid_tgid);
	if (call == 0)
		return 0;
	struct ssl_call copy = *call;
	bpf_map_delete_elem(map, &pid_tgid);
	__u64 length = 0;
	if (extended) {
		if (result != 1 || copy.size_output == 0 ||
			bpf_probe_read_user(&length, sizeof(length), (const void *)copy.size_output) < 0)
			return 0;
	} else {
		if (result <= 0)
			return 0;
		length = result;
	}
	if (length == 0)
		return 0;
	if (length > 0xffffffffULL)
		length = 0xffffffffULL;
	return emit_user_fragment(copy.fd, (const void *)copy.buffer, (__u32)length,
		direction, EVENT_SOURCE_OPENSSL, copy.context,
		copy.tuple.family == AF_INET || copy.tuple.family == AF_INET6 ? &copy.tuple : 0);
}

#define X86_ARG1(ctx) (((struct pt_regs_x86 *)(ctx))->di)
#define X86_ARG2(ctx) (((struct pt_regs_x86 *)(ctx))->si)
#define X86_ARG3(ctx) (((struct pt_regs_x86 *)(ctx))->dx)
#define X86_ARG4(ctx) (((struct pt_regs_x86 *)(ctx))->cx)
#define X86_RETURN(ctx) (((struct pt_regs_x86 *)(ctx))->ax)
#define ARM64_ARG1(ctx) (((struct pt_regs_arm64 *)(ctx))->regs[0])
#define ARM64_ARG2(ctx) (((struct pt_regs_arm64 *)(ctx))->regs[1])
#define ARM64_ARG3(ctx) (((struct pt_regs_arm64 *)(ctx))->regs[2])
#define ARM64_ARG4(ctx) (((struct pt_regs_arm64 *)(ctx))->regs[3])
#define ARM64_RETURN(ctx) (((struct pt_regs_arm64 *)(ctx))->regs[0])

#define DECLARE_SSL_SET_FD(name, arg1, arg2) \
	SEC("uprobe/SSL_set_fd") int name(void *ctx) { return remember_ssl_fd(arg1(ctx), (__s32)arg2(ctx)); }
#define DECLARE_SSL_FREE(name, arg1) \
	SEC("uprobe/SSL_free") int name(void *ctx) { return forget_ssl_fd(arg1(ctx)); }
#define DECLARE_BIO_NEW_SOCKET(name, arg1) \
	SEC("uprobe/BIO_new_socket") int name(void *ctx) { return remember_bio_new_socket((__s32)arg1(ctx)); }
#define DECLARE_BIO_NEW_SOCKET_RETURN(name, ret) \
	SEC("uretprobe/BIO_new_socket") int name(void *ctx) { return finish_bio_new_socket(ret(ctx)); }
#define DECLARE_BIO_INT_CTRL(name, arg1, arg2, arg4) \
	SEC("uprobe/BIO_int_ctrl") int name(void *ctx) { return remember_bio_int_ctrl(arg1(ctx), arg2(ctx), (__s32)arg4(ctx)); }
#define DECLARE_SSL_SET_BIO(name, arg1, arg2, arg3) \
	SEC("uprobe/SSL_set_bio") int name(void *ctx) { return remember_ssl_bio(arg1(ctx), arg2(ctx), arg3(ctx)); }
#define DECLARE_BIO_FREE(name, arg1) \
	SEC("uprobe/BIO_free") int name(void *ctx) { return forget_bio(arg1(ctx)); }
#define DECLARE_SSL_ENTER(name, section, map, arg1, arg2) \
	SEC(section) int name(void *ctx) { return remember_ssl_call(&map, arg1(ctx), arg2(ctx), 0); }
#define DECLARE_SSL_EX_ENTER(name, section, map, arg1, arg2, arg4) \
	SEC(section) int name(void *ctx) { return remember_ssl_call(&map, arg1(ctx), arg2(ctx), arg4(ctx)); }
#define DECLARE_SSL_EXIT(name, section, map, ret, extended, direction_value) \
	SEC(section) int name(void *ctx) { return finish_ssl_call(&map, (long)ret(ctx), extended, direction_value); }

DECLARE_SSL_SET_FD(observe_ssl_set_fd_x86, X86_ARG1, X86_ARG2);
DECLARE_SSL_FREE(observe_ssl_free_x86, X86_ARG1);
DECLARE_BIO_NEW_SOCKET(observe_bio_new_socket_x86, X86_ARG1);
DECLARE_BIO_NEW_SOCKET_RETURN(observe_bio_new_socket_return_x86, X86_RETURN);
DECLARE_BIO_INT_CTRL(observe_bio_int_ctrl_x86, X86_ARG1, X86_ARG2, X86_ARG4);
DECLARE_SSL_SET_BIO(observe_ssl_set_bio_x86, X86_ARG1, X86_ARG2, X86_ARG3);
DECLARE_BIO_FREE(observe_bio_free_x86, X86_ARG1);
DECLARE_SSL_ENTER(observe_ssl_read_x86, "uprobe/SSL_read", ssl_read_calls, X86_ARG1, X86_ARG2);
DECLARE_SSL_EXIT(observe_ssl_read_return_x86, "uretprobe/SSL_read", ssl_read_calls, X86_RETURN, 0, DIRECTION_RECEIVE);
DECLARE_SSL_ENTER(observe_ssl_write_x86, "uprobe/SSL_write", ssl_write_calls, X86_ARG1, X86_ARG2);
DECLARE_SSL_EXIT(observe_ssl_write_return_x86, "uretprobe/SSL_write", ssl_write_calls, X86_RETURN, 0, DIRECTION_SEND);
DECLARE_SSL_EX_ENTER(observe_ssl_read_ex_x86, "uprobe/SSL_read_ex", ssl_read_ex_calls, X86_ARG1, X86_ARG2, X86_ARG4);
DECLARE_SSL_EXIT(observe_ssl_read_ex_return_x86, "uretprobe/SSL_read_ex", ssl_read_ex_calls, X86_RETURN, 1, DIRECTION_RECEIVE);
DECLARE_SSL_EX_ENTER(observe_ssl_write_ex_x86, "uprobe/SSL_write_ex", ssl_write_ex_calls, X86_ARG1, X86_ARG2, X86_ARG4);
DECLARE_SSL_EXIT(observe_ssl_write_ex_return_x86, "uretprobe/SSL_write_ex", ssl_write_ex_calls, X86_RETURN, 1, DIRECTION_SEND);

DECLARE_SSL_SET_FD(observe_ssl_set_fd_arm64, ARM64_ARG1, ARM64_ARG2);
DECLARE_SSL_FREE(observe_ssl_free_arm64, ARM64_ARG1);
DECLARE_BIO_NEW_SOCKET(observe_bio_new_socket_arm64, ARM64_ARG1);
DECLARE_BIO_NEW_SOCKET_RETURN(observe_bio_new_socket_return_arm64, ARM64_RETURN);
DECLARE_BIO_INT_CTRL(observe_bio_int_ctrl_arm64, ARM64_ARG1, ARM64_ARG2, ARM64_ARG4);
DECLARE_SSL_SET_BIO(observe_ssl_set_bio_arm64, ARM64_ARG1, ARM64_ARG2, ARM64_ARG3);
DECLARE_BIO_FREE(observe_bio_free_arm64, ARM64_ARG1);
DECLARE_SSL_ENTER(observe_ssl_read_arm64, "uprobe/SSL_read", ssl_read_calls, ARM64_ARG1, ARM64_ARG2);
DECLARE_SSL_EXIT(observe_ssl_read_return_arm64, "uretprobe/SSL_read", ssl_read_calls, ARM64_RETURN, 0, DIRECTION_RECEIVE);
DECLARE_SSL_ENTER(observe_ssl_write_arm64, "uprobe/SSL_write", ssl_write_calls, ARM64_ARG1, ARM64_ARG2);
DECLARE_SSL_EXIT(observe_ssl_write_return_arm64, "uretprobe/SSL_write", ssl_write_calls, ARM64_RETURN, 0, DIRECTION_SEND);
DECLARE_SSL_EX_ENTER(observe_ssl_read_ex_arm64, "uprobe/SSL_read_ex", ssl_read_ex_calls, ARM64_ARG1, ARM64_ARG2, ARM64_ARG4);
DECLARE_SSL_EXIT(observe_ssl_read_ex_return_arm64, "uretprobe/SSL_read_ex", ssl_read_ex_calls, ARM64_RETURN, 1, DIRECTION_RECEIVE);
DECLARE_SSL_EX_ENTER(observe_ssl_write_ex_arm64, "uprobe/SSL_write_ex", ssl_write_ex_calls, ARM64_ARG1, ARM64_ARG2, ARM64_ARG4);
DECLARE_SSL_EXIT(observe_ssl_write_ex_return_arm64, "uretprobe/SSL_write_ex", ssl_write_ex_calls, ARM64_RETURN, 1, DIRECTION_SEND);

char LICENSE[] SEC("license") = "GPL";