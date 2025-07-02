from bcc import BPF
import datetime
import socket
import struct
import logging

logging.basicConfig(filename='syscall_trace.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char event[16];
    char path[256];
    u32 ip;
    u16 port;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(&data.event, "OPEN", 4);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(&data.event, "EXEC", 4);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(&data.event, "UNLINK", 6);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    struct sockaddr addr = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event, "CONNECT", 7);

    bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);

    if (addr.sa_family == AF_INET) {
        struct sockaddr_in s = {};
        bpf_probe_read_user(&s, sizeof(s), args->uservaddr);

        data.ip = s.sin_addr.s_addr;
        data.port = ntohs(s.sin_port);
    }

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=program)
print("Tracing syscalls (openat, execve, unlink, connect)... Ctrl-C to exit.\n")

def ip_to_str(ip):
    try:
        return socket.inet_ntoa(struct.pack("I", ip))
    except Exception as e:
        logging.error(f"Error converting IP: {e}")
        return "0.0.0.0"

def print_event(cpu, data, size):
    try:
        event = b["events"].event(data)
        now = datetime.datetime.now().strftime("%H:%M:%S")
        comm = event.comm.decode('utf-8', 'replace')
        evt = event.event.decode('utf-8', 'replace')
        path = event.path.decode('utf-8', 'replace')

        if evt == "CONNECT" and event.ip != 0:
            ip = ip_to_str(event.ip)
            message = f"{now}-tracepoint:syscalls:sys_enter_connect PID: {event.pid:<6} COMM:<{comm}> PATH:<{ip}:{event.port}>"
            print(message)
            logging.info(message)
        else:
            message = f"{now}-tracepoint:syscalls:sys_enter_{evt.lower()} PID: {event.pid:<6} COMM:<{comm}> PATH: {path}"
            print(message)
            logging.info(message)

    except Exception as e:
        logging.error(f"Error processing event: {e}")

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
    except Exception as e:
        logging.error(f"Error in perf_buffer_poll: {e}")
