from bcc import BPF
import ctypes as ct

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#define SIGTERM 15
struct key_t {
    char fname[NAME_MAX];
};
BPF_HASH(secure_files, struct key_t, int);
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct key_t key = {};
    u32 uid = bpf_get_current_uid_gid();
    bpf_probe_read_user_str(&key.fname, sizeof(key.fname), (void *)filename);
    int *security_level = secure_files.lookup(&key);
    if (security_level != 0) {
        if (uid == 0) {
            bpf_trace_printk("Root user opening secret file %s \\n", key.fname);
            return 0;
        }
        bpf_trace_printk("Non-root user attempt to open secure file %s with security level %d \\n", key.fname, *security_level );
        if (*security_level == 1) {
            bpf_override_return(ctx, -EACCES);
        } else if (*security_level > 1) {
            bpf_send_signal(SIGTERM);
        }
    }
    return 0;
}
"""

def add_file(map, file, security_level):
    key = map.Key()
    key.fname = file.encode()
    value = ct.c_int(security_level)
    map[key] = value

def main():
    b = BPF(text=prog)
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    
    secure_files = b.get_table("secure_files")
    
    # Read secure files from secure_files.txt
    with open('secure_files.txt', 'r') as f:
        for line in f:
            file, security_level = line.strip().split(',')
            add_file(secure_files, file, int(security_level))
    
    try:
        print("Attaching kprobe to sys_openat... Press Ctrl+C to exit.")
        b.trace_print()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
