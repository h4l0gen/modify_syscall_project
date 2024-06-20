from bcc import BPF
import ctypes as ct

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define SIGTERM 15

struct key_t {
    char fname[NAME_MAX];
};

struct auth_key_t {
    u32 uid;
};

struct auth_value_t {
    int access_level;
};

BPF_HASH(protected_files, struct key_t, int);
BPF_HASH(authorized_users, struct auth_key_t, struct auth_value_t);

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct key_t key = {};
    struct auth_key_t auth_key = {};
    struct auth_value_t *auth_value;
    
    u32 uid = bpf_get_current_uid_gid();
    auth_key.uid = uid;
    
    bpf_probe_read_user_str(&key.fname, sizeof(key.fname), (void *)filename);
    int *protection_level = protected_files.lookup(&key);
    
    if (protection_level != 0) {
        auth_value = authorized_users.lookup(&auth_key);
        
        if (auth_value) {
            if (auth_value->access_level >= *protection_level) {
                bpf_trace_printk("Authorized user (UID: %d) opening protected file %s\\n", uid, key.fname);
                return 0;
            }
        }
        
        if (uid == 0) {
            bpf_trace_printk("Root user opening protected file %s\\n", key.fname);
            return 0;
        }
        
        bpf_trace_printk("Unauthorized user (UID: %d) attempting to open protected file %s with protection level %d\\n", uid, key.fname, *protection_level);
        
        if (*protection_level == 1) {
            bpf_override_return(ctx, -EACCES);
        } else if (*protection_level > 1) {
            bpf_send_signal(SIGTERM);
        }
    }
    return 0;
}
"""

def add_file(map, file, protection_level):
    key = map.Key()
    key.fname = file.encode()
    value = ct.c_int(protection_level)
    map[key] = value

def add_authorized_user(map, uid, access_level):
    key = map.Key()
    key.uid = uid
    value = map.Leaf()
    value.access_level = access_level
    map[key] = value

def main():
    b = BPF(text=prog)
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    
    protected_files = b.get_table("protected_files")
    authorized_users = b.get_table("authorized_users")
    
    # Read secret files from protected_files.txt
    with open('protected_files.txt', 'r') as f:
        for line in f:
            file, protection_level = line.strip().split(',')
            add_file(protected_files, file, int(protection_level))
    
    # Read authorized users from authorized_users.txt
    with open('authorized_users.txt', 'r') as f:
        for line in f:
            uid, access_level = line.strip().split(',')
            add_authorized_user(authorized_users, int(uid), int(access_level))
    
    try:
        print("Hi, I will protect your files now :)")
        b.trace_print()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
