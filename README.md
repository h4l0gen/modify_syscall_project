# modify_openat_syscall

## Description

This program will help users to prevent non-root users to read their protected files. User just need to add those file's `Absolute path` and `Relative paths` to `protected_files.txt` along with their `protection levels`. Protection level decide which action they want if non-root user try to access those file.
- protection level 1: This will show `Permission denied` to non-root users.
- protection level 2: This will `terminate` the process which trying to access these files.

Along with this, there may be a case when user wants to give access to some non-root users to read protected files, in that case, user can also specify specific UID to allow some users with that UID to access protected files.
UID will also contain protection level assigned it to you:
- **uid,1** : It can only access files with protection level 1.
- **uid,2** : It can access files with either protection level 1 or 2.

## RUN
To run the project, `modify_syscalls.py`, `protected_files.txt` and `authorized_users.txt` needs to be in same directory. You must have [bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md) installed in your linux environment. To run program run this command 
```bash
 sudo python3 modify_syscalls.py
```
to check UID, run:
```bash
 id -u
```

to create another user, you can run these commands:
```bash
 sudo useradd testuser
 sudo passwd testuser
```

to change current user to testuser, run:
```bash
 su - testuser
```

to delete user, run:
```bash
 sudo userdel <user_name>
```

Please do not forget to add correct file name, which you want to protect, you may need to create it first.

## Internal Working of Program

- Program Initialization:
  - The BPF program is defined using C code within a Python script.
  - The program attaches to the `sys_openat` system call to monitor file access attempts.

- Data Structures:
  - **protected_files**: A hash map to store file names and their associated security levels.
  - **authorized_users**: A hash map to store user **IDs (UIDs)** and their access levels.

- File Access Monitoring:
  - When a file open operation is detected, the program reads the filename and the UID of the process attempting to open the file.
  - The program looks up the file in protected_files to determine its security level.

- Authorization Check:
  - If the file has a security level, the program checks authorized_users to see if the UID has sufficient access level.
  - If the access level is sufficient, the operation proceeds, and an authorized access message is logged.
  - If the access level is insufficient, the program logs an unauthorized access attempt and either blocks the access or sends a SIGKILL signal based on the security level.
  - Root user can read all protected files.

- Configuration Files:
  - protected_files.txt: Specifies files to protect and their security levels.
  - authorized_users.txt: Specifies authorized UIDs and their access levels.

- Execution:
  - The script reads configurations from the files and populates the hash maps.
  - The BPF program attaches to the system call and starts monitoring and enforcing access control based on the defined policies.

## Reference

I took help of [bcc reference guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md), along with Liz rice's book [Learning eBPF](https://isovalent.com/books/learning-ebpf/) and [container security](https://www.google.com/search?client=ubuntu-sn&hs=pB6&sa=X&sca_esv=d5d0c4751fe7bdbd&channel=fs&biw=1920&bih=968&sxsrf=ADLYWIIvsYYxn3fFiLkSc3bdxh5DYTJPAA:1718907452261&q=Container+Security:+Fundamental+Technology+Concepts+that+Protect+Containerized+Applications&stick=H4sIAAAAAAAAAONgFuLVT9c3NEwzqCwxMSwzU4JwswyKs0ssSzK0pLKTrfST8vOz9RNLSzLyi6xA7GKF_LycykWs0c75eSWJmXmpRQrBqcmlRZkllVYKbqV5KYm5qUCJHIWQ1OSMvPyc_PRKBaDS5NSCkmKFkozEEoWAovyS1OQSBbgBmVWpKQqOBQU5mcmJJZn5ecUT2BgBtAnDa50AAAA&ved=2ahUKEwiR2t-g5eqGAxU4fPUHHcZyDEkQri56BAgKEAo&stq=1&lei=PHJ0ZpHMD7j41e8PxuWxyAQ) to learn about eBPF and its internals. I have read multiple blogs too. And I got an idea of protecting files from non-root users from a blog. Hence, I created this program to completely restrict access to files to be protected, along with setting up a method for allowed users to access files.

## learning

This will help me to take first step in eBPF programming. Please feel free to give thoughts, by creating issue or mail me at ks3913688@gmail.com. 

THANKS FOR READING. HAVE A GOOD DAY...

