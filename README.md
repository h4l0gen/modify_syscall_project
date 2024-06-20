# eBPF_project

## Description

This project helps user to prevent non-root users to read their files whichever they want. User just need to add those files `Absolute path` and `Relative path` to `secure_files.txt` along with their `security levels`. Security level decide which action they want if non-root user try to access those file.
- security level 1: This will show `Permission denied` to non-root users.
- security level 2: This will `terminate` the process which trying to access these files.

## RUN
To run the project, `modify_syscalls.py` and `secure_files.txt` needs to be in same directory. You must have `bcc` in your linux environment. To run program just run command 
```bash
$ sudo python3 modify_syscalls.py
```

## Reference

I took help of [bcc reference guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md), along with Liz rice's book [Learning eBPF](https://isovalent.com/books/learning-ebpf/) and [container security](https://www.google.com/search?client=ubuntu-sn&hs=pB6&sa=X&sca_esv=d5d0c4751fe7bdbd&channel=fs&biw=1920&bih=968&sxsrf=ADLYWIIvsYYxn3fFiLkSc3bdxh5DYTJPAA:1718907452261&q=Container+Security:+Fundamental+Technology+Concepts+that+Protect+Containerized+Applications&stick=H4sIAAAAAAAAAONgFuLVT9c3NEwzqCwxMSwzU4JwswyKs0ssSzK0pLKTrfST8vOz9RNLSzLyi6xA7GKF_LycykWs0c75eSWJmXmpRQrBqcmlRZkllVYKbqV5KYm5qUCJHIWQ1OSMvPyc_PRKBaDS5NSCkmKFkozEEoWAovyS1OQSBbgBmVWpKQqOBQU5mcmJJZn5ecUT2BgBtAnDa50AAAA&ved=2ahUKEwiR2t-g5eqGAxU4fPUHHcZyDEkQri56BAgKEAo&stq=1&lei=PHJ0ZpHMD7j41e8PxuWxyAQ) to learn about eBPF and its internals. I have read multiple blogs too.

## learning

This will help me to take first step in eBPF programming.

