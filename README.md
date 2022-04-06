# eBPF considered harmful

This is a simple PoC for a eBPF backdoor running fully in kernelspace after being compiled and loaded.

It only leaves traces in /sys/fs/bpf and in tools like `bpftool prog`.

The PoC currently monitors all TCP connection state changes and overrides the return pointer on the stack
with `0x4141414142424242` if the service running on port `1337` was connected to from a source port `31337`.

While this PoC just crashes the binary (socat in this case), real adversaries could inject a ROP chain or
inject shellcodes by other means. The shellcode could be provided by the received TCP packet.

Alternative hooks can also be used, for example invalid TCP checksums, completely removing the need for having
a custom victim service running.


## Requirements to run the PoC

- vagrant with virtualbox provider
- (GNU) netcat

## Requirements of the PoC code

- kernel 5.16+ (due the use of `bpf_task_pt_regs`, but I'm relatively sure it can be done without this shortcut)

was developed with rust 1.59.0 stable and run on box `fedora/35-cloud-base` with version `35.20211026.0`


## Demo

(run `./poc.sh` to do it yourself)

[![asciicast](https://asciinema.org/a/H9JO6ZLkdiZft5uG2e5V2zIf4.svg)](https://asciinema.org/a/H9JO6ZLkdiZft5uG2e5V2zIf4)


## Credits

The idea for this primarily came up during some discussions with [felixwilhelm](https://github.com/felixwilhelm), I just happend to find the time to actually work on it.