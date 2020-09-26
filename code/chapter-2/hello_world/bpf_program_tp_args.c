#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
                               ...) = (void *)BPF_FUNC_trace_printk;

/*
 +---------+
| 8 bytes | hidden 'struct pt_regs *' (inaccessible to bpf program)
+---------+
| N bytes | static tracepoint fields defined in tracepoint/format (bpf readonly)
+---------+
| dynamic | __dynamic_array bytes of tracepoint (inaccessible to bpf yet)
----------
 */
struct execve_params {
    __u64 hidden_pad;  // hidden 'struct pt_regs *' (inaccessible to bpf program)
                       // https://lore.kernel.org/patchwork/patch/664886/
    int syscall_nr;
    const char * filename;
    const char *const * argv;
    const char *const * envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct execve_params *ctx) {
  char fmt[] = "sysnr %d, filename %s";
  bpf_trace_printk(fmt,sizeof(fmt), ctx->syscall_nr, ctx->filename);
  return 0;
}

char _license[] SEC("license") = "GPL";
