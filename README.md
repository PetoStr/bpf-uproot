## lkm-bpf-enum

LKM that lists loaded eBPF programs by iterating over `prog_idr`.

## proc-measure

Benchmarks `getdents64` system call. When a dummy tracepoint program is attached, the observed overhead is 62.7%.

## proclook

Searches for hidden processes in `/proc`.

## scanner-rs

Scans exported symbols and checks whether the function has an active ftrace. This could also indicate a present kprobe program.
