#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_uchar,
    helpers::{bpf_probe_read, bpf_probe_read_kernel},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    BpfContext,
};
use scanner_rs_common::IOCTL_TRIGGER_CODE;

#[map]
static DATA: PerfEventArray<bool> = PerfEventArray::new(0);

// from https://github.com/kunai-project/kunai/blob/main/kunai-common/src/syscalls/bpf.rs
#[repr(C, packed(1))]
pub struct TracepointCommonArgs {
    pub ctype: u16,
    pub flags: u8,
    pub preempt_count: u8,
    pub pid: i32,
}

#[repr(C, packed(1))]
pub struct Syscall {
    pub sys_nr: i32,
    pad: u32,
}

#[repr(C, packed(1))]
struct IoctlArgs {
    pub common: TracepointCommonArgs,
    pub syscall: Syscall,
    fd: u64,
    request: u64,
    address: u64,
}

impl IoctlArgs {
    pub fn from_context<C: BpfContext>(c: &C) -> Result<Self, ()> {
        Ok(unsafe { bpf_probe_read(c.as_ptr() as *const Self) }
            .expect("Failed to read ioctl arguments"))
    }
}

// since this is a tracepoint, we can't override the return value (do error injection)
#[tracepoint]
pub fn sys_enter_ioctl(ctx: TracePointContext) -> u32 {
    match try_sys_enter_ioctl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_ioctl(ctx: TracePointContext) -> Result<u32, u32> {
    let args = IoctlArgs::from_context(&ctx).unwrap();

    if args.request != IOCTL_TRIGGER_CODE {
        return Ok(0);
    }

    let val: Result<c_uchar, i64> = unsafe { bpf_probe_read_kernel(args.address as _) };

    let is_call = match val {
        Ok(0xe8) => {
            let off: i32 = unsafe { bpf_probe_read_kernel((args.address + 1) as _) }.unwrap();
            let mut interesting = false;

            // 4881eca80000.  sub rsp, 0xa8
            // 4889442450     mov qword [var_50h], rax
            // 48894c2458     mov qword [var_58h], rcx    ; arg4
            // 4889542460     mov qword [var_60h], rdx    ; arg3
            // 4889742468     mov qword [var_68h], rsi    ; arg2
            // 48897c2470     mov qword [var_70h], rdi    ; arg1
            // 4c89442448     mov qword [var_48h], r8     ; arg5
            // 4c894c2440     mov qword [var_40h], r9     ; arg6
            const SAVE_CONTEXT_TO_STACK_INSNS: [u8; 42] = [
                0x48, 0x81, 0xec, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x89,
                0x4c, 0x24, 0x58, 0x48, 0x89, 0x54, 0x24, 0x60, 0x48, 0x89, 0x74, 0x24, 0x68, 0x48,
                0x89, 0x7c, 0x24, 0x70, 0x4c, 0x89, 0x44, 0x24, 0x48, 0x4c, 0x89, 0x4c, 0x24, 0x40,
            ];

            let insns_res: Result<[u8; 80 + SAVE_CONTEXT_TO_STACK_INSNS.len()], i64> =
                unsafe { bpf_probe_read_kernel((args.address + 5 + off as u64) as _) };

            if let Ok(insns) = insns_res {
                let pos = insns
                    .windows(SAVE_CONTEXT_TO_STACK_INSNS.len())
                    .position(|window| window == SAVE_CONTEXT_TO_STACK_INSNS);
                if pos.is_some() {
                    interesting = true;
                }
            }

            interesting
        }
        Err(_) => false,
        _ => false,
    };

    DATA.output(&ctx, &is_call, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
