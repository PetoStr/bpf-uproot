use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;
use libc::ioctl;
use log::{debug, error};
use scanner_rs_common::IOCTL_TRIGGER_CODE;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use tokio::sync::mpsc;

const IGNORE_SYMBOLS: [&str; 2] = ["ftrace_call", "ftrace_regs_call"];

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/scanner-rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/scanner-rs"
    ))?;
    let program: &mut TracePoint = bpf.program_mut("sys_enter_ioctl").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_ioctl")?;

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("DATA").unwrap())?;

    let (tx, mut rx) = mpsc::channel(1);

    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        let tx = tx.clone();
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<u8>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading events: {e}");
                        continue;
                    }
                };

                for event in buffers.iter().take(events.read) {
                    if tx.send(event[0]).await.is_err() {
                        error!("Receiver dropped");
                        return;
                    }
                }
            }
        });
    }

    let file = File::open("/proc/kallsyms")?;
    let lines = BufReader::new(file).lines();
    for line in lines.map_while(Result::ok) {
        let values: Vec<&str> = line.split_whitespace().collect();
        let address = u64::from_str_radix(values[0], 16)?;
        let symbol_name = values[2];

        if IGNORE_SYMBOLS.contains(&symbol_name) {
            continue;
        }

        unsafe { ioctl(-1, IOCTL_TRIGGER_CODE, address) };

        match rx.recv().await {
            Some(is_hooked) if is_hooked != 0 => {
                println!("{symbol_name:30} has active ftrace");
            }
            _ => (),
        }

    }

    Ok(())
}
