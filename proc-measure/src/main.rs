use libc::{open, O_DIRECTORY, O_RDONLY};
use statrs::statistics::Data;
use statrs::statistics::OrderStatistics;
use statrs::statistics::Statistics;
use std::env;
use std::fs::File;
use std::io::Write;
use syscalls::{syscall, Sysno};

fn open_proc() -> Option<i32> {
    let fd = unsafe { open(b"/proc\x00" as *const u8 as _, O_RDONLY | O_DIRECTORY) };

    if fd != -1 {
        Some(fd)
    } else {
        None
    }
}

fn store_results(data: &[f64], fname: &str) {
    let json_data = serde_json::to_string(&data).expect("Failed to convert data.");

    let mut file = File::create(fname).expect("Failed to create output file.");
    file.write_all(json_data.as_bytes())
        .expect("Failed to write to output file.");
}

#[inline(always)]
fn getdents64_unchecked(fd: i32, buf: &mut [i8]) {
    let _ = unsafe { syscall!(Sysno::getdents64, fd, buf.as_mut_ptr(), buf.len()) };
}

#[inline(always)]
fn getdents64(fd: i32, buf: &mut [i8]) {
    unsafe { syscall!(Sysno::getdents64, fd, buf.as_mut_ptr(), buf.len()) }
        .expect("getdents64 system call failed.");
}

#[inline(always)]
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let output_fname = if args.len() == 2 {
        &args[1]
    } else {
        "output.json"
    };

    let fd = open_proc().expect("Failed to open /proc");
    let mut buf = [0i8; 1024];

    // test if getdents64 works
    getdents64(fd, &mut buf);

    const CALLS: usize = 1000000;

    let mut vals = Vec::with_capacity(CALLS);

    // first, just calculate mean
    let mut s = 0f64;
    for _ in 0..CALLS {
        let start = rdtsc();
        getdents64_unchecked(fd, &mut buf);
        let end = rdtsc();

        let d = (end - start) as f64;
        s += d;
    }

    let tmp_mean = s / CALLS as f64;

    while vals.len() < CALLS {
        let start = rdtsc();
        getdents64_unchecked(fd, &mut buf);
        let end = rdtsc();

        let d = (end - start) as f64;

        // filter out huge extremes
        if d < 10.0 * tmp_mean {
            vals.push(d as f64);
        }
    }

    let cn = vals.len();
    let mn = vals.as_slice().min();
    let mx = vals.as_slice().max();
    let mean = vals.as_slice().mean();
    let med = Data::new(vals.clone()).median();
    let sdev = vals.as_slice().std_dev();

    println!("cn:   {cn}");
    println!("mean: {mean}");
    println!("med:  {med}");
    println!("sdev: {sdev}");
    println!("min:  {mn}");
    println!("max:  {mx}");

    store_results(&vals, output_fname);
}
