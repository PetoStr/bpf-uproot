use anyhow::Result;
use std::collections::HashSet;
use std::fs;

const PID_MAX: u32 = 4194304;

fn get_tgid_pid(pid: u32) -> Result<(u32, u32)> {
    let status_path = format!("/proc/{pid}/status");

    let status = fs::read_to_string(status_path)?;
    let lines = status.lines();

    let (mut tgid, mut pid) = (0, 0);

    for line in lines {
        let mut split = line.split(':');

        let opt_key = split.next();
        let opt_val = split.next();

        if let (Some(key), Some(val)) = (opt_key, opt_val) {
            let (key, val) = (key.trim(), val.trim());

            if key == "Tgid" {
                if let Ok(parsed) = val.parse::<u32>() {
                    tgid = parsed;
                }
            } else if key == "Pid" {
                if let Ok(parsed) = val.parse::<u32>() {
                    pid = parsed;
                }
            }
        }
    }

    Ok((tgid, pid))
}

fn proc_contains(pid: u32) -> Result<bool> {
    let pid = format!("{pid}");

    let contains = fs::read_dir("/proc/")?
        .filter_map(|e| e.ok())
        .filter(|f| f.metadata().is_ok_and(|m| m.is_dir()))
        .filter_map(|f| {
            f.path()
                .strip_prefix("/proc/")
                .map(|p| String::from(p.to_string_lossy()))
                .ok()
        })
        .any(|x| x == pid);

    Ok(contains)
}

fn check_dir(pid: u32) -> Result<bool> {
    let path = format!("/proc/{pid}/cmdline");

    // read cmdline if it is accessible
    if let Ok(cmdline) = fs::read_to_string(path) {
        // get tgid and pid from /proc/{pid}/status
        let (tgid, pid) = get_tgid_pid(pid)?;

        // main process thread, also check again if PID is not visible under /proc
        if tgid == pid && !proc_contains(pid).unwrap_or(false) {
            println!("{pid} is hidden in /proc/ directory, cmdline: {cmdline}");
            return Ok(true);
        }
    }

    Ok(false)
}

fn visible_pids() -> Result<HashSet<u32>> {
    let visible = fs::read_dir("/proc/")?
        .filter_map(|e| e.ok())
        .filter(|f| f.metadata().is_ok_and(|m| m.is_dir()))
        .filter_map(|f| {
            f.path()
                .strip_prefix("/proc/")
                .map(|p| String::from(p.to_string_lossy()))
                .ok()
        })
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();

    Ok(visible)
}

fn main() -> Result<()> {
    let visible = visible_pids()?;
    let mut found = false;

    for test_pid in 1..=PID_MAX {
        if visible.contains(&test_pid) {
            continue;
        }

        found |= check_dir(test_pid)?;
    }

    if !found {
        println!("No hidden process detected.");
    }

    Ok(())
}
