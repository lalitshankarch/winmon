#![cfg_attr(
    debug_assertions,
    allow(dead_code, unused_imports, unused_assignments, unused_variables)
)]
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::mem;
use std::time::Instant;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, SYSTEMTIME};
use windows::Win32::Storage::EnhancedStorage::{PKEY_FileDescription, PKEY_Software_ProductName};
use windows::Win32::System::Com::{CoInitialize, CoUninitialize, CreateBindCtx};
use windows::Win32::System::ProcessStatus::{
    EnumProcesses, GetModuleFileNameExW, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    PROCESS_MEMORY_COUNTERS_EX2,
};
use windows::Win32::System::Threading::{
    GetProcessHandleCount, GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::System::Time::FileTimeToSystemTime;
use windows::Win32::UI::Shell::*;
use windows::core::PCWSTR;

type Dword = u32;

fn init() {
    unsafe {
        _ = CoInitialize(None);
    }
}

fn cleanup(pid_to_handle: &HashMap<Dword, HANDLE>) {
    unsafe {
        for (_, value) in pid_to_handle.iter() {
            CloseHandle(*value).unwrap();
        }
        CoUninitialize();
    }
}

fn get_pids(proc_pids: &mut Vec<Dword>) {
    let dword_size = mem::size_of::<Dword>();

    loop {
        let proc_pids_nbytes = proc_pids.len() * dword_size;
        let mut needed_size = 0;

        unsafe {
            EnumProcesses(&mut proc_pids[0], proc_pids_nbytes as u32, &mut needed_size).unwrap();
        }

        if needed_size as usize >= proc_pids_nbytes {
            proc_pids.resize(proc_pids.len() * 2, 0);
        } else {
            let num_procs = needed_size as usize / dword_size;
            proc_pids.truncate(num_procs);
            break;
        }
    }
}

struct ProcCaches {
    pid_to_handle: HashMap<Dword, HANDLE>,
    pid_to_path: HashMap<Dword, String>,
    path_to_disp_name: HashMap<String, String>,
}

fn get_file_path_u16(proc_handle: HANDLE) -> ([u16; 32767], usize) {
    unsafe {
        let mut file_path_u16 = [0; 32767_usize];
        let len = GetModuleFileNameExW(Some(proc_handle), None, &mut file_path_u16) as usize;
        (file_path_u16, len)
    }
}

fn get_proc_disp_name(file_path_u16: &[u16]) -> Result<String, String> {
    unsafe {
        let bind_ctx = CreateBindCtx(0).map_err(|err| err.message())?;
        let item: IShellItem2 =
            SHCreateItemFromParsingName(PCWSTR(file_path_u16.as_ptr()), &bind_ctx)
                .map_err(|err| err.message())?;
        let display_name = item
            .GetString(&PKEY_FileDescription)
            .or_else(|_| item.GetString(&PKEY_Software_ProductName))
            .map_err(|err| err.message())?;

        Ok(String::from_utf16_lossy(display_name.as_wide()))
    }
}

fn print_process_info(pid: Dword, caches: &mut ProcCaches) -> Result<(), String> {
    unsafe {
        let proc_handle = match caches.pid_to_handle.entry(pid) {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => {
                let proc_handle =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                        .map_err(|err| err.message())?;
                entry.insert(proc_handle)
            }
        };

        let file_path = match caches.pid_to_path.entry(pid) {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => {
                let (file_path_u16, len) = get_file_path_u16(*proc_handle);
                let file_path = String::from_utf16_lossy(&file_path_u16[..len]);
                entry.insert(file_path.clone())
            }
        };

        let proc_disp_name = match caches.path_to_disp_name.entry(file_path.clone()) {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => {
                let (file_path_u16, len) = get_file_path_u16(*proc_handle);
                entry.insert(get_proc_disp_name(&file_path_u16[..len])?)
            }
        };

        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        GetProcessMemoryInfo(
            *proc_handle,
            &mut pmc,
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32,
        )
        .map_err(|err| err.message())?;
        let pmc_ex2 = &mut pmc as *mut _ as *mut PROCESS_MEMORY_COUNTERS_EX2;

        let (mut creation_time_ft, mut exit_time_ft, mut kernel_time_ft, mut user_time_ft) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        GetProcessTimes(
            *proc_handle,
            &mut creation_time_ft,
            &mut exit_time_ft,
            &mut kernel_time_ft,
            &mut user_time_ft,
        )
        .map_err(|err| err.message())?;

        let (mut kernel_time, mut user_time) = (SYSTEMTIME::default(), SYSTEMTIME::default());
        FileTimeToSystemTime(&kernel_time_ft, &mut kernel_time).map_err(|err| err.message())?;
        FileTimeToSystemTime(&user_time_ft, &mut user_time).map_err(|err| err.message())?;

        let mut hnd_count = 0;
        GetProcessHandleCount(*proc_handle, &mut hnd_count).map_err(|err| err.message())?;

        println!(
            "{:>6} {:<40} {:<6} {:<10} {:<10} {:<10} {:<14} {:<14}",
            pid,
            proc_disp_name,
            hnd_count,
            (pmc.WorkingSetSize / 1024),
            (pmc.PagefileUsage / 1024),
            ((*pmc_ex2).PrivateWorkingSetSize / 1024),
            format!(
                "{}:{}:{}:{}",
                kernel_time.wHour,
                kernel_time.wMinute,
                kernel_time.wSecond,
                kernel_time.wMilliseconds
            ),
            format!(
                "{}:{}:{}:{}",
                user_time.wHour, user_time.wMinute, user_time.wSecond, user_time.wMilliseconds
            )
        );

        Ok(())
    }
}

fn print_process_list(caches: &mut ProcCaches) {
    let mut pids = vec![0; 1024];
    get_pids(&mut pids);
    println!(
        "\n{:>6} {:<40} {:<6} {:<10} {:<10} {:<10} {:<14} {:<14}",
        "PID", "Program", "Hnd.", "WS", "Pagefile", "Priv. WS", "Kernel time", "User time"
    );
    for pid in pids {
        _ = print_process_info(pid, caches);
    }
}

fn main() {
    init();
    let start = Instant::now();
    let mut caches = ProcCaches {
        pid_to_handle: HashMap::new(),
        pid_to_path: HashMap::new(),
        path_to_disp_name: HashMap::new(),
    };
    print_process_list(&mut caches);
    println!("Elapsed: {:?}", start.elapsed());
    cleanup(&caches.pid_to_handle);
}
