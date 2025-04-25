#![cfg_attr(
    debug_assertions,
    allow(dead_code, unused_imports, unused_assignments, unused_variables)
)]
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::mem;
use std::time::Instant;
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::Storage::EnhancedStorage::{PKEY_FileDescription, PKEY_Software_ProductName};
use windows::Win32::System::Com::{CoInitialize, CoUninitialize, CreateBindCtx};
use windows::Win32::System::ProcessStatus::{
    EnumProcesses, GetModuleBaseNameW, GetModuleFileNameExW, GetProcessMemoryInfo,
    PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::UI::Shell::*;
use windows::core::PCWSTR;

type DWORD = u32;

fn init() {
    unsafe {
        _ = CoInitialize(None);
    }
}

fn cleanup(pid_to_handle: &HashMap<DWORD, HANDLE>) {
    unsafe {
        for (_, value) in pid_to_handle.into_iter() {
            CloseHandle(*value).unwrap();
        }
        CoUninitialize();
    }
}

fn get_pids(proc_pids: &mut Vec<DWORD>) {
    let dword_size = mem::size_of::<DWORD>();

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
    pid_to_handle: HashMap<DWORD, HANDLE>,
    pid_to_path: HashMap<DWORD, String>,
    path_to_desc: HashMap<String, ProcessDesc>,
}

struct ProcessDesc {
    exe_name: String,
    display_name: String,
}

struct ProcessInfo {
    file_path: String,
    exe_name: String,
    display_name: String,
    working_set: usize,
    page_file: usize,
    private_working_set: usize,
}

fn get_file_path_u16(proc_handle: HANDLE) -> ([u16; 32767], usize) {
    unsafe {
        let mut file_path_u16 = [0; 32767 as usize];
        let len = GetModuleFileNameExW(Some(proc_handle), None, &mut file_path_u16) as usize;
        (file_path_u16, len)
    }
}

fn get_process_desc(proc_handle: HANDLE, file_path_u16: &[u16]) -> Result<ProcessDesc, String> {
    unsafe {
        let mut exe_name_u16 = [0; MAX_PATH as usize];
        let len = GetModuleBaseNameW(proc_handle, None, &mut exe_name_u16);

        let bind_ctx = CreateBindCtx(0).map_err(|err| err.message())?;
        let item: IShellItem2 =
            SHCreateItemFromParsingName(PCWSTR(file_path_u16.as_ptr()), &bind_ctx)
                .map_err(|err| err.message())?;
        let display_name = item
            .GetString(&PKEY_FileDescription)
            .or_else(|_| item.GetString(&PKEY_Software_ProductName))
            .map_err(|err| err.message())?;

        Ok(ProcessDesc {
            exe_name: String::from_utf16_lossy(&exe_name_u16[..len as usize]),
            display_name: String::from_utf16_lossy(display_name.as_wide()),
        })
    }
}

fn get_process_info(pid: DWORD, caches: &mut ProcCaches) -> Result<ProcessInfo, String> {
    unsafe {
        let proc_handle = match caches.pid_to_handle.entry(pid) {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => {
                let proc_handle =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                        .map_err(|err| err.message())?;
                entry.insert(proc_handle.clone())
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

        let proc_desc = match caches.path_to_desc.entry(file_path.clone()) {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => {
                let (file_path_u16, len) = get_file_path_u16(*proc_handle);
                entry.insert(get_process_desc(*proc_handle, &file_path_u16[..len])?)
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

        Ok(ProcessInfo {
            exe_name: proc_desc.exe_name.clone(),
            display_name: proc_desc.display_name.clone(),
            file_path: file_path.clone(),
            working_set: pmc.WorkingSetSize,
            page_file: pmc.PagefileUsage,
            private_working_set: (*pmc_ex2).PrivateWorkingSetSize,
        })
    }
}

fn print_process_list(caches: &mut ProcCaches) {
    let mut pids = vec![0; 1024];
    get_pids(&mut pids);
    println!(
        "{:>8}  {:<40}  {:<16}  {:<16}  {:<16}",
        "PID", "Exectable name", "Working set", "Page file", "Private working set"
    );
    for pid in pids {
        let proc_info = match get_process_info(pid, caches) {
            Ok(stats) => stats,
            Err(_) => continue,
        };

        println!(
            "{:>8}  {:<40}  {:<16}  {:<16}  {:<16}",
            pid,
            proc_info.display_name,
            (proc_info.working_set / 1024),
            (proc_info.page_file / 1024),
            (proc_info.private_working_set / 1024),
        );
    }
}

fn main() {
    init();
    let start = Instant::now();
    let mut caches = ProcCaches {
        pid_to_handle: HashMap::new(),
        pid_to_path: HashMap::new(),
        path_to_desc: HashMap::new(),
    };
    print_process_list(&mut caches);
    println!("Elapsed: {:?}", start.elapsed());
    cleanup(&caches.pid_to_handle);
}
