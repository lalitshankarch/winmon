#![cfg_attr(
    debug_assertions,
    allow(dead_code, unused_imports, unused_assignments, unused_variables)
)]
use std::collections::HashMap;
use std::mem;
use std::time::Instant;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH};
use windows::Win32::Storage::EnhancedStorage::{PKEY_FileDescription, PKEY_Software_ProductName};
use windows::Win32::System::Com::{CoInitialize, CoUninitialize, CreateBindCtx};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, EnumProcesses, GetModuleBaseNameW, GetModuleFileNameExW,
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
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

fn cleanup() {
    unsafe {
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

struct ProcessDesc {
    display_name: String,
    file_path: String,
}

struct ProcessInfo {
    exe_name: String,
    display_name: String,
    file_path: String,
    working_set: usize,
    page_file: usize,
    private_working_set: usize,
}

fn get_process_desc(proc_handle: HANDLE, h_module: HMODULE) -> Result<ProcessDesc, String> {
    unsafe {
        let mut file_path_u16 = vec![0u16; 32767];
        let len = GetModuleFileNameExW(Some(proc_handle), Some(h_module), &mut file_path_u16);

        let bind_ctx = CreateBindCtx(0).map_err(|err| err.message())?;
        let item: IShellItem2 =
            SHCreateItemFromParsingName(PCWSTR(file_path_u16.as_ptr()), &bind_ctx)
                .map_err(|err| err.message())?;
        let display_name = item
            .GetString(&PKEY_FileDescription)
            .or_else(|_| item.GetString(&PKEY_Software_ProductName))
            .map_err(|err| err.message())?;

        Ok(ProcessDesc {
            file_path: String::from_utf16(&file_path_u16[..len as usize]).unwrap(),
            display_name: String::from_utf16(display_name.as_wide()).unwrap(),
        })
    }
}

fn get_process_info(
    pid: DWORD,
    pid_descs: &mut HashMap<String, ProcessDesc>,
) -> Result<ProcessInfo, String> {
    unsafe {
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|err| err.message())?;

        let mut h_module = HMODULE::default();
        let mut cb_needed = DWORD::default();
        EnumProcessModules(
            proc_handle,
            &mut h_module,
            mem::size_of::<HMODULE>() as u32,
            &mut cb_needed,
        )
        .map_err(|err| err.message())?;

        let mut proc_name = vec![0; MAX_PATH as usize];
        let len = GetModuleBaseNameW(proc_handle, Some(h_module), &mut proc_name) as usize;
        let exe_name = String::from_utf16(&proc_name[..len]).unwrap();

        let proc_desc = match pid_descs.get(&exe_name) {
            Some(desc) => desc,
            None => {
                let proc_desc = get_process_desc(proc_handle, h_module)?;
                pid_descs.insert(exe_name.clone(), proc_desc);
                pid_descs.get(&exe_name).unwrap()
            }
        };

        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        GetProcessMemoryInfo(
            proc_handle,
            &mut pmc,
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32,
        )
        .map_err(|err| err.message())?;
        let pmc_ex2 = &mut pmc as *mut _ as *mut PROCESS_MEMORY_COUNTERS_EX2;

        CloseHandle(proc_handle).map_err(|err| err.message())?;

        Ok(ProcessInfo {
            exe_name,
            display_name: proc_desc.display_name.clone(),
            file_path: proc_desc.file_path.clone(),
            working_set: pmc.WorkingSetSize,
            page_file: pmc.PagefileUsage,
            private_working_set: (*pmc_ex2).PrivateWorkingSetSize,
        })
    }
}

fn print_process_list(pid_descs: &mut HashMap<String, ProcessDesc>) {
    let mut pids = vec![0; 1024];
    get_pids(&mut pids);
    println!(
        "{:>8}  {:<40}  {:<16}  {:<16}  {:<16}",
        "PID", "Exectable name", "Working set", "Page file", "Private working set"
    );
    for pid in pids {
        let proc_info = match get_process_info(pid, pid_descs) {
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
    let mut pid_descs = HashMap::<String, ProcessDesc>::new();
    print_process_list(&mut pid_descs);
    println!("Elapsed: {:?}", start.elapsed());
    cleanup();
}
