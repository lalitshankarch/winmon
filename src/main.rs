#![cfg_attr(
    debug_assertions,
    allow(dead_code, unused_imports, unused_assignments, unused_variables)
)]
use std::mem;
use std::time::Instant;
use windows::Win32::Foundation::{CloseHandle, HMODULE, MAX_PATH};
use windows::Win32::Storage::EnhancedStorage::{PKEY_FileDescription, PKEY_Software_ProductName};
use windows::Win32::System::Com::{CoInitialize, CoUninitialize, CreateBindCtx, IBindCtx};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, EnumProcesses, GetModuleBaseNameW, GetModuleFileNameExW,
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::UI::Shell::*;
use windows::core::{PCWSTR, PWSTR};

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
    if proc_pids.is_empty() {
        return;
    }

    let dword_size = mem::size_of::<DWORD>();

    loop {
        let proc_pids_nbytes = proc_pids.len() * dword_size;
        let mut needed_size: u32 = 0;

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

struct ProcessInfo {
    exe_name: String,
    display_name: String,
    file_path: String,
    working_set: usize,
    page_file: usize,
    private_working_set: usize,
}

fn get_process_info(pid: DWORD) -> Result<ProcessInfo, String> {
    unsafe {
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|err| err.message())?;

        let mut h_module: HMODULE = Default::default();
        let mut cb_needed: DWORD = Default::default();
        EnumProcessModules(
            proc_handle,
            &mut h_module,
            mem::size_of::<HMODULE>() as u32,
            &mut cb_needed,
        )
        .map_err(|err| err.message())?;

        let mut process_name = vec![0; MAX_PATH as usize];
        _ = GetModuleBaseNameW(proc_handle, Some(h_module), &mut process_name);
        let proc_ex_name = String::from_utf16(&process_name).map_err(|err| err.to_string())?;

        let mut file_path = vec![0; 32767 as usize];
        _ = GetModuleFileNameExW(Some(proc_handle), Some(h_module), &mut file_path);
        let proc_file_path = String::from_utf16(&file_path).map_err(|err| err.to_string())?;

        let file_path_wstr = PCWSTR(&file_path[0]);
        let bind_ctx = CreateBindCtx(0).map_err(|err| err.to_string())?;
        // IBindCtx make this option type
        let result = SHCreateItemFromParsingName::<PCWSTR, &IBindCtx, IShellItem2>(
            file_path_wstr,
            &bind_ctx,
        )
        .map_err(|err| err.to_string())?;

        let display_name_wstr = result.GetString(&PKEY_FileDescription).unwrap_or(
            result
                .GetString(&PKEY_Software_ProductName)
                .unwrap_or(PWSTR(&mut process_name[0])),
        );
        let display_name =
            String::from_utf16(display_name_wstr.as_wide()).map_err(|err| err.to_string())?;

        let mut pmc: PROCESS_MEMORY_COUNTERS = Default::default();
        GetProcessMemoryInfo(
            proc_handle,
            &mut pmc,
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32,
        )
        .map_err(|err| err.message())?;
        let pmc_ex2 = &mut pmc as *mut _ as *mut PROCESS_MEMORY_COUNTERS_EX2;

        let proc_info: ProcessInfo = ProcessInfo {
            exe_name: proc_ex_name,
            display_name: display_name,
            file_path: proc_file_path,
            working_set: pmc.WorkingSetSize,
            page_file: pmc.PagefileUsage,
            private_working_set: (*pmc_ex2).PrivateWorkingSetSize,
        };

        CloseHandle(proc_handle).map_err(|err| err.message())?;

        Ok(proc_info)
    }
}

fn print_process_list() {
    let mut pids = vec![0; 1024];
    get_pids(&mut pids);
    println!(
        "{:>8}  {:<40}  {:<16}  {:<16}  {:<16}",
        "PID", "Exectable name", "Working set", "Page file", "Private working set"
    );
    for pid in pids {
        match get_process_info(pid) {
            Ok(proc_info) => println!(
                "{:>8}  {:<40}  {:<16}  {:<16}  {:<16}",
                pid,
                proc_info.display_name,
                (proc_info.working_set / 1024),
                (proc_info.page_file / 1024),
                (proc_info.private_working_set / 1024),
            ),
            Err(_) => continue,
        }
    }
}

fn main() {
    init();
    let start = Instant::now();
    print_process_list();
    println!("Elapsed: {:?}", start.elapsed());
    cleanup();
}
