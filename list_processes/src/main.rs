
use std::{mem, io, str};
use windows::Win32::System::ProcessStatus::{K32EnumProcesses, K32EnumProcessModules, K32GetModuleBaseNameA};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION};
use windows::Win32::Foundation::{HANDLE, HINSTANCE};
use windows::core::Error;

struct Process {
    pid: u32,
    handle: HANDLE,
}

impl Process {
    fn open(pid: u32) -> Result<Self, Error> {
        let desired_access: PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
        unsafe {
            OpenProcess(desired_access, false, pid)
            .map(|handle| Self { pid, handle })
        }
    }

    fn get_name(&self) -> io::Result<String> {
        let mut h_mod: Vec<HINSTANCE> = vec![HINSTANCE::default(); 1024];
        let cb = (h_mod.capacity() * mem::size_of::<HINSTANCE>()) as u32;
        let mut lpcbneeded = 0;
    
        unsafe {
            if K32EnumProcessModules(self.handle, h_mod.as_mut_ptr(), cb, &mut lpcbneeded) == false {
                return Err(io::Error::last_os_error());
            }
            let module = *h_mod.get(0).unwrap();
            let mut buf: Vec<u8> = vec![u8::default(); 1024];

            let name_length: u32 = K32GetModuleBaseNameA(self.handle, module, &mut buf);
            buf.set_len(name_length as usize);
            let res = str::from_utf8(&buf).unwrap().to_string();
            Ok(res)
        }
    }
}

fn get_process_ids() -> io::Result<Vec<u32>> {
    let mut lpidprocess: Vec<u32> = Vec::<u32>::with_capacity(1024);
    let cb = (lpidprocess.capacity() * mem::size_of::<u32>()) as u32;
    let mut lpcbneeded = 0;

    unsafe {
        if K32EnumProcesses(lpidprocess.as_mut_ptr(), cb, &mut lpcbneeded) == false {
            return Err(io::Error::last_os_error());
        }
        let process_count = lpcbneeded as usize / mem::size_of::<u32>();
        lpidprocess.set_len(process_count);
    }

    Ok(lpidprocess)
}

fn main() {
    let pid_list = get_process_ids().unwrap();
    let mut processes: Vec<Process> = Vec::new();
    for pid in pid_list {
        match Process::open(pid) {
            Ok(p) => processes.push(p),
            Err(_) => continue,
        }
    }

    for p in processes {
        let name = p.get_name().unwrap();
        println!("[-] {} ({})", name, p.pid);
    }
}