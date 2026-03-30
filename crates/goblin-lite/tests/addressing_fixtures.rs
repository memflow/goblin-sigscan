use std::{fs, path::PathBuf};

use goblin_lite::{elf::ElfFile, mach::MachFile, pe64::PeFile, MappedAddressView};

const PE64_FIXTURE: &str = "memflow_coredump.x86_64.dll";
const PE32_FIXTURE: &str = "memflow_coredump.x86.dll";
const ELF64_FIXTURE: &str = "libmemflow_coredump.x86_64.so";
const MACH_FIXTURE: &str = "libmemflow_native.aarch64.dylib";

const PE_MMAP_FILE_OFFSET: usize = 2_801_315;
const ELF_MMAP_FILE_OFFSET: usize = 2_434;
const MACH_TEXT_FILE_OFFSET: usize = 40;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("fixture binary should be readable")
}

fn read_le_u32(bytes: &[u8], file_offset: usize) -> u32 {
    let end = file_offset
        .checked_add(4)
        .expect("known fixture offsets should not overflow");
    let raw = bytes
        .get(file_offset..end)
        .expect("known fixture offsets should have at least four bytes");
    let mut out = [0u8; 4];
    out.copy_from_slice(raw);
    u32::from_le_bytes(out)
}

#[test]
fn pe64_addressing_helpers_roundtrip_and_read() {
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).expect("PE64 fixture should parse as PE64");

    assert!(!file.pe().sections.is_empty());
    assert_eq!(file.image(), bytes.as_slice());

    let rva = file
        .file_offset_to_rva(PE_MMAP_FILE_OFFSET)
        .expect("known string file offset should map into an RVA");
    assert_eq!(file.rva_to_file_offset(rva), Some(PE_MMAP_FILE_OFFSET));
    assert_eq!(file.file_offset_to_mapped(PE_MMAP_FILE_OFFSET), Some(rva));
    assert_eq!(file.mapped_to_file_offset(rva), Some(PE_MMAP_FILE_OFFSET));

    let value = file
        .read_rva::<u32>(rva)
        .expect("known mapped RVA should decode a u32");
    assert_eq!(value, read_le_u32(&bytes, PE_MMAP_FILE_OFFSET));
    assert_eq!(
        MappedAddressView::read_le::<u32>(&file, rva),
        Some(read_le_u32(&bytes, PE_MMAP_FILE_OFFSET))
    );

    let name = file
        .derva_c_str(rva)
        .expect("known mapped RVA should decode as C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(name, "mmap");
    let trait_name = file
        .mapped_c_str(rva)
        .expect("trait helper should decode C string at mapped RVA")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(trait_name, "mmap");

    let image_base = file
        .rva_to_va(0)
        .expect("PE optional header always defines image base for PE64");
    let va = file
        .rva_to_va(rva)
        .expect("mapped RVA should convert into VA");
    assert_eq!(va, image_base + rva);
    assert_eq!(file.va_to_rva(va), Some(rva));

    assert!(file.read_rva::<u32>(u64::MAX).is_none());
    assert!(file.derva_c_str(u64::MAX).is_none());
}

#[test]
fn pe32_fixture_is_rejected_by_pe64_parser() {
    let bytes = fixture_bytes(PE32_FIXTURE);
    let err = PeFile::from_bytes(&bytes).expect_err("PE32 fixture should be rejected by PeFile");
    assert!(matches!(err, goblin_lite::pe64::PeError::NotPe64));
}

#[test]
fn elf_addressing_helpers_roundtrip_and_read() {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).expect("ELF fixture should parse");

    assert!(!file.elf().program_headers.is_empty());
    assert_eq!(file.image(), bytes.as_slice());

    let vaddr = file
        .file_offset_to_vaddr(ELF_MMAP_FILE_OFFSET)
        .expect("known string file offset should map into a virtual address");
    assert_eq!(file.vaddr_to_file_offset(vaddr), Some(ELF_MMAP_FILE_OFFSET));
    assert_eq!(
        file.file_offset_to_mapped(ELF_MMAP_FILE_OFFSET),
        Some(vaddr)
    );
    assert_eq!(
        file.mapped_to_file_offset(vaddr),
        Some(ELF_MMAP_FILE_OFFSET)
    );

    let value = file
        .read_vaddr::<u32>(vaddr)
        .expect("known mapped virtual address should decode a u32");
    assert_eq!(value, read_le_u32(&bytes, ELF_MMAP_FILE_OFFSET));
    assert_eq!(
        MappedAddressView::read_le::<u32>(&file, vaddr),
        Some(read_le_u32(&bytes, ELF_MMAP_FILE_OFFSET))
    );

    let name = file
        .dvaddr_c_str(vaddr)
        .expect("known mapped virtual address should decode as C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(name, "mmap");
    let alias_name = file
        .derva_c_str(vaddr)
        .expect("backward-compatible alias should decode the same C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(alias_name, "mmap");

    assert!(file.read_vaddr::<u32>(u64::MAX).is_none());
    assert!(file.dvaddr_c_str(u64::MAX).is_none());
}

#[test]
fn mach_addressing_helpers_roundtrip_and_read() {
    let bytes = fixture_bytes(MACH_FIXTURE);
    let file = MachFile::from_bytes(&bytes).expect("Mach-O fixture should parse");

    assert!(matches!(
        file.mach(),
        goblin::mach::Mach::Binary(_) | goblin::mach::Mach::Fat(_)
    ));
    assert_eq!(file.image(), bytes.as_slice());

    let vmaddr = file
        .file_offset_to_vmaddr(MACH_TEXT_FILE_OFFSET)
        .expect("known string file offset should map into a VM address");
    assert_eq!(
        file.vmaddr_to_file_offset(vmaddr),
        Some(MACH_TEXT_FILE_OFFSET)
    );
    assert_eq!(
        file.file_offset_to_mapped(MACH_TEXT_FILE_OFFSET),
        Some(vmaddr)
    );
    assert_eq!(
        file.mapped_to_file_offset(vmaddr),
        Some(MACH_TEXT_FILE_OFFSET)
    );

    let value = file
        .read_vmaddr::<u32>(vmaddr)
        .expect("known mapped VM address should decode a u32");
    assert_eq!(value, read_le_u32(&bytes, MACH_TEXT_FILE_OFFSET));
    assert_eq!(
        MappedAddressView::read_le::<u32>(&file, vmaddr),
        Some(read_le_u32(&bytes, MACH_TEXT_FILE_OFFSET))
    );

    let name = file
        .dvmaddr_c_str(vmaddr)
        .expect("known mapped VM address should decode as C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(name, "__TEXT");
    let alias_name = file
        .derva_c_str(vmaddr)
        .expect("backward-compatible alias should decode the same C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(alias_name, "__TEXT");

    assert!(file.read_vmaddr::<u32>(u64::MAX).is_none());
    assert!(file.dvmaddr_c_str(u64::MAX).is_none());
}
