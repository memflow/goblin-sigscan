use std::{fs, path::PathBuf};

use goblin_lite::pattern::Atom;
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

/// Scans `matches_code` looking for the first match where `save[0] == expected_start`.
/// Returns the full save array for that match, or panics if not found.
fn find_match_at<const N: usize, B: goblin_lite::BinaryView>(
    matches: &mut goblin_lite::Matches<'_, '_, B>,
    expected_start: u64,
) -> [u64; N] {
    let mut save = [0u64; N];
    loop {
        assert!(
            matches.next(&mut save),
            "pattern ran out of matches before reaching VA/RVA 0x{expected_start:x}"
        );
        if save[0] == expected_start {
            return save;
        }
    }
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
        .deref_copy_rva::<u32>(rva)
        .expect("known mapped RVA should decode a u32");
    assert_eq!(value, read_le_u32(&bytes, PE_MMAP_FILE_OFFSET));
    assert_eq!(
        MappedAddressView::read_le::<u32>(&file, rva),
        Some(read_le_u32(&bytes, PE_MMAP_FILE_OFFSET))
    );

    let name = file
        .deref_c_str_rva(rva)
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

    assert!(file.deref_copy_rva::<u32>(u64::MAX).is_none());
    assert!(file.deref_c_str_rva(u64::MAX).is_none());
    assert!(file.deref_copy_va::<u32>(u64::MAX).is_none());
    assert!(file.deref_c_str_va(u64::MAX).is_none());
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
        .deref_copy_vaddr::<u32>(vaddr)
        .expect("known mapped virtual address should decode a u32");
    assert_eq!(value, read_le_u32(&bytes, ELF_MMAP_FILE_OFFSET));
    assert_eq!(
        MappedAddressView::read_le::<u32>(&file, vaddr),
        Some(read_le_u32(&bytes, ELF_MMAP_FILE_OFFSET))
    );

    let name = file
        .deref_c_str_vaddr(vaddr)
        .expect("known mapped virtual address should decode as C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(name, "mmap");
    let ptr_name = file
        .deref_c_str_vaddr(vaddr)
        .expect("format-specific helper should decode the same C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(ptr_name, "mmap");

    assert!(file.deref_copy_vaddr::<u32>(u64::MAX).is_none());
    assert!(file.deref_c_str_vaddr(u64::MAX).is_none());
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
        .deref_copy_vmaddr::<u32>(vmaddr)
        .expect("known mapped VM address should decode a u32");
    assert_eq!(value, read_le_u32(&bytes, MACH_TEXT_FILE_OFFSET));
    assert_eq!(
        MappedAddressView::read_le::<u32>(&file, vmaddr),
        Some(read_le_u32(&bytes, MACH_TEXT_FILE_OFFSET))
    );

    let name = file
        .deref_c_str_vmaddr(vmaddr)
        .expect("known mapped VM address should decode as C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(name, "__TEXT");
    let ptr_name = file
        .deref_c_str_vmaddr(vmaddr)
        .expect("format-specific helper should decode the same C string")
        .to_str()
        .expect("fixture C string should be UTF-8");
    assert_eq!(ptr_name, "__TEXT");

    assert!(file.deref_copy_vmaddr::<u32>(u64::MAX).is_none());
    assert!(file.deref_c_str_vmaddr(u64::MAX).is_none());
}

#[test]
fn pe64_section_lookup_cache_handles_section_switches() {
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).expect("PE64 fixture should parse as PE64");

    let mut mapped = file
        .pe()
        .sections
        .iter()
        .filter_map(|section| {
            if section.size_of_raw_data == 0 {
                return None;
            }
            Some(u64::from(section.virtual_address))
        })
        .take(2);
    let first = mapped
        .next()
        .expect("fixture should expose at least one mapped PE section");
    let second = mapped
        .next()
        .expect("fixture should expose at least two mapped PE sections");

    let first_offset = file
        .rva_to_file_offset(first)
        .expect("first section RVA should map to file offset");
    let second_offset = file
        .rva_to_file_offset(second)
        .expect("second section RVA should map to file offset");

    assert_eq!(file.rva_to_file_offset(first), Some(first_offset));
    assert_eq!(file.rva_to_file_offset(second), Some(second_offset));
    assert_eq!(file.rva_to_file_offset(first), Some(first_offset));
}

#[test]
fn elf_load_lookup_cache_handles_segment_switches() {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).expect("ELF fixture should parse");

    let mut mapped = file
        .elf()
        .program_headers
        .iter()
        .filter_map(|ph| {
            if ph.p_type != goblin::elf::program_header::PT_LOAD || ph.p_filesz == 0 {
                return None;
            }
            Some(ph.p_vaddr)
        })
        .take(2);
    let first = mapped
        .next()
        .expect("fixture should expose at least one load segment");
    let second = mapped
        .next()
        .expect("fixture should expose at least two load segments");

    let first_offset = file
        .vaddr_to_file_offset(first)
        .expect("first segment vaddr should map to file offset");
    let second_offset = file
        .vaddr_to_file_offset(second)
        .expect("second segment vaddr should map to file offset");

    assert_eq!(file.vaddr_to_file_offset(first), Some(first_offset));
    assert_eq!(file.vaddr_to_file_offset(second), Some(second_offset));
    assert_eq!(file.vaddr_to_file_offset(first), Some(first_offset));
}

#[test]
fn mach_load_lookup_cache_handles_segment_switches() {
    let bytes = fixture_bytes(MACH_FIXTURE);
    let file = MachFile::from_bytes(&bytes).expect("Mach-O fixture should parse");

    let mut mapped = Vec::new();
    match file.mach() {
        goblin::mach::Mach::Binary(binary) => {
            for segment in binary.segments.iter() {
                if segment.filesize != 0 {
                    mapped.push(segment.vmaddr);
                }
                if mapped.len() >= 2 {
                    break;
                }
            }
        }
        goblin::mach::Mach::Fat(fat) => {
            for index in 0..fat.narches {
                let arch = fat
                    .get(index)
                    .expect("fixture fat entry should decode cleanly");
                if let goblin::mach::SingleArch::MachO(binary) = arch {
                    for segment in binary.segments.iter() {
                        if segment.filesize != 0 {
                            mapped.push(segment.vmaddr);
                        }
                        if mapped.len() >= 2 {
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    assert!(
        mapped.len() >= 2,
        "fixture should expose at least two mapped Mach segments"
    );
    let first = mapped[0];
    let second = mapped[1];

    let first_offset = file
        .vmaddr_to_file_offset(first)
        .expect("first segment vmaddr should map to file offset");
    let second_offset = file
        .vmaddr_to_file_offset(second)
        .expect("second segment vmaddr should map to file offset");

    assert_eq!(file.vmaddr_to_file_offset(first), Some(first_offset));
    assert_eq!(file.vmaddr_to_file_offset(second), Some(second_offset));
    assert_eq!(file.vmaddr_to_file_offset(first), Some(first_offset));
}

/// The scanner finds a known 8-byte function prologue in the ELF .text segment.
/// Exercises `Byte` matching and `Save` slot capture.
/// Bytes at VA 0x1f950: 55 41 57 41 56 41 55 41 (push rbp / push r15 / push r14 / push r13)
#[test]
fn elf_scanner_byte_and_save_match_known_prologue() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file
        .scanner()
        .matches_code(pat!("55 41 57 41 56 41 55 41 54 53 48 83"));
    let found = find_match_at::<1, _>(&mut matches, 0x1f950);
    assert_eq!(found[0], 0x1f950);

    // Save captures mid-pattern cursor positions.
    let mut matches2 = file.scanner().matches_code(pat!("55 ' 41 57"));
    let mid = find_match_at::<2, _>(&mut matches2, 0x1f950);
    assert_eq!(mid[0], 0x1f950);
    assert_eq!(
        mid[1], 0x1f951,
        "Save after first byte should capture cursor at byte 1"
    );
}

/// `Skip` bridges a known fixed-width gap between two byte sequences.
/// Bytes at VA 0x1f70c: 48 8b [6 bytes] 48 89
#[test]
fn elf_scanner_skip_bridges_fixed_gap() {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(&[
        Atom::Save(0),
        Atom::Byte(0x48),
        Atom::Byte(0x8b),
        Atom::Skip(6),
        Atom::Byte(0x48),
        Atom::Byte(0x89),
    ]);
    let found = find_match_at::<1, _>(&mut matches, 0x1f70c);
    assert_eq!(found[0], 0x1f70c);
}

/// `SkipRange` matches when the gap falls within the specified range.
/// The gap between `48 8b` and `48 89` at VA 0x1f70c is exactly 6 bytes.
/// `[4-10]` (exclusive upper → SkipRange(4,9)) covers 6.
#[test]
fn elf_scanner_skip_range_matches_variable_gap() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("48 8b [4-10] 48 89"));
    let found = find_match_at::<1, _>(&mut matches, 0x1f70c);
    assert_eq!(found[0], 0x1f70c);
}

/// `Jump4` follows a signed 4-byte relative call.
/// `e8 e1 d4 00 00` at VA 0x1f66a → call target VA 0x2cb50.
/// disp = 0x0000d4e1, base = 0x1f66f, target = 0x2cb50.
#[test]
fn elf_scanner_jump4_follows_call_rel32() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("e8 ${'}"));
    let found = find_match_at::<2, _>(&mut matches, 0x1f66a);
    assert_eq!(found[1], 0x2cb50, "call target VA should be 0x2cb50");
}

/// `Jump1` follows a signed 1-byte conditional jump.
/// `48 85 c0 74 21` at VA 0x1f631: jz with disp=33 → target 0x1f657.
/// base = 0x1f636, target = 0x1f636 + 33 = 0x1f657.
#[test]
fn elf_scanner_jump1_follows_short_conditional_jz() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    // `48 85 c0` (test rax,rax) + `74` (jz) narrows to one site in this area.
    let mut matches = file.scanner().matches_code(pat!("48 85 c0 74 %'"));
    let found = find_match_at::<2, _>(&mut matches, 0x1f631);
    assert_eq!(found[1], 0x1f657, "jz target VA should be 0x1f657");
}

/// `u4` reads a 4-byte little-endian unsigned immediate.
/// `b8 15 7c 4a 7f` at VA 0x21df4: mov eax, 0x7f4a7c15.
#[test]
fn elf_scanner_read_u32_reads_mov_eax_imm32() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("b8 u4"));
    let found = find_match_at::<2, _>(&mut matches, 0x21df4);
    assert_eq!(found[1], 0x7f4a7c15, "imm32 should be 0x7f4a7c15");
}

/// `i4` reads a 4-byte little-endian signed immediate and sign-extends to 64 bits.
/// 0x7f4a7c15 is positive as i32 so the u64 representation is identical to u32.
#[test]
fn elf_scanner_read_i32_sign_extends_positive_immediate() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("b8 i4"));
    let found = find_match_at::<2, _>(&mut matches, 0x21df4);
    assert_eq!(found[1] as i64, 0x7f4a7c15_i64);
}

/// `u1` reads and zero-extends a 1-byte immediate.
/// `6a 2c` at VA 0x204a6: push 44 (0x2c).
#[test]
fn elf_scanner_read_u8_reads_push_imm8() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("6a u1"));
    let found = find_match_at::<2, _>(&mut matches, 0x204a6);
    assert_eq!(found[1], 44, "push immediate should be 44 (0x2c)");
}

/// `i1` reads and sign-extends a 1-byte immediate.
/// Same `6a 2c` site — 44 is positive, so ReadI8 and ReadU8 agree.
#[test]
fn elf_scanner_read_i8_sign_extends_positive_byte() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("6a i1"));
    let found = find_match_at::<2, _>(&mut matches, 0x204a6);
    assert_eq!(found[1] as i64, 44_i64);
}

/// `u2` reads and zero-extends a 16-bit little-endian word.
/// `66 b8 fe ff` at VA 0x22660: mov ax, 0xfffe (65534).
#[test]
fn elf_scanner_read_u16_reads_mov_ax_imm16() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("66 b8 u2"));
    let found = find_match_at::<2, _>(&mut matches, 0x22660);
    assert_eq!(found[1], 0xfffe, "mov ax immediate should be 0xfffe");
}

/// `i2` reads and sign-extends a 16-bit little-endian signed word.
/// 0xfffe as i16 = -2; stored in the u64 save slot as 0xfffffffffffffffeu64.
#[test]
fn elf_scanner_read_i16_sign_extends_negative_word() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("66 b8 i2"));
    let found = find_match_at::<2, _>(&mut matches, 0x22660);
    assert_eq!(found[1] as i64, -2_i64, "0xfffe sign-extended is -2");
}

/// `@4` asserts the cursor is aligned to 2^4 = 16 bytes at the point of the check.
/// Every match of `@4 <bytes>` must start at a 16-byte-aligned VA.
#[test]
fn elf_scanner_aligned_only_matches_at_aligned_addresses() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut save = [0u64; 1];
    let mut matches = file.scanner().matches_code(pat!("@4 55 41"));
    while matches.next(&mut save) {
        assert_eq!(save[0] % 16, 0, "VA 0x{:x} is not 16-byte aligned", save[0]);
    }
}

/// The function prologue at VA 0x1f950 is 16-byte aligned and starts with
/// `55 41 57 41 56 41 55 41 54 53 48 83` (10 fixed bytes).
#[test]
fn elf_scanner_aligned_matches_known_aligned_prologue() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut matches = file
        .scanner()
        .matches_code(pat!("@4 55 41 57 41 56 41 55 41 54 53 48 83"));
    let found = find_match_at::<1, _>(&mut matches, 0x1f950);
    assert_eq!(found[0], 0x1f950);
    assert_eq!(found[0] % 16, 0);
}

/// `Back(n)` rewinds the cursor by `n` bytes.
/// Match 8 bytes of the prologue at 0x1f950, rewind by 6, then match `57 41 56`
/// which starts at byte 2 of the original match (VA 0x1f952).
#[test]
fn elf_scanner_back_rewinds_cursor() {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    // 0x1f950: 55 41 57 41 56 41 55 41 ...
    // After 8-byte match cursor = 0x1f958; Back(6) → 0x1f952; `57 41 56` ✓
    let pat = [
        Atom::Save(0),
        Atom::Byte(0x55),
        Atom::Byte(0x41),
        Atom::Byte(0x57),
        Atom::Byte(0x41),
        Atom::Byte(0x56),
        Atom::Byte(0x41),
        Atom::Byte(0x55),
        Atom::Byte(0x41),
        Atom::Back(6),
        Atom::Byte(0x57),
        Atom::Byte(0x41),
        Atom::Byte(0x56),
    ];
    let mut save = [0u64; 1];
    let mut matches = file.scanner().matches_code(&pat);
    assert!(matches.next(&mut save), "Back pattern should find a match");
    assert_eq!(save[0], 0x1f950);
}

/// `Zero(slot)` writes 0 to the named save slot without advancing the cursor.
/// `Save(1)` captures the cursor, then `Zero(1)` resets it to 0.
#[test]
fn elf_scanner_zero_clears_save_slot() {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    // 0x1f950: 55 41 ...
    // Save(0)=0x1f950, Byte(55), Save(1)=0x1f951, Zero(1) → save[1]=0, Byte(41)
    let pat = [
        Atom::Save(0),
        Atom::Byte(0x55),
        Atom::Save(1), // save[1] = cursor (= 0x1f951 when started at 0x1f950)
        Atom::Zero(1), // save[1] = 0
        Atom::Byte(0x41),
    ];
    let mut save = [0u64; 2];
    let mut matches = file.scanner().matches_code(&pat);
    loop {
        assert!(matches.next(&mut save), "Zero pattern should find a match");
        if save[0] == 0x1f950 {
            break;
        }
    }
    assert_eq!(save[1], 0, "Zero(1) must have cleared save[1] to 0");
}

/// `Check(slot)` fails unless the current cursor equals save[slot].
/// After `Back`, cursor returns to a position that was previously saved; `Check`
/// verifies they agree.
#[test]
fn elf_scanner_check_validates_cursor_equals_saved_position() {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    // 0x1f950: 55 41 57 ...
    // Save(0)=0x1f950, Byte(55), Save(1)=0x1f951,
    // Byte(41), Byte(57), cursor=0x1f953
    // Back(2) → cursor=0x1f951 == save[1] → Check passes
    // Byte(41) matches byte at 0x1f951 ✓
    let pat = [
        Atom::Save(0),
        Atom::Byte(0x55),
        Atom::Save(1),
        Atom::Byte(0x41),
        Atom::Byte(0x57),
        Atom::Back(2),
        Atom::Check(1),
        Atom::Byte(0x41),
    ];
    let mut save = [0u64; 2];
    let mut matches = file.scanner().matches_code(&pat);
    loop {
        assert!(matches.next(&mut save), "Check pattern should find a match");
        if save[0] == 0x1f950 {
            break;
        }
    }
    assert_eq!(save[1], 0x1f951);
}

/// `(A | B)` tries each alternative in order.
/// `85 c0` (test eax,eax) and `48 85 c0` (test rax,rax) are both present in .text.
#[test]
fn elf_scanner_case_break_matches_both_alternatives() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    let mut save = [0u64; 1];
    let mut matches = file.scanner().matches_code(pat!("(85 c0 | 48 85 c0)"));

    let mut found_32bit = false; // 85 c0 at 0x21b15
    let mut found_64bit = false; // 48 85 c0 at 0x1f631

    while matches.next(&mut save) {
        if save[0] == 0x21b15 {
            found_32bit = true;
        }
        if save[0] == 0x1f631 {
            found_64bit = true;
        }
        if found_32bit && found_64bit {
            break;
        }
    }

    assert!(
        found_32bit,
        "32-bit `test eax,eax` (85 c0) at VA 0x21b15 should match"
    );
    assert!(
        found_64bit,
        "64-bit `test rax,rax` (48 85 c0) at VA 0x1f631 should match"
    );
}

/// `${...}` follows a relative jump, matches a sub-pattern at the destination,
/// then resumes after the jump displacement.
/// call at VA 0x1f66a → target 0x2cb50; verify target starts with a known byte.
#[test]
fn elf_scanner_push_pop_matches_call_target() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).unwrap();

    // The call target at 0x2cb50 starts with `41 57` (REX + push r15).
    assert_eq!(&bytes[0x2cb50..0x2cb52], &[0x41, 0x57]);

    // Follow the call, verify the first two target bytes, then resume after the
    // 5-byte `e8 XX XX XX XX` instruction and match the byte at 0x1f66f (`48`).
    let mut matches = file.scanner().matches_code(pat!("e8 ${41 57} 48"));
    let found = find_match_at::<1, _>(&mut matches, 0x1f66a);
    assert_eq!(found[0], 0x1f66a);
}

/// The scanner finds a known byte sequence in the PE64 .text section.
#[test]
fn pe64_scanner_byte_and_save_match_known_sequence() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    // `e8 11 63 1f 00` at RVA 0x100a — call rel32 as fixed bytes.
    let mut matches = file.scanner().matches_code(pat!("e8 11 63 1f 00"));
    let found = find_match_at::<1, _>(&mut matches, 0x100a);
    assert_eq!(found[0], 0x100a);
}

/// `e8 11 63 1f 00` at RVA 0x100a: call rel32 0x1f6311 → target RVA 0x1f7320.
/// base = RVA 0x100f, disp = 0x1f6311, target = 0x1f7320.
#[test]
fn pe64_scanner_jump4_follows_call_rel32() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("e8 ${'}"));
    let found = find_match_at::<2, _>(&mut matches, 0x100a);
    assert_eq!(found[1], 0x1f7320, "call target RVA should be 0x1f7320");
}

/// `eb 26` at RVA 0x101e: jmp short with disp=38 → target RVA 0x1046.
/// base = RVA 0x1020, disp = 38, target = 0x1046.
#[test]
fn pe64_scanner_jump1_follows_short_jmp() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("eb %'"));
    let found = find_match_at::<2, _>(&mut matches, 0x101e);
    assert_eq!(found[1], 0x1046, "jmp target RVA should be 0x1046");
}

/// `b8 01 00 00 00` at RVA 0x1042: mov eax, 1.
#[test]
fn pe64_scanner_read_u32_reads_mov_eax_imm32() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("b8 u4"));
    let found = find_match_at::<2, _>(&mut matches, 0x1042);
    assert_eq!(found[1], 1, "mov eax, 1 immediate should be 1");
}

/// `6a 1f` at RVA 0x1405: push 31 (0x1f).
#[test]
fn pe64_scanner_read_u8_reads_push_imm8() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("6a u1"));
    let found = find_match_at::<2, _>(&mut matches, 0x1405);
    assert_eq!(found[1], 31, "push immediate should be 31 (0x1f)");
}

/// `66 b8 10 00` at RVA 0x4fba: mov ax, 16.
#[test]
fn pe64_scanner_read_u16_reads_mov_ax_imm16() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("66 b8 u2"));
    let found = find_match_at::<2, _>(&mut matches, 0x4fba);
    assert_eq!(found[1], 16, "mov ax immediate should be 16");
}

/// `48 8b` at RVA 0x1027 is separated from `48 89` by 5 bytes.
/// `[3-10]` (exclusive upper → SkipRange(3,9)) covers gap=5.
#[test]
fn pe64_scanner_skip_range_bridges_variable_gap() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("48 8b [3-10] 48 89"));
    let found = find_match_at::<1, _>(&mut matches, 0x1027);
    assert_eq!(found[0], 0x1027);
}

/// Every match of `@4 <bytes>` must start at a 16-byte-aligned RVA.
#[test]
fn pe64_scanner_aligned_only_matches_at_aligned_rvas() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut save = [0u64; 1];
    let mut matches = file.scanner().matches_code(pat!("@4 48 8b"));
    while matches.next(&mut save) {
        assert_eq!(
            save[0] % 16,
            0,
            "RVA 0x{:x} is not 16-byte aligned",
            save[0]
        );
    }
}

/// `48 8b 2d` at RVA 0x1100 is 16-byte aligned.
#[test]
fn pe64_scanner_aligned_matches_known_aligned_instruction() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut matches = file.scanner().matches_code(pat!("@4 48 8b 2d"));
    let found = find_match_at::<1, _>(&mut matches, 0x1100);
    assert_eq!(found[0], 0x1100);
    assert_eq!(found[0] % 16, 0);
}

/// Both `85 c0` (test eax,eax) and `48 85 c0` (test rax,rax) appear in .text.
#[test]
fn pe64_scanner_case_break_matches_both_alternatives() {
    use goblin_lite::pattern as pat;
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).unwrap();

    let mut save = [0u64; 1];
    let mut matches = file.scanner().matches_code(pat!("(85 c0 | 48 85 c0)"));

    let mut found_32bit = false; // `85 c0` at RVA 0x106c
    let mut found_64bit = false; // `48 85 c0` at RVA 0x10a3

    while matches.next(&mut save) {
        if save[0] == 0x106c {
            found_32bit = true;
        }
        if save[0] == 0x10a3 {
            found_64bit = true;
        }
        if found_32bit && found_64bit {
            break;
        }
    }

    assert!(
        found_32bit,
        "32-bit `test eax,eax` (85 c0) at RVA 0x106c should match"
    );
    assert!(
        found_64bit,
        "64-bit `test rax,rax` (48 85 c0) at RVA 0x10a3 should match"
    );
}
