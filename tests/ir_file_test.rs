#![expect(unused_crate_dependencies, reason = "used in lib/bin")]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn linker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bpf-linker"))
}

fn create_test_ir_file(dir: &Path, name: &str) -> PathBuf {
    let ir_path = dir.join(format!("{}.ll", name));
    let ir_content = format!(
        r#"; ModuleID = '{name}'
source_filename = "{name}"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

define i32 @test_{name}(i32 %x) #0 {{
entry:
  %result = add i32 %x, 1
  ret i32 %result
}}

attributes #0 = {{ noinline nounwind optnone }}

!llvm.module.flags = !{{!0}}
!0 = !{{i32 1, !"wchar_size", i32 4}}
"#
    );
    fs::write(&ir_path, ir_content).expect("Failed to write test IR file");
    ir_path
}

#[test]
fn test_link_ir_file() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let ir_file = create_test_ir_file(temp_dir.path(), "alessandro");
    let output_file = temp_dir.path().join("output.o");

    let output = Command::new(linker_path())
        .arg("--export")
        .arg(format!("test_{}", "alessandro"))
        .arg(&ir_file)
        .arg("-o")
        .arg(&output_file)
        .output()
        .expect("Failed to execute bpf-linker");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("bpf-linker failed with status: {}", output.status);
    }

    assert!(
        output_file.exists(),
        "Output file should exist: {:?}",
        output_file
    );
    assert!(
        output_file.metadata().unwrap().len() > 0,
        "Output file should not be empty"
    );
}

#[test]
fn test_link_multiple_ir_files() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let ir_file1 = create_test_ir_file(temp_dir.path(), "decina");
    let ir_file2 = create_test_ir_file(temp_dir.path(), "despacito");
    let output_file = temp_dir.path().join("output.o");

    let output = Command::new(linker_path())
        .arg("--export")
        .arg("test_decina")
        .arg("--export")
        .arg("test_despacito")
        .arg(&ir_file1)
        .arg(&ir_file2)
        .arg("-o")
        .arg(&output_file)
        .output()
        .expect("Failed to execute bpf-linker");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!(
            "bpf-linker failed with status: {} when linking multiple IR files",
            output.status
        );
    }

    assert!(output_file.exists(), "Output file should exist");
}

#[test]
fn test_link_mixed_ir_and_bitcode() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let ir_file = create_test_ir_file(temp_dir.path(), "toly");
    let bc_file = temp_dir.path().join("bc_part.bc");
    let output_file = temp_dir.path().join("output.o");

    // Create bitcode from IR using llvm-as
    let llvm_as_output = Command::new("llvm-as")
        .arg(&ir_file)
        .arg("-o")
        .arg(&bc_file)
        .output();

    if llvm_as_output.is_err() || !llvm_as_output.as_ref().unwrap().status.success() {
        eprintln!("llvm-as not available or failed, skipping test");
        return;
    }

    // Now create another IR file
    let ir_file2 = create_test_ir_file(temp_dir.path(), "anatoly");

    let output = Command::new(linker_path())
        .arg("--export")
        .arg("test_toly")
        .arg("--export")
        .arg("test_anatoly")
        .arg(&bc_file)
        .arg(&ir_file2)
        .arg("-o")
        .arg(&output_file)
        .output()
        .expect("Failed to execute bpf-linker");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("bpf-linker failed when linking mixed IR and bitcode");
    }

    assert!(
        output_file.exists(),
        "Output file should exist after linking IR and bitcode"
    );
}

#[test]
fn test_invalid_ir_file() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let invalid_ir = temp_dir.path().join("invalid.ll");
    fs::write(&invalid_ir, "This is not valid LLVM IR\n").expect("Failed to write invalid IR");

    let output_file = temp_dir.path().join("output.o");

    let output = Command::new(linker_path())
        .arg(&invalid_ir)
        .arg("-o")
        .arg(&output_file)
        .output()
        .expect("Failed to execute bpf-linker");

    // Should fail with invalid IR
    assert!(
        !output.status.success(),
        "bpf-linker should fail with invalid IR"
    );
}
