mod di;
mod iter;
mod types;

use std::{
    borrow::Cow,
    collections::HashSet,
    ffi::{c_void, CStr, CString},
    os::raw::c_char,
    ptr, slice, str,
};

pub(crate) use di::DISanitizer;
use iter::{IterModuleFunctions as _, IterModuleGlobalAliases as _, IterModuleGlobals as _};
use llvm_sys::{
    bit_reader::LLVMParseBitcodeInContext2,
    core::{
        LLVMCountBasicBlocks, LLVMCreateMemoryBufferWithMemoryRange, LLVMDisposeMemoryBuffer,
        LLVMDisposeMessage, LLVMDisposeModule, LLVMGetDiagInfoDescription, LLVMGetDiagInfoSeverity,
        LLVMGetEnumAttributeKindForName, LLVMGetMDString, LLVMGetModuleInlineAsm, LLVMGetTarget,
        LLVMGetValueName2, LLVMIsAFunction, LLVMModuleCreateWithNameInContext,
        LLVMPrintModuleToFile, LLVMRemoveEnumAttributeAtIndex, LLVMSetLinkage,
        LLVMSetModuleInlineAsm2, LLVMSetVisibility,
    },
    debuginfo::LLVMStripModuleDebugInfo,
    error::{
        LLVMDisposeErrorMessage, LLVMGetErrorMessage, LLVMGetErrorTypeId, LLVMGetStringErrorTypeId,
    },
    ir_reader::LLVMParseIRInContext,
    linker::LLVMLinkModules2,
    object::{
        LLVMCreateBinary, LLVMDisposeBinary, LLVMDisposeSectionIterator, LLVMGetSectionContents,
        LLVMGetSectionName, LLVMGetSectionSize, LLVMMoveToNextSection,
        LLVMObjectFileCopySectionIterator, LLVMObjectFileIsSectionIteratorAtEnd,
    },
    prelude::{LLVMContextRef, LLVMDiagnosticInfoRef, LLVMModuleRef, LLVMValueRef},
    support::LLVMParseCommandLineOptions,
    target::{
        LLVMInitializeBPFAsmParser, LLVMInitializeBPFAsmPrinter, LLVMInitializeBPFDisassembler,
        LLVMInitializeBPFTarget, LLVMInitializeBPFTargetInfo, LLVMInitializeBPFTargetMC,
    },
    target_machine::{
        LLVMCodeGenFileType, LLVMCodeGenOptLevel, LLVMCodeModel, LLVMCreateTargetMachine,
        LLVMGetTargetFromTriple, LLVMRelocMode, LLVMTargetMachineEmitToFile, LLVMTargetMachineRef,
        LLVMTargetRef,
    },
    transforms::pass_builder::{
        LLVMCreatePassBuilderOptions, LLVMDisposePassBuilderOptions, LLVMRunPasses,
    },
    LLVMAttributeFunctionIndex, LLVMLinkage, LLVMVisibility,
};
use tracing::{debug, error, info};

use crate::OptLevel;

pub(crate) fn init(args: &[Cow<'_, CStr>], overview: &CStr) {
    unsafe {
        LLVMInitializeBPFTarget();
        LLVMInitializeBPFTargetMC();
        LLVMInitializeBPFTargetInfo();
        LLVMInitializeBPFAsmPrinter();
        LLVMInitializeBPFAsmParser();
        LLVMInitializeBPFDisassembler();
    }

    let c_ptrs = args.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    unsafe { LLVMParseCommandLineOptions(c_ptrs.len() as i32, c_ptrs.as_ptr(), overview.as_ptr()) };
}

pub(crate) fn create_module(name: &CStr, context: LLVMContextRef) -> Option<LLVMModuleRef> {
    let module = unsafe { LLVMModuleCreateWithNameInContext(name.as_ptr(), context) };

    if module.is_null() {
        return None;
    }

    Some(module)
}

pub(crate) fn find_embedded_bitcode(
    context: LLVMContextRef,
    data: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let buffer_name = c"mem_buffer";
    let buffer = unsafe {
        LLVMCreateMemoryBufferWithMemoryRange(
            data.as_ptr().cast(),
            data.len(),
            buffer_name.as_ptr(),
            0,
        )
    };

    let (bin, message) =
        Message::with(|message| unsafe { LLVMCreateBinary(buffer, context, message) });
    if bin.is_null() {
        return Err(message.as_string_lossy().to_string());
    }

    let mut ret = None;
    let iter = unsafe { LLVMObjectFileCopySectionIterator(bin) };
    while unsafe { LLVMObjectFileIsSectionIteratorAtEnd(bin, iter) } == 0 {
        let name = unsafe { LLVMGetSectionName(iter) };
        if !name.is_null() {
            let name = unsafe { CStr::from_ptr(name) };
            if name == c".llvmbc" {
                let buf = unsafe { LLVMGetSectionContents(iter) };
                let size = unsafe { LLVMGetSectionSize(iter) } as usize;
                ret = Some(unsafe { slice::from_raw_parts(buf.cast(), size).to_vec() });
                break;
            }
        }
        unsafe { LLVMMoveToNextSection(iter) };
    }
    unsafe { LLVMDisposeSectionIterator(iter) };
    unsafe { LLVMDisposeBinary(bin) };
    unsafe { LLVMDisposeMemoryBuffer(buffer) };

    Ok(ret)
}

#[must_use]
pub(crate) fn link_bitcode_buffer(
    context: LLVMContextRef,
    module: LLVMModuleRef,
    buffer: &[u8],
) -> bool {
    let mut linked = false;
    let buffer_name = c"mem_buffer";
    let buffer = unsafe {
        LLVMCreateMemoryBufferWithMemoryRange(
            buffer.as_ptr().cast(),
            buffer.len(),
            buffer_name.as_ptr(),
            0,
        )
    };

    let mut temp_module = ptr::null_mut();

    if unsafe { LLVMParseBitcodeInContext2(context, buffer, &mut temp_module) } == 0 {
        linked = unsafe { LLVMLinkModules2(module, temp_module) } == 0;
    }

    unsafe { LLVMDisposeMemoryBuffer(buffer) };

    linked
}

#[must_use]
pub(crate) fn link_ir_buffer(
    context: LLVMContextRef,
    module: LLVMModuleRef,
    buffer: &[u8],
) -> bool {
    let mut linked = false;
    let buffer_name = c"ir_buffer";
    let buffer = unsafe {
        LLVMCreateMemoryBufferWithMemoryRange(
            buffer.as_ptr().cast(),
            buffer.len(),
            buffer_name.as_ptr(),
            1, // IR, so null-terminated
        )
    };

    let mut temp_module = ptr::null_mut();
    let mut error_msg = ptr::null_mut();

    if unsafe { LLVMParseIRInContext(context, buffer, &mut temp_module, &mut error_msg) } == 0 {
        if temp_module.is_null() {
            error!("IR parsing succeeded but module is null");
        } else {
            linked = unsafe { LLVMLinkModules2(module, temp_module) } == 0;
        }
    } else {
        if !error_msg.is_null() {
            let err_str = unsafe { CStr::from_ptr(error_msg) };
            error!("failed to parse IR: {:?}", err_str);
            unsafe { LLVMDisposeMessage(error_msg) };
        } else {
            error!("failed to parse IR: unknown error");
        }
        if !temp_module.is_null() {
            unsafe { LLVMDisposeModule(temp_module) };
        }
    }

    unsafe { LLVMDisposeMemoryBuffer(buffer) };

    linked
}

pub(crate) fn target_from_triple(triple: &CStr) -> Result<LLVMTargetRef, String> {
    let mut target = ptr::null_mut();
    let (ret, message) = Message::with(|message| unsafe {
        LLVMGetTargetFromTriple(triple.as_ptr(), &mut target, message)
    });
    if ret == 0 {
        Ok(target)
    } else {
        Err(message.as_string_lossy().to_string())
    }
}

pub(crate) fn target_from_module(module: LLVMModuleRef) -> Result<LLVMTargetRef, String> {
    let triple = unsafe { LLVMGetTarget(module) };
    unsafe { target_from_triple(CStr::from_ptr(triple)) }
}

pub(crate) fn create_target_machine(
    target: LLVMTargetRef,
    triple: &CStr,
    cpu: &CStr,
    features: &CStr,
) -> Option<LLVMTargetMachineRef> {
    let tm = unsafe {
        LLVMCreateTargetMachine(
            target,
            triple.as_ptr(),
            cpu.as_ptr(),
            features.as_ptr(),
            LLVMCodeGenOptLevel::LLVMCodeGenLevelAggressive,
            LLVMRelocMode::LLVMRelocDefault,
            LLVMCodeModel::LLVMCodeModelDefault,
        )
    };
    if tm.is_null() {
        None
    } else {
        Some(tm)
    }
}

pub(crate) fn optimize(
    tm: LLVMTargetMachineRef,
    module: LLVMModuleRef,
    opt_level: OptLevel,
    ignore_inline_never: bool,
    export_symbols: &HashSet<Cow<'_, [u8]>>,
) -> Result<(), String> {
    if module_asm_is_probestack(module) {
        unsafe { LLVMSetModuleInlineAsm2(module, ptr::null_mut(), 0) };
    }

    for sym in module.globals_iter() {
        internalize(sym, symbol_name(sym), export_symbols);
    }
    for sym in module.global_aliases_iter() {
        internalize(sym, symbol_name(sym), export_symbols);
    }

    for function in module.functions_iter() {
        let name = symbol_name(function);
        if !name.starts_with(b"llvm.") {
            if ignore_inline_never {
                remove_attribute(function, "noinline");
            }
            internalize(function, name, export_symbols);
        }
    }

    let passes = [
        // NB: "default<_>" must be the first pass in the list, otherwise it will be ignored.
        match opt_level {
            // Pretty much nothing compiles with -O0 so make it an alias for -O1.
            OptLevel::No | OptLevel::Less => "default<O1>",
            OptLevel::Default => "default<O2>",
            OptLevel::Aggressive => "default<O3>",
            OptLevel::Size => "default<Os>",
            OptLevel::SizeMin => "default<Oz>",
        },
        // NB: This seems to be included in most default pipelines, but not obviously all of them.
        // See
        // https://github.com/llvm/llvm-project/blob/bbe2887f/llvm/lib/Passes/PassBuilderPipelines.cpp#L2011-L2012
        // for a case which includes DCE only conditionally. Better safe than sorry; include it always.
        "dce",
    ];

    let passes = passes.join(",");
    debug!("running passes: {passes}");
    let passes = CString::new(passes).unwrap();
    let options = unsafe { LLVMCreatePassBuilderOptions() };
    let error = unsafe { LLVMRunPasses(module, passes.as_ptr(), tm, options) };
    unsafe { LLVMDisposePassBuilderOptions(options) };
    // Handle the error and print it to stderr.
    if !error.is_null() {
        let error_type_id = unsafe { LLVMGetErrorTypeId(error) };
        // This is the only error type that exists currently, but there might be more in the future.
        assert_eq!(error_type_id, unsafe { LLVMGetStringErrorTypeId() });
        let error_message = unsafe { LLVMGetErrorMessage(error) };
        let error_string = unsafe { CStr::from_ptr(error_message) }
            .to_string_lossy()
            .to_string();
        unsafe { LLVMDisposeErrorMessage(error_message) };
        return Err(error_string);
    }

    Ok(())
}

/// strips debug information, returns true if DI got stripped
pub(crate) fn strip_debug_info(module: LLVMModuleRef) -> bool {
    unsafe { LLVMStripModuleDebugInfo(module) != 0 }
}

pub(crate) fn module_asm_is_probestack(module: LLVMModuleRef) -> bool {
    let mut len = 0;
    let ptr = unsafe { LLVMGetModuleInlineAsm(module, &mut len) };
    if ptr.is_null() {
        return false;
    }

    let needle = b"__rust_probestack";
    let haystack: &[u8] = unsafe { slice::from_raw_parts(ptr.cast(), len) };
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub(crate) fn symbol_name<'a>(value: *mut llvm_sys::LLVMValue) -> &'a [u8] {
    let mut name_len = 0;
    let ptr = unsafe { LLVMGetValueName2(value, &mut name_len) };
    unsafe { slice::from_raw_parts(ptr.cast(), name_len) }
}

pub(crate) fn remove_attribute(function: *mut llvm_sys::LLVMValue, name: &str) {
    let attr_kind = unsafe { LLVMGetEnumAttributeKindForName(name.as_ptr().cast(), name.len()) };
    unsafe { LLVMRemoveEnumAttributeAtIndex(function, LLVMAttributeFunctionIndex, attr_kind) };
}

pub(crate) fn write_ir(module: LLVMModuleRef, output: &CStr) -> Result<(), String> {
    let (ret, message) =
        Message::with(|message| unsafe { LLVMPrintModuleToFile(module, output.as_ptr(), message) });
    if ret == 0 {
        Ok(())
    } else {
        Err(message.as_string_lossy().to_string())
    }
}

pub(crate) fn codegen(
    tm: LLVMTargetMachineRef,
    module: LLVMModuleRef,
    output: &CStr,
    output_type: LLVMCodeGenFileType,
) -> Result<(), String> {
    let (ret, message) = Message::with(|message| unsafe {
        LLVMTargetMachineEmitToFile(tm, module, output.as_ptr().cast_mut(), output_type, message)
    });
    if ret == 0 {
        Ok(())
    } else {
        Err(message.as_string_lossy().to_string())
    }
}

pub(crate) fn internalize(
    value: LLVMValueRef,
    name: &[u8],
    export_symbols: &HashSet<Cow<'_, [u8]>>,
) {
    if !name.starts_with(b"llvm.") && !export_symbols.contains(name) {
        if unsafe { !LLVMIsAFunction(value).is_null() } {
            let num_blocks = unsafe { LLVMCountBasicBlocks(value) };
            if num_blocks == 0 {
                info!(
                    "not internalizing undefined function {}",
                    str::from_utf8(name).unwrap_or("<invalid utf8>")
                );
                return;
            }
        }
        unsafe { LLVMSetLinkage(value, LLVMLinkage::LLVMInternalLinkage) };
        unsafe { LLVMSetVisibility(value, LLVMVisibility::LLVMDefaultVisibility) };
    }
}

pub(crate) trait LLVMDiagnosticHandler {
    fn handle_diagnostic(
        &mut self,
        severity: llvm_sys::LLVMDiagnosticSeverity,
        message: Cow<'_, str>,
    );
}

pub(crate) extern "C" fn diagnostic_handler<T: LLVMDiagnosticHandler>(
    info: LLVMDiagnosticInfoRef,
    handler: *mut c_void,
) {
    let severity = unsafe { LLVMGetDiagInfoSeverity(info) };
    let message = Message {
        ptr: unsafe { LLVMGetDiagInfoDescription(info) },
    };
    let handler = handler.cast::<T>();
    unsafe { &mut *handler }.handle_diagnostic(severity, message.as_string_lossy());
}

pub(crate) extern "C" fn fatal_error(reason: *const c_char) {
    error!("fatal error: {:?}", unsafe { CStr::from_ptr(reason) })
}

struct Message {
    ptr: *mut c_char,
}

impl Message {
    fn with<T, F: FnOnce(*mut *mut c_char) -> T>(f: F) -> (T, Self) {
        let mut ptr = ptr::null_mut();
        let t = f(&mut ptr);
        (t, Self { ptr })
    }

    fn as_c_str(&self) -> Option<&CStr> {
        let Self { ptr } = self;
        let ptr = *ptr;
        (!ptr.is_null()).then(|| unsafe { CStr::from_ptr(ptr) })
    }

    fn as_string_lossy(&self) -> Cow<'_, str> {
        self.as_c_str()
            .map(CStr::to_bytes)
            .map(String::from_utf8_lossy)
            .unwrap_or("<null>".into())
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        let Self { ptr } = self;
        let ptr = *ptr;
        if !ptr.is_null() {
            unsafe {
                LLVMDisposeMessage(ptr);
            }
        }
    }
}
