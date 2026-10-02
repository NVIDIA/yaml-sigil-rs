// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

// Linking this consumer on a target without std must require neither an
// allocator nor an allocation-error handler. The alloc profile provides a
// negative control for the same link check.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// This isolated link fixture owns its sole entry symbol. Exporting it keeps
// the portable contract reachable during linking without a hosted runtime.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    assert!(yaml_sigil_no_std_consumer::allocator_free_contract());
    loop {
        core::hint::spin_loop();
    }
}
