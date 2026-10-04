#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    password_manager::fuzz_support::native_message(data);
});
