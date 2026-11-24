//! Thin Android adapter; all vault rules live in the shared Rust implementation.
#[cfg(target_os = "android")]
mod android {
    use jni::{
        EnvUnowned,
        errors::ThrowRuntimeExAndDefault,
        objects::{JByteArray, JClass, JObject, JString},
    };
    use password_manager::mobile::{Cancellation, MobileVault};
    use std::{
        path::PathBuf,
        sync::{Mutex, OnceLock},
    };
    use zeroize::Zeroizing;

    static CANCELLED: Cancellation = Cancellation::new();
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_dev_nelszack_passwordmanager_NativeBridge_invalidate(
        _: EnvUnowned<'_>,
        _: JClass<'_>,
    ) {
        CANCELLED.signal();
    }

    /// Calls may arrive from several app threads. The vault serializes its
    /// own state and releases it during network transfers, so a sync never
    /// blocks autofill.
    static VAULT: OnceLock<MobileVault> = OnceLock::new();
    static INIT: Mutex<()> = Mutex::new(());

    /// The process-wide vault, created on first use in the app's directory.
    fn vault(directory: String) -> Result<&'static MobileVault, String> {
        if VAULT.get().is_none() {
            let _init = INIT.lock().map_err(|_| "Mobile initialization failed")?;
            if VAULT.get().is_none() {
                let mut vault = MobileVault::new(PathBuf::from(directory))?;
                vault.set_cancellation(&CANCELLED);
                let _ = VAULT.set(vault);
            }
        }
        VAULT
            .get()
            .ok_or_else(|| "Mobile initialization failed".into())
    }

    fn envelope(result: Result<serde_json::Value, String>) -> serde_json::Value {
        match result {
            Ok(data) => serde_json::json!({"ok":true,"data":data}),
            Err(error) => serde_json::json!({"ok":false,"error":error}),
        }
    }

    /// Like `call`, with file content as raw bytes in both directions:
    /// `data` (may be null) is the request's content, and the reply is one
    /// array holding a 4-byte big-endian JSON length, the JSON envelope, and
    /// then any file content the operation returned.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_dev_nelszack_passwordmanager_NativeBridge_callBytes<'local>(
        mut unowned: EnvUnowned<'local>,
        _: JClass<'local>,
        context: JObject<'local>,
        directory: JString<'local>,
        request: JString<'local>,
        data: JByteArray<'local>,
    ) -> JByteArray<'local> {
        unowned
            .with_env(|env| -> jni::errors::Result<JByteArray<'local>> {
                rustls_platform_verifier::android::init_with_env(env, context)?;
                let directory = directory.try_to_string(env)?;
                let request = Zeroizing::new(request.try_to_string(env)?);
                let data = if data.is_null() {
                    None
                } else {
                    Some(Zeroizing::new(env.convert_byte_array(&data)?))
                };
                let (result, content) =
                    match vault(directory).and_then(|vault| vault.call_binary(&request, data)) {
                        Ok((value, content)) => (Ok(value), content),
                        Err(error) => (Err(error), None),
                    };
                let mut envelope = envelope(result);
                let text = Zeroizing::new(envelope.to_string());
                password_manager::mobile::wipe_response(&mut envelope);
                let content = content.unwrap_or_default();
                let reply = JByteArray::new(env, 4 + text.len() + content.len())?;
                let header = (text.len() as u32).to_be_bytes();
                // SAFETY: u8 and i8 have the same size and alignment; the bits pass unchanged.
                let signed = |bytes: &[u8]| -> &[i8] { unsafe { std::mem::transmute(bytes) } };
                reply.set_region(env, 0, signed(&header))?;
                reply.set_region(env, 4, signed(text.as_bytes()))?;
                reply.set_region(env, (4 + text.len()) as i32, signed(&content))?;
                Ok(reply)
            })
            .resolve::<ThrowRuntimeExAndDefault>()
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_dev_nelszack_passwordmanager_NativeBridge_call<'local>(
        mut unowned: EnvUnowned<'local>,
        _: JClass<'local>,
        context: JObject<'local>,
        directory: JString<'local>,
        request: JString<'local>,
    ) -> JString<'local> {
        unowned
            .with_env(|env| -> jni::errors::Result<JString<'local>> {
                // reqwest uses Android's certificate verifier. Initialize its JVM
                // context and bundled Kotlin verifier before constructing any client.
                rustls_platform_verifier::android::init_with_env(env, context)?;
                let directory = directory.try_to_string(env)?;
                let request = Zeroizing::new(request.try_to_string(env)?);
                let result = vault(directory).and_then(|vault| vault.call(&request));
                let mut envelope = envelope(result);
                let text = Zeroizing::new(envelope.to_string());
                let result = JString::from_str(env, &*text);
                password_manager::mobile::wipe_response(&mut envelope);
                result
            })
            .resolve::<ThrowRuntimeExAndDefault>()
    }
}
