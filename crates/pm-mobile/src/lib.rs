//! Thin Android adapter; all vault rules live in the shared Rust implementation.
#[cfg(target_os = "android")]
mod android {
    use jni::{
        EnvUnowned,
        errors::ThrowRuntimeExAndDefault,
        objects::{JClass, JObject, JString},
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
                let result = (|| -> Result<serde_json::Value, String> {
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
                        .ok_or("Mobile initialization failed")?
                        .call(&request)
                })();
                let mut envelope = match result {
                    Ok(data) => serde_json::json!({"ok":true,"data":data}),
                    Err(error) => serde_json::json!({"ok":false,"error":error}),
                };
                let text = Zeroizing::new(envelope.to_string());
                let result = JString::from_str(env, &*text);
                password_manager::mobile::wipe_response(&mut envelope);
                result
            })
            .resolve::<ThrowRuntimeExAndDefault>()
    }
}
