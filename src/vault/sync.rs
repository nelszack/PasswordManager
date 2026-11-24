//! Applying cloud snapshots stays on the vault owner's queue.
use super::*;

/// Start of the error returned for a cloud snapshot that is not newer than
/// the local vault. The full message points the user to a conflict review;
/// no host matches on this prefix.
pub(crate) const ROLLBACK_PREFIX: &str = "Cloud copy is not newer than this vault";

/// Constructed only from authenticated remote data or this vault's validated merge.
pub(crate) struct PreparedCloud {
    pub(super) data: VaultData,
    pub(super) bytes: Vec<u8>,
    pub(super) credentials: VaultCredentials,
}

impl Vault {
    pub(crate) fn sync_path(&self) -> Result<std::path::PathBuf, String> {
        match &self.store {
            VaultStore::File {
                directory,
                filename,
            } => Ok(directory.join(filename)),
            _ => Err("Only saved vaults can synchronize".into()),
        }
    }
    pub(crate) fn apply_cloud(
        &mut self,
        credentials: &mut VaultCredentials,
        bytes: &[u8],
    ) -> Result<(), String> {
        let mut key = credentials.clone();
        let plaintext = decrypt_file(&mut key, bytes).ok_or(
            "Cannot decrypt cloud update with this session key; the password/key may have changed on another device. Download a comparison copy with the new credentials; local vault preserved.",
        )?;
        let data = persistence::decode_document(&plaintext).map_err(|e| e.to_string())?;
        if data.vault_id != self.vault_id() {
            return Err("Cloud update has the wrong encrypted vault identity".into());
        }
        // Server versions are random, so only the authenticated revision orders
        // snapshots. Every legitimate change (edit, merge, rekey) advances it;
        // an older or sibling snapshot is a restored or rolled-back server copy.
        // An equal revision is accepted only when its contents are equivalent
        // (for example, a re-encryption of the same state).
        if data.revision < self.data.revision
            || (data.revision == self.data.revision && !conflicts::equivalent(&self.data, &data))
        {
            return Err(format!(
                "{ROLLBACK_PREFIX} (cloud revision {}, local revision {}); the server may have \
                 been restored or rolled back. Local vault preserved; review conflicts to choose \
                 which values to keep.",
                data.revision, self.data.revision
            ));
        }
        self.persist_cloud_data(credentials, data, key, bytes)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn apply_prepared_cloud(
        &mut self,
        credentials: &mut VaultCredentials,
        prepared: PreparedCloud,
    ) -> Result<(), VaultError> {
        self.persist_cloud_data(
            credentials,
            prepared.data,
            prepared.credentials,
            &prepared.bytes,
        )
    }
    fn persist_cloud_data(
        &mut self,
        credentials: &mut VaultCredentials,
        mut data: VaultData,
        key: VaultCredentials,
        bytes: &[u8],
    ) -> Result<(), VaultError> {
        let VaultStore::File {
            directory,
            filename,
        } = &self.store
        else {
            return Err(VaultError::Persistence("Vault has no file".into()));
        };
        let result = persistence::persist_ciphertext(directory, filename, bytes);
        if result.as_ref().map_or_else(|e| e.committed(), |_| true) {
            // A snapshot replacement invalidates every prior Duo review, even
            // when the prepared merge retained an otherwise unchanged item.
            for item in data.items.values_mut() {
                if let Some(duo) = &mut item.duo {
                    duo.review_key.zeroize();
                }
            }
            self.data = data;
            self.metadata.duo_session.zeroize();
            *credentials = key;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_snapshots_must_advance_the_authenticated_revision() {
        let vault = Vault::from_entries(
            vec![VaultEntry {
                id: 1,
                name: "Current".into(),
                ..Default::default()
            }],
            None,
        );
        let (directory, mut vault, mut credentials) =
            crate::vault::test::persist_fixture(vault, "rollback.enc");
        let path = directory.path().join("rollback.enc");
        let encrypt = |data: &VaultData, credentials: &VaultCredentials| {
            let plaintext = persistence::encode_document(data, None).unwrap();
            try_encrypt_file_in_place(&mut credentials.clone(), plaintext.to_vec()).unwrap()
        };
        vault.data.revision = 5;
        let original_file = fs::read(&path).unwrap();
        let original = vault.data.clone();
        // An older snapshot, and a different snapshot claiming the same revision.
        let mut older = vault.data.clone();
        older.revision = 4;
        older.items.get_mut(&ItemId(1)).unwrap().entry.name = "Restored".into();
        let mut sibling = older.clone();
        sibling.revision = 5;
        for data in [&older, &sibling] {
            let bytes = encrypt(data, &credentials);
            let error = vault.apply_cloud(&mut credentials, &bytes).unwrap_err();
            assert!(error.starts_with(ROLLBACK_PREFIX), "{error}");
            assert_eq!(vault.data, original);
            assert_eq!(fs::read(&path).unwrap(), original_file);
        }
        // Re-encrypting the same state at the same revision is harmless.
        let same = encrypt(&vault.data, &credentials);
        vault.apply_cloud(&mut credentials, &same).unwrap();
        assert_eq!(fs::read(&path).unwrap(), same);
        let mut newer = older;
        newer.revision = 6;
        let bytes = encrypt(&newer, &credentials);
        vault.apply_cloud(&mut credentials, &bytes).unwrap();
        assert_eq!(vault.data, newer);
    }

    #[test]
    fn prepared_merge_adopts_data_only_when_replacement_commits() {
        for fault in [0, 1, 2] {
            let mut vault = Vault::from_entries(
                vec![
                    VaultEntry {
                        id: 1,
                        name: "Local".into(),
                        password: "local-secret".into(),
                        ..Default::default()
                    },
                    VaultEntry {
                        id: 2,
                        name: "Unchanged".into(),
                        ..Default::default()
                    },
                ],
                None,
            );
            let duo_key = crate::duo::crypto::new_key().unwrap();
            vault.item_mut(2).unwrap().duo = Some(DuoRecord {
                credentials: DuoCredentials {
                    host: "api-test.duosecurity.com".into(),
                    akey: "syntheticAccount".into(),
                    pkey: "syntheticDevice".into(),
                    private_key: crate::duo::crypto::private_pem(&duo_key)
                        .unwrap()
                        .to_string()
                        .into(),
                },
                review_key: Some([37; 32]),
            });
            let (directory, mut vault, mut credentials) =
                crate::vault::test::persist_fixture(vault, "test.enc");
            let original = vault.data.clone();
            let original_file = fs::read(directory.path().join("test.enc")).unwrap();
            let mut remote = vault.clone();
            remote.item_mut(1).unwrap().entry.name = "Remote".into();
            let mut plaintext = persistence::encode_document(&remote.data, None).unwrap();
            let bytes = try_encrypt_file_in_place(
                &mut credentials.clone(),
                std::mem::take(&mut *plaintext),
            )
            .unwrap();
            let choices = vec![crate::cloud::Choice {
                id: 1,
                field: "name".into(),
                side: crate::cloud::Side::Remote,
            }];
            let prepared = vault.merge_cloud(&credentials, &bytes, &choices).unwrap();
            let mut expected = prepared.data.clone();
            assert!(
                expected.items[&ItemId(2)]
                    .duo
                    .as_ref()
                    .unwrap()
                    .review_key
                    .is_some()
            );
            expected
                .items
                .get_mut(&ItemId(2))
                .unwrap()
                .duo
                .as_mut()
                .unwrap()
                .review_key = None;
            let expected_file = prepared.bytes.clone();
            let result = persistence::with_write_fault(fault, || {
                vault.apply_prepared_cloud(&mut credentials, prepared)
            });
            if fault == 1 {
                assert!(!result.unwrap_err().committed());
                assert_eq!(vault.data, original);
                assert_eq!(
                    fs::read(directory.path().join("test.enc")).unwrap(),
                    original_file
                );
            } else {
                if fault == 2 {
                    assert!(result.unwrap_err().committed());
                } else {
                    result.unwrap();
                }
                assert_eq!(vault.data, expected);
                assert_eq!(
                    fs::read(directory.path().join("test.enc")).unwrap(),
                    expected_file
                );
                let decoded = decrypt_file(&mut credentials, &expected_file).unwrap();
                assert_eq!(persistence::decode_document(&decoded).unwrap(), expected);
            }
        }
    }
}

/// The shared engine against a scripted peer that honors conditional requests.
#[cfg(test)]
mod engine_tests {
    use super::*;
    use crate::cloud::{
        CloudClient, binding,
        engine::{self, Bind, Snapshot, Stuck, SyncHost},
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct Remote {
        bytes: Vec<u8>,
        version: u64,
        log: Vec<String>,
    }
    fn tag(version: u64) -> String {
        format!("\"{version:032x}\"")
    }
    fn serve(remote: Arc<Mutex<Remote>>) -> String {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", socket.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in socket.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut head = Vec::new();
                let mut byte = [0];
                while !head.ends_with(b"\r\n\r\n") && stream.read_exact(&mut byte).is_ok() {
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap().to_lowercase();
                let header = |name: &str| {
                    head.lines()
                        .find_map(|l| l.strip_prefix(&format!("{name}: ")))
                        .map(str::to_owned)
                };
                let length = header("content-length").map_or(0, |v| v.parse().unwrap());
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let method = head.split_whitespace().next().unwrap().to_uppercase();
                let mut remote = remote.lock().unwrap();
                let current = tag(remote.version);
                let condition = header("if-match")
                    .map(|v| format!(" if-match {v}"))
                    .or_else(|| header("if-none-match").map(|v| format!(" if-none-match {v}")))
                    .unwrap_or_default();
                remote.log.push(format!("{method}{condition}"));
                let (code, response) = match method.as_str() {
                    "HEAD" | "GET" if remote.version == 0 => (404, vec![]),
                    "GET" if header("if-none-match") == Some(current.clone()) => (304, vec![]),
                    "HEAD" | "GET" => (200, remote.bytes.clone()),
                    "PUT" => {
                        let allowed = if remote.version == 0 {
                            header("if-none-match").as_deref() == Some("*")
                        } else {
                            header("if-match") == Some(current)
                        };
                        if allowed {
                            remote.bytes = body;
                            remote.version += 1;
                            let ack = format!("{{\"version\":\"{:032x}\"}}", remote.version);
                            (200, ack.into_bytes())
                        } else {
                            (412, vec![])
                        }
                    }
                    _ => (405, vec![]),
                };
                let reply = format!(
                    "HTTP/1.1 {code} Reply\r\nConnection: close\r\nContent-Length: {}\r\nETag: \
                     {}\r\n\r\n",
                    response.len(),
                    tag(remote.version)
                );
                let _ = stream.write_all(reply.as_bytes());
                if method != "HEAD" {
                    let _ = stream.write_all(&response);
                }
            }
        });
        url
    }

    struct Host {
        url: String,
        vault: Mutex<(Vault, VaultCredentials)>,
    }
    impl crate::operations::VaultHost for Host {
        fn with_session<T: Send + 'static>(
            &self,
            _: Option<String>,
            apply: impl FnOnce(&mut Vault, &mut VaultCredentials) -> Result<T, VaultError>
            + Send
            + 'static,
        ) -> impl std::future::Future<Output = Result<Result<T, VaultError>, String>> + Send
        {
            let mut guard = self.vault.lock().unwrap();
            let (vault, credentials) = &mut *guard;
            let result = apply(vault, credentials);
            async move { Ok(result) }
        }
        fn staleness(&self, _: Option<String>, _: Option<u64>) -> crate::operations::Stale {
            std::sync::Arc::new(|| false)
        }
        fn blocking<T: Send + 'static>(
            &self,
            work: impl FnOnce() -> T + Send + 'static,
        ) -> crate::operations::Blocking<T> {
            let result = work();
            Box::pin(async move { Some(result) })
        }
    }
    impl SyncHost for Host {
        fn client(&self) -> impl std::future::Future<Output = Result<CloudClient, String>> + Send {
            let client = CloudClient::with_token(&self.url, Zeroizing::new("1".repeat(64)));
            async move { client }
        }
        fn snapshot(&self) -> impl std::future::Future<Output = Result<Snapshot, String>> + Send {
            let guard = self.vault.lock().unwrap();
            let snapshot = guard.0.sync_path().and_then(|path| {
                Ok(Snapshot {
                    bytes: fs::read(&path).map_err(|e| e.to_string())?,
                    state: binding(&path)?,
                    id: hex::encode(guard.0.vault_id()),
                    session: "session".into(),
                    path,
                })
            });
            async move { snapshot }
        }
        fn directory(&self) -> std::path::PathBuf {
            std::env::temp_dir()
        }
    }

    fn encrypt(data: &VaultData, credentials: &VaultCredentials) -> Vec<u8> {
        let plaintext = persistence::encode_document(data, None).unwrap();
        try_encrypt_file_in_place(&mut credentials.clone(), plaintext.to_vec()).unwrap()
    }
    /// Another device publishes `data` as the next cloud version.
    fn publish(remote: &Mutex<Remote>, bytes: Vec<u8>) -> String {
        let mut remote = remote.lock().unwrap();
        remote.bytes = bytes;
        remote.version += 1;
        format!("{:032x}", remote.version)
    }
    fn requests(remote: &Mutex<Remote>) -> Vec<String> {
        std::mem::take(&mut remote.lock().unwrap().log)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_conditional_request_per_sync_and_rollback_needs_review() {
        let vault = Vault::from_entries(
            vec![VaultEntry {
                id: 1,
                name: "Original".into(),
                ..Default::default()
            }],
            None,
        );
        let (_directory, vault, credentials) =
            crate::vault::test::persist_fixture(vault, "engine.enc");
        let remote = Arc::new(Mutex::new(Remote::default()));
        let host = Host {
            url: serve(remote.clone()),
            vault: Mutex::new((vault, credentials.clone())),
        };
        engine::sync(&host, None, Bind::Enable).await.unwrap();
        assert_eq!(requests(&remote), ["PUT if-none-match *"]);
        // Nothing changed locally: a conditional download answered 304.
        assert_eq!(
            engine::sync(&host, None, Bind::Existing).await.unwrap(),
            "Vault is up to date"
        );
        assert_eq!(requests(&remote), [format!("GET if-none-match {}", tag(1))]);

        // A newer cloud snapshot arrives with its version in the same response.
        let mut newer = host.vault.lock().unwrap().0.data.clone();
        newer.revision += 1;
        newer.items.get_mut(&ItemId(1)).unwrap().entry.name = "Cloud edit".into();
        publish(&remote, encrypt(&newer, &credentials));
        engine::sync(&host, None, Bind::Existing).await.unwrap();
        assert_eq!(requests(&remote), [format!("GET if-none-match {}", tag(1))]);
        assert_eq!(host.vault.lock().unwrap().0.data, newer);

        // A replayed older snapshot is not applied and is reported as stuck.
        let path = host.vault.lock().unwrap().0.sync_path().unwrap();
        let local_file = fs::read(&path).unwrap();
        let mut older = newer.clone();
        older.revision -= 1;
        let version = publish(&remote, encrypt(&older, &credentials));
        let error = engine::sync_checked(&host, None, Bind::Existing)
            .await
            .unwrap_err();
        assert!(
            error.message.starts_with(ROLLBACK_PREFIX),
            "{}",
            error.message
        );
        let stuck = error.stuck.expect("rollback waits for a change");
        assert_eq!(
            stuck,
            Stuck {
                remote: Some(version),
                local: crate::cloud::digest(&local_file),
            }
        );
        assert_eq!(host.vault.lock().unwrap().0.data, newer);
        assert_eq!(fs::read(&path).unwrap(), local_file);
        requests(&remote);
        assert!(engine::still_stuck(&host, &stuck).await.unwrap());
        assert_eq!(requests(&remote), ["HEAD"], "no full download while stuck");

        // Local and cloud both change: one rejected upload, one comparison download.
        let mut local = newer.clone();
        local.revision += 5;
        local.items.get_mut(&ItemId(1)).unwrap().entry.name = "Local edit".into();
        fs::write(&path, encrypt(&local, &credentials)).unwrap();
        assert!(!engine::still_stuck(&host, &stuck).await.unwrap());
        requests(&remote);
        let error = engine::sync_checked(&host, None, Bind::Existing)
            .await
            .unwrap_err();
        assert!(error.message.contains("conflict"), "{}", error.message);
        assert!(error.stuck.is_some());
        assert_eq!(
            requests(&remote),
            [format!("PUT if-match {}", tag(2)), "GET".to_owned()]
        );
        assert_eq!(
            binding(&path).unwrap().unwrap().version,
            Some(format!("{:032x}", 2))
        );
    }
}
