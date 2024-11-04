//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use openmls_rust_crypto::{RustCrypto, SqliteStorage};
use openmls_sqlite_storage::MLSLitePool;
use openmls_traits::OpenMlsProvider;

#[derive(Default, Debug)]
pub struct OpenMlsRustPersistentCrypto {
    pub crypto: RustCrypto,
    pub storage: SqliteStorage,
}

impl OpenMlsRustPersistentCrypto {
    pub async fn new(username: String, pool: MLSLitePool) -> Self {
        let out = Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorage::new(username, pool).await,
        };
        out
    }
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
