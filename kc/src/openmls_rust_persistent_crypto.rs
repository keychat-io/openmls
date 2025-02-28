//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub struct OpenMlsRustPersistentCrypto {
    pub crypto: RustCrypto,
    pub storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl OpenMlsRustPersistentCrypto {
    pub async fn new(storage: SqliteStorageProvider<JsonCodec, Connection>) -> Self {
        let out = Self {
            crypto: RustCrypto::default(),
            storage,
        };
        out
    }
}

impl Default for OpenMlsRustPersistentCrypto {
    fn default() -> Self {
        let connection = Connection::open_in_memory().unwrap();
        let mut storage = SqliteStorageProvider::new(connection);
        storage.initialize().unwrap();
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

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
