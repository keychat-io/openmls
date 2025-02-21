//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use std::borrow::Borrow;

pub struct OpenMlsRustPersistentCrypto<C: Codec, ConnectionRef: Borrow<Connection>> {
    pub crypto: RustCrypto,
    pub storage: SqliteStorageProvider<C, ConnectionRef>,
}

impl<C: Codec, ConnectionRef: Borrow<Connection>> OpenMlsRustPersistentCrypto<C, ConnectionRef> {
    pub async fn new(storage: SqliteStorageProvider<C, ConnectionRef>) -> Self {
        let out = Self {
            crypto: RustCrypto::default(),
            storage,
        };
        out
    }
}

impl<C: Codec, ConnectionRef: Borrow<Connection>> OpenMlsProvider
    for OpenMlsRustPersistentCrypto<C, ConnectionRef>
{
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<C, ConnectionRef>;

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
