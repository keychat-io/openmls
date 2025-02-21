//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

pub use openmls_sqlite_storage::SqliteStorageProvider;
use openmls_sqlite_storage::{Codec, Connection};
use openmls_traits::OpenMlsProvider;
use std::borrow::Borrow;

mod provider;
pub use provider::*;

pub struct OpenMlsRustCrypto<C: Codec, ConnectionRef: Borrow<Connection>> {
    crypto: RustCrypto,
    key_store: SqliteStorageProvider<C, ConnectionRef>,
}

impl<C: Codec, ConnectionRef: Borrow<Connection>> OpenMlsProvider
    for OpenMlsRustCrypto<C, ConnectionRef>
{
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<C, ConnectionRef>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
