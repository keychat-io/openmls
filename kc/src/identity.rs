use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_sqlite_storage::{Codec, Connection};
use openmls_traits::OpenMlsProvider;
use std::collections::HashMap;
use std::{borrow::Borrow, marker::PhantomData};

use super::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;

#[derive(Clone)]
pub struct Identity<C: Codec, ConnectionRef: Borrow<Connection>> {
    pub kp: HashMap<Vec<u8>, KeyPackage>,
    pub credential_with_key: CredentialWithKey,
    pub signer: SignatureKeyPair,
    _codec: PhantomData<C>,
    _phantom: PhantomData<ConnectionRef>,
}

impl<C: Codec, ConnectionRef: Borrow<Connection>> Identity<C, ConnectionRef> {
    pub fn new(
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto<C, ConnectionRef>,
        username: &[u8],
    ) -> Self {
        let credential = BasicCredential::new(username.to_vec());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };
        signature_keys.store(crypto.storage()).unwrap();

        Self {
            kp: HashMap::from([]),
            credential_with_key,
            signer: signature_keys,
            _codec: PhantomData,
            _phantom: PhantomData,
        }
    }

    /// Create an additional key package using the credential_with_key/signer
    /// bound to this identity
    pub fn add_key_package(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto<C, ConnectionRef>,
    ) -> KeyPackage {
        let key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                crypto,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .unwrap();

        self.kp.insert(
            key_package
                .key_package()
                .hash_ref(crypto.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            key_package.key_package().clone(),
        );
        key_package.key_package().clone()
    }

    /// Get the plain identity as byte vector.
    pub fn identity(&self) -> &[u8] {
        self.credential_with_key.credential.serialized_content()
    }

    /// Get the plain identity as byte vector.
    pub fn identity_as_string(&self) -> String {
        std::str::from_utf8(self.credential_with_key.credential.serialized_content())
            .unwrap()
            .to_string()
    }
}
