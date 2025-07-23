use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use std::collections::HashMap;

use super::{openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto, serialize_any_hashmap};
use crate::user::CIPHERSUITE;
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Identity {
    #[serde(
        serialize_with = "serialize_any_hashmap::serialize_hashmap",
        deserialize_with = "serialize_any_hashmap::deserialize_hashmap"
    )]
    pub kp: HashMap<Vec<u8>, KeyPackage>,
    pub credential_with_key: CredentialWithKey,
    pub signer: SignatureKeyPair,
}

pub const REQUIRED_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::RequiredCapabilities,
    ExtensionType::LastResort,
    ExtensionType::RatchetTree,
    ExtensionType::Unknown(0xF233),
];

impl Identity {
    pub fn new(
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
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
        }
    }

    pub fn ciphersuite_value(&self) -> u16 {
        CIPHERSUITE.into()
    }

    pub fn extensions_value(&self) -> String {
        REQUIRED_EXTENSIONS
            .to_vec()
            .iter()
            .map(|e| format!("{:?}", e))
            .collect::<Vec<String>>()
            .join(",")
    }

    pub fn create_capabilities(&self) -> Result<Capabilities, anyhow::Error> {
        let capabilities: Capabilities = Capabilities::new(
            None,
            Some(&[CIPHERSUITE]),
            Some(REQUIRED_EXTENSIONS),
            None,
            None,
        );
        Ok(capabilities)
    }

    /// Create an additional key package using the credential_with_key/signer
    /// bound to this identity
    pub fn add_key_package(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
        capabilities: Capabilities,
    ) -> KeyPackage {
        // // Build a KeyPackage with a last resort extension
        // let last_resort = Extension::LastResort(LastResortExtension::default());
        // let extensions = Extensions::single(last_resort);
        // use std::time::{SystemTime, UNIX_EPOCH};
        // let now = SystemTime::now()
        //     .duration_since(UNIX_EPOCH)
        //     .expect("SystemTime before UNIX EPOCH!")
        //     .as_secs();
        // let not_before = now - 100;
        // let not_after = now + 100;
        // let lifetime = Lifetime {
        //     not_before,
        //     not_after,
        // };
        // println!("lifetime: {:?}", lifetime);
        let key_package = KeyPackage::builder()
            // .key_package_lifetime(lifetime)
            // .key_package_extensions(extensions)
            // .leaf_node_extensions(extensions)
            .leaf_node_capabilities(capabilities)
            .mark_as_last_resort()
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

    pub fn delete_key_package_from_storage(
        &mut self,
        key_package: KeyPackage,
        crypto: &OpenMlsRustPersistentCrypto,
    ) -> Result<(), anyhow::Error> {
        let hash_ref = key_package
            .hash_ref(crypto.crypto())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        self.kp.remove(&hash_ref.as_slice().to_vec());

        crypto
            .storage()
            .delete_key_package(&hash_ref)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
}
