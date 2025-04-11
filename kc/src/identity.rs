use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use std::collections::HashMap;

use super::{openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto, serialize_any_hashmap};
use crate::user::CIPHERSUITE;
use openmls_traits::{storage::StorageProvider, OpenMlsProvider};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct KeyPackageWithTimestamp {
    pub key_package: KeyPackage,
    pub timestamp: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(untagged)]
pub enum KeyPackageValue {
    Old(KeyPackage),
    New(KeyPackageWithTimestamp),
}

impl KeyPackageValue {
    pub fn get_key_package(&self) -> &KeyPackage {
        match self {
            KeyPackageValue::Old(kp) => kp,
            KeyPackageValue::New(kp_with_ts) => &kp_with_ts.key_package,
        }
    }

    pub fn get_timestamp(&self) -> u64 {
        match self {
            KeyPackageValue::Old(_) => 0, // for old return 0
            KeyPackageValue::New(kp_with_ts) => kp_with_ts.timestamp,
        }
    }
}

pub const REQUIRED_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::RequiredCapabilities,
    ExtensionType::LastResort,
    ExtensionType::RatchetTree,
    ExtensionType::Unknown(0xF233),
];

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Identity {
    #[serde(
        serialize_with = "serialize_any_hashmap::serialize_hashmap",
        deserialize_with = "serialize_any_hashmap::deserialize_hashmap"
    )]
    // add create time for kp
    pub kp: HashMap<Vec<u8>, KeyPackageValue>,
    pub credential_with_key: CredentialWithKey,
    pub signer: SignatureKeyPair,
    #[serde(default)]
    pub is_upgraded: bool,
}

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
            is_upgraded: false,
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
        let key_package = KeyPackage::builder()
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

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_secs();

        let key_package_with_timestamp = KeyPackageWithTimestamp {
            key_package: key_package.key_package().clone(),
            timestamp: now,
        };

        self.kp.insert(
            key_package
                .key_package()
                .hash_ref(crypto.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            KeyPackageValue::New(key_package_with_timestamp),
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
        // self.kp.retain(|_, v| *v != &hash_ref.as_slice().to_vec());

        crypto
            .storage()
            .delete_key_package(&hash_ref)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    pub fn delete_key_packages_by_timestamp(
        &mut self,
        timestamp: u64,
        crypto: &OpenMlsRustPersistentCrypto,
    ) -> Result<(), anyhow::Error> {
        // first upgrade old key packages
        let _is_upgrade = self.upgrade_old_key_packages();
        // Collect all keys that need to be removed
        let key_packages_to_remove: Vec<KeyPackage> = self
            .kp
            .iter()
            .filter(|(_, v)| v.get_timestamp() < timestamp)
            .map(|(_k, v)| v.get_key_package().clone())
            .collect();

        // Remove the key packages from storage and HashMap
        for key_package in key_packages_to_remove {
            let hash_ref = key_package
                .hash_ref(crypto.crypto())
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            self.kp.remove(&hash_ref.as_slice().to_vec());
            crypto
                .storage()
                .delete_key_package(&hash_ref)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        }

        Ok(())
    }

    pub fn upgrade_old_key_packages(&mut self) -> bool {
        if self.is_upgraded {
            return false;
        }
        let mut to_upgrade = Vec::new();

        // Find all old key packages
        for (key, value) in &self.kp {
            if let KeyPackageValue::Old(_) = value {
                to_upgrade.push(key.clone());
            }
        }

        // Upgrade them to new format
        for key in to_upgrade {
            if let Some(KeyPackageValue::Old(kp)) = self.kp.remove(&key) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("SystemTime before UNIX EPOCH!")
                    .as_secs();

                let kp_with_ts = KeyPackageWithTimestamp {
                    key_package: kp,
                    timestamp: now,
                };

                self.kp.insert(key, KeyPackageValue::New(kp_with_ts));
            }
        }
        self.is_upgraded = true;
        true
    }
}
