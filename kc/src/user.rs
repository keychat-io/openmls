use crate::identity::Identity;
use crate::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use anyhow::Result;
pub use openmls::group::{GroupId, Member, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig};
use openmls_traits::types::Ciphersuite;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::RwLock;
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
use openmls_traits::OpenMlsProvider;

#[derive(Debug)]
pub struct Group {
    pub mls_group: MlsGroup,
}

pub struct MlsUser {
    pub groups: RwLock<HashMap<String, Group>>,
    pub group_list: HashSet<String>,
    pub identity: RwLock<Identity>,
    pub provider: OpenMlsRustPersistentCrypto,
}

impl MlsUser {
    pub async fn new(provider: OpenMlsRustPersistentCrypto, username: String) -> Result<Self> {
        let user = Self {
            groups: RwLock::new(HashMap::new()),
            group_list: HashSet::new(),
            identity: RwLock::new(Identity::new(
                CIPHERSUITE,
                &provider,
                username.clone().as_bytes(),
            )),
            provider,
        };
        Ok(user)
    }

    pub async fn save(&self, nostr_id: String) -> Result<()> {
        let identity = self
            .identity
            .read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        let identity = serde_json::to_vec(&*identity)?;
        let group_list = serde_json::to_string(&self.group_list)?;
        let result = self.provider
            .storage()
            .save(nostr_id, identity, group_list)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Error save user: {:?}", e);
                Err(e.into())
            }
        }
    }

    pub async fn update(
        &mut self,
        nostr_id: String,
        is_identity: bool,
    ) -> Result<()> {
        let identity = self
            .identity
            .read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        let identity = serde_json::to_vec(&*identity)?;
        let group_list = serde_json::to_string(&self.group_list)?;
        let result = self.provider
            .storage()
            .update(nostr_id, is_identity, identity, group_list)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Error update user: {:?}", e);
                Err(e.into())
            }
        }
    }

    pub async fn load(
        provider: OpenMlsRustPersistentCrypto,
        nostr_id: String,
    ) -> Result<MlsUser> {
        let result = provider.storage().load(nostr_id.clone()).await?;
        let mut user = Self::new(provider, nostr_id.clone()).await?;

        if let Some(re) = result {
            let identity: Vec<u8> = re.0;
            let group_list: Option<String> = re.1;
            let group_list: HashSet<String> =
                serde_json::from_str(&group_list.unwrap_or_default())?;

            user.group_list = group_list;
            user.identity = serde_json::from_slice(&identity)?;

            let mut groups: HashMap<String, Group> = HashMap::new();

            for group_id in &user.group_list {
                let mlsgroup = MlsGroup::load(
                    user.provider.storage(),
                    &GroupId::from_slice(group_id.as_bytes()),
                )?
                .ok_or_else(|| {
                    anyhow::anyhow!("Failed to load MlsGroup for group_id: {}", group_id)
                })?;
                let grp = Group {
                    mls_group: mlsgroup,
                };
                groups.insert(group_id.clone(), grp);
            }
            user.groups = RwLock::new(groups);
            return Ok(user);
        }
        // let user = Self::new(provider, nostr_id.clone()).await?;
        Ok(user)
    }
}
