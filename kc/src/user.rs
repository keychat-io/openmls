use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::RwLock;
pub use openmls::group::{GroupId, Member, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig};
use crate::identity::Identity;
use crate::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use openmls_traits::types::Ciphersuite;
use anyhow::Result;
use anyhow::format_err;
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::Serialize;
pub use sqlx;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::Row;
use sqlx::SqlitePool;

#[derive(Debug)]
pub struct Group {
    pub mls_group: MlsGroup,
}

#[derive(Debug, Clone)]
pub struct MLSLitePool {
    pub db: SqlitePool,
    pub tables: Tables,
}

impl MLSLitePool {
    pub async fn new(db: SqlitePool, tables: Tables) -> anyhow::Result<MLSLitePool> {
        tables.check()?;

        let this = Self { db, tables };
        this.migrate().await?;

        Ok(this)
    }

    /// try open tables
    pub async fn migrate(&self) -> anyhow::Result<()> {
        self.init().await?;
        Ok(())
    }

    /// https://docs.rs/sqlx-sqlite/0.7.1/sqlx_sqlite/struct.SqliteConnectOptions.html#impl-FromStr-for-SqliteConnectOptions
    pub async fn open(dbpath: &str, tables: Tables) -> anyhow::Result<MLSLitePool> {
        let opts = dbpath
            .parse::<SqliteConnectOptions>()
            .expect("error in dbpath parse")
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            // prevent other thread open it
            .locking_mode(sqlx::sqlite::SqliteLockingMode::Normal)
            // or normal
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        log::trace!("SqlitePool open: {:?}", opts);
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            // .max_connections(1)
            .connect_with(opts)
            .await
            .expect("error in connect_with");

        Self::new(db, tables).await
    }

    pub fn database(&self) -> &SqlitePool {
        &self.db
    }

    pub fn tables(&self) -> &Tables {
        &self.tables
    }

    pub async fn init(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.db)
            .await
            .map_err(|e| format_err!("run sqlite migrations failed: {}", e))?;

        Ok(())
    }

    #[inline]
    pub fn definition_user(&self) -> &'static str {
        self.tables.user
    }
}

impl Default for MLSLitePool {
    fn default() -> Self {
        let opts = "./mls-user.sqlite"
            .parse::<SqliteConnectOptions>()
            .expect("error in dbpath parse")
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .locking_mode(sqlx::sqlite::SqliteLockingMode::Normal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        log::trace!("SqlitePool open: {:?}", opts);
        let db = sqlx::sqlite::SqlitePoolOptions::new().connect_lazy_with(opts);

        Self {
            db,
            tables: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tables {
    user: &'static str,
}

impl Default for Tables {
    fn default() -> Self {
        Self {
            user: "user",
        }
    }
}

impl Tables {
    pub fn check(&self) -> anyhow::Result<()> {
        let strs = [self.user];
        let mut names = strs.iter().filter(|s| !s.is_empty()).collect::<Vec<_>>();
        if names.len() != strs.len() {
            return Err(anyhow::anyhow!("empty table name".to_string())); 
        }

        names.dedup();
        if names.len() != strs.len() {
            return Err(anyhow::anyhow!("duplicate table name".to_string()));
        }

        Ok(())
    }
}

pub struct MlsUser {
    pub groups: RwLock<HashMap<String, Group>>,
    pub group_list: HashSet<String>,
    pub identity: RwLock<Identity>,
    pub provider: OpenMlsRustPersistentCrypto,
    pub pool: MLSLitePool,
}

impl MlsUser {
    /// Create a new user with the given name and a fresh set of credentials.
    pub async fn new(username: String, pool: MLSLitePool) -> Result<Self> {
        let db_path = "./mls-base.sqlite";
        let connection = Connection::open(db_path).map_err(|e| {
            format_err!("<MlsUser fn[new]> Failed to open database: {}", e)
        })?;
        let mut storage =
            openmls_sqlite_storage::SqliteStorageProvider::new(connection);
        storage.initialize().map_err(|e| {
            format_err!("<MlsUser fn[new]> Failed to initialize storage: {}", e)
        })?;

        let provider = OpenMlsRustPersistentCrypto::new(storage).await;
        
        let user = Self {
            groups: RwLock::new(HashMap::new()),
            group_list: HashSet::new(),
            identity: RwLock::new(Identity::new(
                CIPHERSUITE,
                &provider,
                username.clone().as_bytes(),
            )),
            provider,
            pool,
        };
        Ok(user)
    }

    pub async fn save(&mut self, nostr_id: String) -> Result<()> {
        let sql = format!("INSERT INTO user (user_id, identity, group_list) values(?, ?, ?)",);
        let identity = self
            .identity
            .read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        let identity = serde_json::to_vec(&*identity)?;
        let group_list = serde_json::to_string(&self.group_list)?;
        let sql = sqlx::query(&sql)
            .bind(nostr_id)
            .bind(&identity)
            .bind(group_list);
        let result = sql.execute(&self.pool.db).await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Error saving user: {:?}", e);
                Err(e.into())
            }
        }
    }

    pub async fn update(&mut self, nostr_id: String, is_identity: bool) -> Result<()> {
        let is_user = MlsUser::load(nostr_id.clone(), self.pool.clone()).await?;
        // if none then insert first
        if is_user.is_none() {
            return self.save(nostr_id).await;
        }
        if is_identity {
            let sql = format!("UPDATE user set identity = ? where user_id = ?",);
            let identity = self
                .identity
                .read()
                .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
            let identity = serde_json::to_vec(&*identity)?;
            sqlx::query(&sql)
                .bind(identity)
                .bind(nostr_id)
                .execute(&self.pool.db)
                .await?;
        } else {
            let sql = format!("UPDATE user set group_list = ? where user_id = ?",);
            let group_list = serde_json::to_string(&self.group_list)?;
            sqlx::query(&sql)
                .bind(group_list)
                .bind(nostr_id)
                .execute(&self.pool.db)
                .await?;
        }
        Ok(())
    }

    pub async fn load(nostr_id: String, pool: MLSLitePool) -> Result<Option<MlsUser>> {
        let sql = format!("select identity, group_list from user where user_id = ?",);
        let result = sqlx::query(&sql)
            .bind(nostr_id.clone())
            .fetch_optional(&pool.db)
            .await?;
        if let Some(rows) = result {
            let identity: Vec<u8> = rows.get(0);
            let group_list: Option<String> = rows.get(1);
            let group_list: HashSet<String> =
                serde_json::from_str(&group_list.unwrap_or_default())?;
            let mut user = Self::new(nostr_id.clone(), pool).await?;

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
            return Ok(Some(user));
        }
        Ok(None)
    }
}