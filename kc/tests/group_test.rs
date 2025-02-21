use kc::identity::Identity;
use kc::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use openmls::credentials::CredentialWithKey;
use openmls::extensions::Extensions;
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls::key_packages::KeyPackage;
use openmls::prelude::{
    LeafNodeParameters, Member, MlsMessageIn, ProcessedMessageContent, Proposal, Sender,
    StagedWelcome,
};
use openmls::storage::OpenMlsProvider;
use openmls_sqlite_storage::Connection;
use openmls_sqlite_storage::*;
use openmls_traits::signatures::Signer;
use openmls_traits::types::Ciphersuite;
use std::io::{stdout, Write};
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

use serde::Serialize;

#[tokio::main]
async fn main() {
    println!("this is a test");
    basic_test_create_group().await;
}

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

// #[tokio::test]
// #[test]
async fn basic_test_create_group() {
    println!("this is a test");
    const MESSAGE_1: &str = "First msg alice to bob.";

    let group_id = "G1".to_string();
    let alice = "Alice";
    let bob = "Bob";
    let charlie = "Charlie";
    let tom = "Tom";

    let db_path = "./mls-lite.sqlite";
    let connection = Connection::open(db_path).unwrap();
    let mut storage =
        openmls_sqlite_storage::SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
    storage.initialize().unwrap();

    let provider = OpenMlsRustPersistentCrypto::new(storage).await;
    // let provider = provider;
    // let provider = provider;
    // let provider = provider;

    // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
    // tree, we need to include the ratchet_tree_extension.
    let group_create_config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let identity_alice = Identity::new(CIPHERSUITE, &provider, alice.as_bytes());

    let mut identity_bob = Identity::new(CIPHERSUITE, &provider, bob.as_bytes());
    let bob_key_package = identity_bob.add_key_package(CIPHERSUITE, &provider);

    let mut identity_charlie = Identity::new(CIPHERSUITE, &provider, charlie.as_bytes());
    let charlie_key_package = identity_charlie.add_key_package(CIPHERSUITE, &provider);

    let mut identity_tom = Identity::new(CIPHERSUITE, &provider, tom.as_bytes());
    let tom_key_package = identity_tom.add_key_package(CIPHERSUITE, &provider);

    let mut alice_mls_group = MlsGroup::new_with_group_id(
        &provider,
        &identity_alice.signer,
        &group_create_config,
        GroupId::from_slice(group_id.as_bytes()),
        identity_alice.credential_with_key.clone(),
    )
    .expect("Failed to create MlsGroup");

    // identity (credential_with_key) can use nostr public key instead
    // group_id and group_create_config should send to all
    // alice should know bob bob_key_package(bob should send this to alice),
    // and welcome info should send to bob
    // and alice send msg to bob, bob get the secret msg, then decrypt it.
    // // invite and remove need to execute this func merge_pending_commit()

    // === Alice adds Bob ===
    let welcome = match alice_mls_group.add_members(
        &provider,
        &identity_alice.signer,
        &[bob_key_package.into()],
    ) {
        Ok((_, welcome, _)) => welcome,
        Err(e) => panic!("Could not add member to group: {e:?}"),
    };

    // Check that we received the correct proposals
    if let Some(staged_commit) = alice_mls_group.pending_commit() {
        let _add = staged_commit
            .add_proposals()
            .next()
            .expect("Expected a proposal.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_mls_group
        .merge_pending_commit(&provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut bob_mls_group = StagedWelcome::new_from_welcome(
        &provider,
        &group_create_config.join_config(),
        welcome,
        // Some(alice_mls_group.export_ratchet_tree().into()),
        None,
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(&provider)
    .expect("Error creating group from StagedWelcome");

    // === Alice sends a message to Bob ===
    let message_out = alice_mls_group
        .create_message(&provider, &identity_alice.signer, MESSAGE_1.as_bytes())
        .map_err(|e| format!("{e}"))
        .unwrap();

    let processed_message = bob_mls_group
        .process_message(
            &provider,
            message_out
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        println!(
            "application_message.into_bytes() is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    // === Bob updates and commits ===
    let commit_message_bundle = bob_mls_group
        .self_update(
            &provider,
            &identity_bob.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    let queued_message = commit_message_bundle.commit();

    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct message
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        // Merge staged Commit
        alice_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_mls_group
        .merge_pending_commit(&provider)
        .expect("error merging pending commit");

    // === Alice updates and commits ===
    let (queued_message, _welcome_option) = alice_mls_group
        .propose_self_update(
            &provider,
            &identity_alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();

    let bob_processed_message = bob_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        bob_processed_message.into_content()
    {
        let provider_ref = &provider;
        if let Proposal::Update(ref _update_proposal) = staged_proposal.proposal() {
            // Store proposal
            alice_mls_group
                .store_pending_proposal(&provider_ref.storage, *staged_proposal.clone())
                .unwrap();
        } else {
            unreachable!("Expected a Proposal.");
        }

        bob_mls_group
            .store_pending_proposal(&provider.storage, *staged_proposal)
            .unwrap();
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    let (queued_message, _welcome_option, _group_info) = alice_mls_group
        .commit_to_pending_proposals(&provider, &identity_alice.signer)
        .unwrap();

    let bob_processed_message = bob_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct message
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        // Merge staged Commit
        bob_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_mls_group
        .merge_pending_commit(&provider)
        .expect("error merging pending commit");

    stdout().write_all(b" >>> bob add charlie :)\n").unwrap();

    // === Bob adds Charlie ===
    // add member must execute merge_pending_commit() func
    let (queued_msg, welcome, _) = bob_mls_group
        .add_members(
            &provider,
            &identity_bob.signer,
            &[charlie_key_package.into()],
        )
        .unwrap();
    bob_mls_group.merge_pending_commit(&provider).unwrap();

    // invite members, another need to execute this
    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_msg.clone().into_protocol_message().expect(""),
        )
        .expect("");

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut charlie_group = StagedWelcome::new_from_welcome(
        &provider,
        group_create_config.join_config(),
        welcome,
        // Some(bob_mls_group.export_ratchet_tree().into()),
        None,
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&provider)
    .expect("Error creating group from staged join");

    stdout()
        .write_all(b" >>> charlie send msg start :)\n")
        .unwrap();

    // === Charlie sends a message to the group ===
    let message_charlie = b"Hi, I'm Charlie!";
    let queued_message = charlie_group
        .create_message(&provider, &identity_charlie.signer, message_charlie)
        .expect("Error creating application message");

    let bob_processed_message = bob_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        bob_processed_message.into_content()
    {
        println!(
            "bob process charlie msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        alice_processed_message.into_content()
    {
        println!(
            "alice process charlie msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    // === Bob sends a message to the group ===
    let message_bob = b"Hi, I'm Bob!";
    let queued_message = bob_mls_group
        .create_message(&provider, &identity_bob.signer, message_bob)
        .expect("Error creating application message");

    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        alice_processed_message.into_content()
    {
        println!(
            "alice process bob msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    let charlie_processed_message = charlie_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        charlie_processed_message.into_content()
    {
        println!(
            "charlie process bob msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    // === Bob updates and commits ===
    let commitMessageBundle = bob_mls_group
        .self_update(
            &provider,
            &identity_bob.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();

    let queued_message = commitMessageBundle.commit();

    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    let charlie_processed_message = charlie_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        charlie_processed_message.into_content()
    {
        charlie_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_mls_group
        .merge_pending_commit(&provider)
        .expect("error merging pending commit");

    // === Charlie adds Tom ===
    // add member must execute merge_pending_commit() func
    let (queued_msg, welcome, _) = charlie_group
        .add_members(
            &provider,
            &identity_charlie.signer,
            &[tom_key_package.into()],
        )
        .unwrap();

    // invite members, another need to execute this
    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_msg.clone().into_protocol_message().expect(""),
        )
        .expect("");

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    charlie_group.merge_pending_commit(&provider).unwrap();

    // Merge Commit
    let bob_processed_message = bob_mls_group
        .process_message(
            &provider,
            queued_msg.clone().into_protocol_message().expect(""),
        )
        .expect("");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        bob_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut tom_group = StagedWelcome::new_from_welcome(
        &provider,
        group_create_config.join_config(),
        welcome,
        // Some(charlie_group.export_ratchet_tree().into()),
        None,
    )
    .expect("Error creating staged join from Welcome")
    .into_group(&provider)
    .expect("Error creating group from staged join");

    stdout().write_all(b" >>> tom send msg start :)\n").unwrap();

    // === Tom sends a message to the group ===
    let message_tom = b"Hi, I'm Tom, guys!";
    let queued_message = tom_group
        .create_message(&provider, &identity_tom.signer, message_tom)
        .expect("Error creating application message");

    let bob_processed_message = bob_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        bob_processed_message.into_content()
    {
        println!(
            "bob process tom msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        alice_processed_message.into_content()
    {
        println!(
            "alice process tom msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    let charlie_processed_message = charlie_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        charlie_processed_message.into_content()
    {
        println!(
            "charlie process tom msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    println!(
        "before remove, alice_mls_group members is {:?}",
        alice_mls_group.members().count()
    );

    //  add member or remove this will be changed, send msg do not change it
    println!(
        "before remove, alice_mls_group tree_hash {:?}",
        alice_mls_group.tree_hash()
    );

    // === Charlie removes Bob ===
    println!(" >>> Charlie is removing bob");
    let (queued_message, welcome_option, _group_info) = charlie_group
        .remove_members(
            &provider,
            &identity_charlie.signer,
            &[bob_mls_group.own_leaf_index()],
        )
        .expect("Could not remove member from group.");

    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    let bob_processed_message = bob_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    let tom_processed_message = tom_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    charlie_group
        .merge_pending_commit(&provider)
        .expect("error merging pending commit");

    // Check that we receive the correct proposal for Alice
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");

        // Merge staged Commit
        alice_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that we receive the correct proposal for Bob
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");

        // Merge staged Commit
        bob_mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that we receive the correct proposal for Tom
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        tom_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");

        // Merge staged Commit
        tom_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    println!("bob is active {:?}", bob_mls_group.is_active());

    println!(
        "after remove, alice_mls_group members is {:?}",
        alice_mls_group.members().count()
    );

    println!(
        "after remove, charlie_group members is {:?}",
        charlie_group.members().count()
    );

    println!(
        "after remove, tom_group members is {:?}",
        tom_group.members().count()
    );

    println!(
        "alice_mls_group tree_hash {:?}",
        alice_mls_group.tree_hash()
    );

    println!(
        "alice_mls_group export secret {:?}",
        alice_mls_group
            .export_secret(&provider, "", &[], 32)
            .unwrap()
    );

    // println!(
    //     "bob_mls_group export secret {:?}",
    //     bob_mls_group
    //         .export_secret(&provider, "", &[], 32)
    //         .unwrap()
    // );

    println!(
        "charlie_group export secret {:?}",
        charlie_group.export_secret(&provider, "", &[], 32).unwrap()
    );

    println!(
        "tom_group export secret {:?}",
        tom_group.export_secret(&provider, "", &[], 32).unwrap()
    );

    let members = bob_mls_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    let credential2 = members[2].credential.serialized_content();
    //after remove, bob_group members is "Alice", "Charlie", "Tom"
    println!(
        "after remove, bob_group members is {:?}, {:?}, {:?}",
        String::from_utf8(credential0.to_vec()).unwrap(),
        String::from_utf8(credential1.to_vec()).unwrap(),
        String::from_utf8(credential2.to_vec()).unwrap()
    );

    // Check that Bob can no longer send messages
    println!(
        "Check that Bob can no longer send messages is_err {:?}",
        bob_mls_group
            .create_message(&provider, &identity_bob.signer, b"Should not go through")
            .is_err()
    );

    // then Alice send msg to the group
    let message_alice = b"Hi, I'm alice, again, guys!";
    let queued_message = alice_mls_group
        .create_message(&provider, &identity_alice.signer, message_alice)
        .expect("Error creating application message");

    let tom_processed_message = tom_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        tom_processed_message.into_content()
    {
        println!(
            "tom process alice msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    let charlie_processed_message = charlie_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        charlie_processed_message.into_content()
    {
        println!(
            "charlie process alice msg is {:?}",
            String::from_utf8(application_message.into_bytes()).unwrap()
        );
    }

    println!(
        "after send msg alice_mls_group export secret {:?}",
        alice_mls_group
            .export_secret(&provider, "", &[], 32)
            .unwrap()
    );

    println!(
        "after send msg charlie_group export secret {:?}",
        charlie_group.export_secret(&provider, "", &[], 32).unwrap()
    );

    println!(
        "after send msg tom_group export secret {:?}",
        tom_group.export_secret(&provider, "", &[], 32).unwrap()
    );

    println!(
        "after send msg alice_mls_group tree_hash {:?}",
        alice_mls_group.tree_hash()
    );

    // === tom leaves the group ===
    let queued_message = tom_group
        .leave_group(&provider, &identity_tom.signer)
        .expect("Could not leave group");

    let alice_processed_message = alice_mls_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    let charlie_processed_message = charlie_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Store proposal
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        alice_processed_message.into_content()
    {
        // Store proposal
        alice_mls_group
            .store_pending_proposal(&provider.storage, *staged_proposal)
            .unwrap();
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Store proposal
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        // Store proposal
        charlie_group
            .store_pending_proposal(&provider.storage, *staged_proposal)
            .unwrap();
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    let (queued_message, _welcome_option, _group_info) = alice_mls_group
        .commit_to_pending_proposals(&provider, &identity_alice.signer)
        .expect("Could not commit to proposals.");

    // Check that we received the correct proposals
    let tom_leaf_index = tom_group.own_leaf_index();
    if let Some(staged_commit) = alice_mls_group.pending_commit() {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(remove.remove_proposal().removed(), tom_leaf_index);
        // Check that Bob removed himself
        assert!(matches!(remove.sender(), Sender::Member(member) if *member == tom_leaf_index));
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // === Leave operation from Charlie's perspective ===
    let charlie_processed_message = charlie_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        charlie_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // === Leave operation from Tom's perspective ===
    let tom_processed_message = tom_group
        .process_message(
            &provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        tom_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        // assert_eq!(remove.remove_proposal().removed(), tom_leaf_index);

        assert!(staged_commit.self_removed());
        // Merge staged Commit
        tom_group
            .merge_staged_commit(&provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that Bob's group is no longer active
    assert!(!tom_group.is_active());

    println!(
        "after leave, alice_mls_group members is {:?}",
        alice_mls_group.members().count()
    );

    println!(
        "after leave, charlie_group members is {:?}",
        charlie_group.members().count()
    );

    println!(
        "after leave, tom_group members is {:?}",
        tom_group.members().count()
    );

    println!(
        "alice_mls_group export secret {:?}",
        alice_mls_group
            .export_secret(&provider, "", &[], 32)
            .unwrap()
    );

    println!(
        "charlie_group export secret {:?}",
        charlie_group.export_secret(&provider, "", &[], 32).unwrap()
    );

    println!(
        "alice_mls_group tree_hash {:?}",
        alice_mls_group.tree_hash()
    );

    stdout().write_all(b" >>> test end :)\n").unwrap();
}

fn generate_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    provider: &Provider,
    credential_with_key: CredentialWithKey,
    signer: &impl Signer,
) -> KeyPackage {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
        .key_package()
        .clone()
}
