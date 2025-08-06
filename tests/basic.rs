// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::{
    HpqMlsGroup,
    group_builder::{DEFAULT_PQ_CIPHERSUITE, DEFAULT_T_CIPHERSUITE},
};
use openmls::{
    group::{GroupId, MlsGroupJoinConfig},
    prelude::{LeafNodeIndex, MlsMessageIn, OpenMlsProvider, ProcessedMessageContent},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize};

use crate::utils::{assert_groups_eq, client::Client, init_logging};

mod utils;

fn join_group_helper() -> JoinedGroup {
    let alice = Client::new("Alice", OpenMlsRustCrypto::default());
    let bob = Client::new("Bob", OpenMlsRustCrypto::default());

    // Create a new HpqMlsGroup for Alice
    let mut alice_group = HpqMlsGroup::builder()
        .with_group_ids(
            GroupId::random(alice.provider.rand()),
            GroupId::from_slice(b"test_pq_group"),
        )
        .ciphersuite(DEFAULT_T_CIPHERSUITE, DEFAULT_PQ_CIPHERSUITE)
        .build(
            &alice.provider,
            &alice.t_signer,
            &alice.pq_signer,
            alice.t_credential_with_key.clone(),
            alice.pq_credential_with_key.clone(),
        )
        .unwrap();

    let rc = alice_group.t_group.extensions().required_capabilities();
    println!("Required capabilities for T group: {:?}", rc);

    // Generate KeyPackages for Bob
    let key_package = bob.generate_key_package();

    // Alice proposes to add Bob's KeyPackages
    let commit_bundle = alice_group
        .commit_builder()
        .propose_adds([key_package])
        .finalize(
            &alice.provider,
            &alice.t_signer,
            &alice.pq_signer,
            |_| true,
            |_| true,
        )
        .unwrap();

    alice_group.merge_pending_commit(&alice.provider).unwrap();

    let ratchet_tree = alice_group.export_ratchet_tree();

    // Bob joins Alice's group
    let welcome = commit_bundle.into_welcome().unwrap();
    let mut bob_group = HpqMlsGroup::new_from_welcome(
        &bob.provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(ratchet_tree.into()),
    )
    .unwrap();

    assert_groups_eq(&mut alice_group, &mut bob_group);

    JoinedGroup {
        alice,
        bob,
        alice_group,
        bob_group,
    }
}

fn update_group_helper(group: JoinedGroup) -> JoinedGroup {
    let JoinedGroup {
        mut alice_group,
        mut bob_group,
        alice,
        bob,
    } = group;

    // Alice does an update
    let alice_commit_bundle = alice_group
        .commit_builder()
        .force_self_update(true)
        .finalize(
            &alice.provider,
            &alice.t_signer,
            &alice.pq_signer,
            |_| true,
            |_| true,
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice.provider).unwrap();

    // Bob processes Alice's update
    let processed_message = bob_group
        .process_message(
            &bob.provider,
            alice_commit_bundle.commit.try_into().unwrap(),
        )
        .unwrap();
    bob_group
        .merge_staged_commit(
            &bob.provider,
            processed_message.into_staged_commit().unwrap(),
        )
        .unwrap();

    assert_groups_eq(&mut alice_group, &mut bob_group);

    JoinedGroup {
        alice,
        bob,
        alice_group,
        bob_group,
    }
}

struct JoinedGroup {
    alice: Client<OpenMlsRustCrypto>,
    bob: Client<OpenMlsRustCrypto>,
    alice_group: HpqMlsGroup,
    bob_group: HpqMlsGroup,
}

#[test]
fn join_group() {
    init_logging();
    join_group_helper();
}

#[test]
fn update_group() {
    let joined_group = join_group_helper();

    update_group_helper(joined_group);
}

#[test]
fn remove_from_group() {
    let JoinedGroup {
        mut bob_group, bob, ..
    } = join_group_helper();

    // Bob removes Alice
    let _bob_commit_bundle = bob_group
        .commit_builder()
        .propose_removals(std::iter::once(LeafNodeIndex::new(0)))
        .finalize(
            &bob.provider,
            &bob.t_signer,
            &bob.pq_signer,
            |_| true,
            |_| true,
        )
        .unwrap();
    bob_group.merge_pending_commit(&bob.provider).unwrap();
}

#[test]
fn t_only_update() {
    let JoinedGroup {
        alice,
        bob,
        mut alice_group,
        mut bob_group,
    } = join_group_helper();

    // Alice does a T-only update
    let alice_commit_bundle = alice_group
        .t_group
        .commit_builder()
        .force_self_update(true)
        .load_psks(alice.provider.storage())
        .unwrap()
        .build(
            alice.provider.rand(),
            alice.provider.crypto(),
            &alice.t_signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice.provider)
        .unwrap();

    alice_group
        .t_group
        .merge_pending_commit(&alice.provider)
        .unwrap();

    // Bob processes Alice's T-only update
    let commit = MlsMessageIn::tls_deserialize_exact(
        &alice_commit_bundle
            .into_commit()
            .tls_serialize_detached()
            .unwrap(),
    )
    .unwrap()
    .try_into_protocol_message()
    .unwrap();

    let processed_message = bob_group
        .t_group
        .process_message(&bob.provider, commit)
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(processed_message) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message");
    };

    bob_group
        .t_group
        .merge_staged_commit(&bob.provider, *processed_message)
        .unwrap();

    assert_groups_eq(&mut alice_group, &mut bob_group);

    // Do an HPQMLS update to make sure everything still works
    let joined_group = JoinedGroup {
        alice,
        bob,
        alice_group,
        bob_group,
    };

    update_group_helper(joined_group);
}
