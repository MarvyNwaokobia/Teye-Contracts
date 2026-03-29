#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};
use zk_verifier::verifier::{G1Point, G2Point};
use zk_verifier::Proof;
use zk_voting::ballot::{DataKey, VoteError};
use zk_voting::merkle::{make_leaf, MerkleTree};
use zk_voting::{ZkVoting, ZkVotingClient};

fn valid_proof(env: &Env) -> (Proof, Vec<BytesN<32>>) {
    let mut ax = [0u8; 32];
    ax[0] = 1;
    let mut cx = [0u8; 32];
    cx[0] = 1;
    let mut pi = [0u8; 32];
    pi[0] = 1;
    let z = [0u8; 32];

    let proof = Proof {
        a: G1Point {
            x: BytesN::from_array(env, &ax),
            y: BytesN::from_array(env, &z),
        },
        b: G2Point {
            x: (BytesN::from_array(env, &z), BytesN::from_array(env, &z)),
            y: (BytesN::from_array(env, &z), BytesN::from_array(env, &z)),
        },
        c: G1Point {
            x: BytesN::from_array(env, &cx),
            y: BytesN::from_array(env, &z),
        },
    };

    let mut inputs = Vec::new(env);
    inputs.push_back(BytesN::from_array(env, &pi));
    (proof, inputs)
}

fn nullifier(env: &Env, seed: u8) -> BytesN<32> {
    let mut raw = [0u8; 32];
    raw[0] = seed;
    BytesN::from_array(env, &raw)
}

fn setup() -> (Env, ZkVotingClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(ZkVoting, ());
    let client = ZkVotingClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.initialize(&admin, &3u32);

    let mut leaves = Vec::new(&env);
    for i in 0u8..4 {
        leaves.push_back(make_leaf(&env, i));
    }
    let tree = MerkleTree::new(&env, leaves);
    client.set_merkle_root(&admin, &tree.root());

    let z = BytesN::from_array(&env, &[0u8; 32]);
    let g1z = zk_verifier::vk::G1Point {
        x: z.clone(),
        y: z.clone(),
    };
    let g2z = zk_verifier::vk::G2Point {
        x: (z.clone(), z.clone()),
        y: (z.clone(), z.clone()),
    };
    let mut ic = Vec::new(&env);
    ic.push_back(g1z.clone());
    client.set_verification_key(
        &admin,
        &zk_verifier::vk::VerificationKey {
            alpha_g1: g1z.clone(),
            beta_g2: g2z.clone(),
            gamma_g2: g2z.clone(),
            delta_g2: g2z,
            ic,
        },
    );

    (env, client, admin, contract_id)
}

#[test]
fn cast_vote_rejects_tally_overflow_at_u64_max() {
    let (env, client, _admin, contract_id) = setup();
    let (proof, inputs) = valid_proof(&env);
    let n = nullifier(&env, 0xA1);

    env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .set(&DataKey::Tally(1), &u64::MAX);
    });

    let result = client.try_cast_vote(&n, &1u32, &proof, &inputs);
    assert_eq!(result.unwrap_err(), Ok(VoteError::TallyOverflow));

    let results = client.get_results();
    assert_eq!(
        results.tallies.get(1).unwrap(),
        u64::MAX,
        "overflow attempt must leave tally unchanged"
    );
    assert!(
        !client.is_nullifier_used(&n),
        "failed overflowing vote must not consume the nullifier"
    );
}

#[test]
fn zero_index_merkle_proof_does_not_underflow() {
    let env = Env::default();

    let mut leaves = Vec::new(&env);
    for i in 0u8..4 {
        leaves.push_back(make_leaf(&env, i));
    }

    let tree = MerkleTree::new(&env, leaves);
    let root = tree.root();
    let leaf0 = tree.leaf(0);
    let proof0 = tree.proof(&env, 0);

    assert_eq!(proof0.len(), 2);
    assert!(
        MerkleTree::verify_proof(&env, &root, &leaf0, 0, &proof0),
        "index 0 proof should verify without idx - 1 underflow"
    );
}

#[test]
fn rejected_votes_do_not_underflow_other_option_tallies() {
    let (env, client, _admin, _contract_id) = setup();
    let (proof, inputs) = valid_proof(&env);

    client.cast_vote(&nullifier(&env, 0x10), &2u32, &proof, &inputs);

    let rejected = client.try_cast_vote(&nullifier(&env, 0x11), &99u32, &proof, &inputs);
    assert_eq!(rejected.unwrap_err(), Ok(VoteError::InvalidOption));

    let results = client.get_results();
    assert_eq!(results.tallies.get(0).unwrap(), 0u64);
    assert_eq!(results.tallies.get(1).unwrap(), 0u64);
    assert_eq!(results.tallies.get(2).unwrap(), 1u64);
}
