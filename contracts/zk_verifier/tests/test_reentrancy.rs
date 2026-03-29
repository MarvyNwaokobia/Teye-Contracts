#![allow(clippy::unwrap_used, clippy::expect_used)]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    testutils::{Address as _, Events},
    Address, BytesN, Env, Symbol, Val, Vec,
};
use zk_verifier::vk::{G1Point, G2Point, VerificationKey};
use zk_verifier::{
    AccessRequest, ContractError, Proof, ZkVerifierContract, ZkVerifierContractClient,
};

const TARGET: Symbol = symbol_short!("TARGET");
const ARMED: Symbol = symbol_short!("ARMED");
const ATTEMPTS: Symbol = symbol_short!("ATTEMPTS");
const LAST_ERROR: Symbol = symbol_short!("LAST_ERR");

#[contracttype]
#[derive(Clone)]
struct AttackState {
    target: Address,
    request: AccessRequest,
}

#[contract]
struct ReentrantAuthContract;

#[contractimpl]
impl ReentrantAuthContract {
    pub fn configure(env: Env, target: Address, request: AccessRequest) {
        env.storage()
            .instance()
            .set(&TARGET, &AttackState { target, request });
        env.storage().instance().set(&ARMED, &true);
        env.storage().instance().set(&ATTEMPTS, &0u32);
        env.storage().instance().set(&LAST_ERROR, &0u32);
    }

    pub fn arm(env: Env) {
        env.storage().instance().set(&ARMED, &true);
        env.storage().instance().set(&ATTEMPTS, &0u32);
        env.storage().instance().set(&LAST_ERROR, &0u32);
    }

    pub fn attempts(env: Env) -> u32 {
        env.storage().instance().get(&ATTEMPTS).unwrap_or(0)
    }

    pub fn last_error(env: Env) -> u32 {
        env.storage().instance().get(&LAST_ERROR).unwrap_or(0)
    }

    #[allow(non_snake_case)]
    pub fn __check_auth(env: Env, _signature_payload: Val, _signatures: Val, _auth_context: Val) {
        if !env.storage().instance().get(&ARMED).unwrap_or(false) {
            return;
        }

        let state: AttackState = env.storage().instance().get(&TARGET).unwrap();
        let attempts = Self::attempts(env.clone()).saturating_add(1);
        env.storage().instance().set(&ATTEMPTS, &attempts);
        env.storage().instance().set(&ARMED, &false);

        let client = ZkVerifierContractClient::new(&env, &state.target);
        let nested = client.try_verify_access(&state.request);
        let error_code = match nested {
            Err(Ok(err)) => err as u32,
            _ => 0,
        };
        env.storage().instance().set(&LAST_ERROR, &error_code);
    }
}

fn setup_vk(env: &Env) -> VerificationKey {
    let mut one = [0u8; 32];
    one[0] = 1;
    let mut two = [0u8; 32];
    two[0] = 2;

    let g1 = G1Point {
        x: BytesN::from_array(env, &one),
        y: BytesN::from_array(env, &two),
    };
    let g2 = G2Point {
        x: (BytesN::from_array(env, &one), BytesN::from_array(env, &one)),
        y: (BytesN::from_array(env, &one), BytesN::from_array(env, &one)),
    };

    let mut ic = Vec::new(env);
    ic.push_back(g1.clone());
    ic.push_back(g1.clone());

    VerificationKey {
        alpha_g1: g1.clone(),
        beta_g2: g2.clone(),
        gamma_g2: g2.clone(),
        delta_g2: g2,
        ic,
    }
}

fn valid_request(env: &Env, user: Address, resource_seed: u8) -> AccessRequest {
    let mut proof_byte = [0u8; 32];
    proof_byte[0] = 1;

    let proof = Proof {
        a: G1Point {
            x: BytesN::from_array(env, &proof_byte),
            y: BytesN::from_array(env, &proof_byte),
        },
        b: G2Point {
            x: (
                BytesN::from_array(env, &proof_byte),
                BytesN::from_array(env, &proof_byte),
            ),
            y: (
                BytesN::from_array(env, &proof_byte),
                BytesN::from_array(env, &proof_byte),
            ),
        },
        c: G1Point {
            x: BytesN::from_array(env, &proof_byte),
            y: BytesN::from_array(env, &proof_byte),
        },
    };

    let mut public_inputs = Vec::new(env);
    public_inputs.push_back(BytesN::from_array(env, &proof_byte));

    AccessRequest {
        user,
        resource_id: BytesN::from_array(env, &[resource_seed; 32]),
        proof,
        public_inputs,
        expires_at: env.ledger().timestamp().saturating_add(600),
        nonce: 0,
    }
}

fn setup() -> (
    Env,
    ZkVerifierContractClient<'static>,
    ReentrantAuthContractClient<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let verifier_id = env.register(ZkVerifierContract, ());
    let verifier = ZkVerifierContractClient::new(&env, &verifier_id);
    let attacker_id = env.register(ReentrantAuthContract, ());
    let attacker = ReentrantAuthContractClient::new(&env, &attacker_id);
    let admin = Address::generate(&env);

    verifier.initialize(&admin);
    verifier.set_verification_key(&admin, &setup_vk(&env));

    env.set_auths(&[]);

    (env, verifier, attacker, verifier_id, attacker_id)
}

#[test]
fn verify_access_blocks_reentrant_auth_callback() {
    let (env, verifier, attacker, verifier_id, attacker_id) = setup();
    let request = valid_request(&env, attacker_id.clone(), 55);
    attacker.configure(&verifier_id, &request);

    let result = verifier.verify_access(&request);
    assert!(result, "outer verification should still succeed");
    assert_eq!(
        attacker.attempts(),
        1,
        "expected one nested re-entry attempt"
    );
    assert_eq!(
        attacker.last_error(),
        ContractError::ReentrantCall as u32,
        "nested call should fail with ReentrantCall"
    );
    assert_eq!(
        verifier.get_nonce(&attacker_id),
        1,
        "outer successful verification should advance nonce once"
    );
    assert!(
        verifier
            .get_audit_record(&attacker_id, &request.resource_id)
            .is_some(),
        "outer verification should still emit one audit record"
    );

    let contract_events = env.events().all().filter_by_contract(&verifier_id);
    assert_eq!(
        contract_events.events().len(),
        0,
        "blocked nested call must not leak verifier events"
    );
}

#[test]
fn verify_access_plonk_reuses_the_same_reentrancy_guard() {
    let (env, verifier, attacker, verifier_id, attacker_id) = setup();
    let request = valid_request(&env, attacker_id.clone(), 77);
    attacker.configure(&verifier_id, &request);

    let result = verifier.verify_access_plonk(&request);
    assert!(result, "outer PLONK path should still succeed");
    assert_eq!(attacker.attempts(), 1);
    assert_eq!(attacker.last_error(), ContractError::ReentrantCall as u32);
    assert_eq!(verifier.get_nonce(&attacker_id), 1);
    assert!(verifier
        .get_audit_record(&attacker_id, &request.resource_id)
        .is_some());

    attacker.arm();
    let next_request = AccessRequest {
        nonce: 1,
        resource_id: BytesN::from_array(&env, &[78u8; 32]),
        ..request
    };
    attacker.configure(&verifier_id, &next_request);

    let second = verifier.verify_access(&next_request);
    assert!(
        second,
        "guard must be released after the first blocked re-entry"
    );
    assert_eq!(attacker.attempts(), 1);
    assert_eq!(attacker.last_error(), ContractError::ReentrantCall as u32);
}
