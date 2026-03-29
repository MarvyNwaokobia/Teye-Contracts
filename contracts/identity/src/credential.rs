#![allow(deprecated)]
use soroban_sdk::{symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec};

const ZK_VERIFIER: Symbol = symbol_short!("ZK_VER");

#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CredentialError {
    Unauthorized = 100,
    VerifierNotSet = 101,
    ZkVerificationFailed = 102,
    InvalidNonce = 103,
    CredentialExpired = 104,
}

pub fn set_zk_verifier(env: &Env, verifier_id: &Address) {
    env.storage().instance().set(&ZK_VERIFIER, verifier_id);
}

pub fn get_zk_verifier(env: &Env) -> Option<Address> {
    env.storage().instance().get(&ZK_VERIFIER)
}

pub fn verify_zk_credential(
    env: &Env,
    user: &Address,
    resource_id: BytesN<32>,
    proof_a: Bytes,
    proof_b: Bytes,
    proof_c: Bytes,
    public_inputs: Vec<BytesN<32>>,
    expires_at: u64,
    nonce: u64,
) -> Result<bool, CredentialError> {
    if env.ledger().timestamp() > expires_at {
        return Err(CredentialError::CredentialExpired);
    }

    let verifier_id = get_zk_verifier(env).ok_or(CredentialError::VerifierNotSet)?;
    let client = zk_verifier::ZkVerifierContractClient::new(env, &verifier_id);

    // Validate lengths before reconstruction to prevent panics
    if proof_a.len() != 64 || proof_b.len() != 128 || proof_c.len() != 64 {
        return Err(CredentialError::ZkVerificationFailed);
    }

    // Reconstruct the proof points from raw bytes.
    let mut a_buf = [0u8; 64];
    proof_a.copy_into_slice(&mut a_buf);
    
    let mut b_buf = [0u8; 128];
    proof_b.copy_into_slice(&mut b_buf);

    let mut c_buf = [0u8; 64];
    proof_c.copy_into_slice(&mut c_buf);

    let proof = zk_verifier::Proof {
        a: zk_verifier::vk::G1Point {
            x: BytesN::from_array(env, &a_buf[0..32].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            y: BytesN::from_array(env, &a_buf[32..64].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
        },
        b: zk_verifier::vk::G2Point {
            x: (
                BytesN::from_array(env, &b_buf[0..32].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
                BytesN::from_array(env, &b_buf[32..64].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            ),
            y: (
                BytesN::from_array(env, &b_buf[64..96].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
                BytesN::from_array(env, &b_buf[96..128].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            ),
        },
        c: zk_verifier::vk::G1Point {
            x: BytesN::from_array(env, &c_buf[0..32].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
            y: BytesN::from_array(env, &c_buf[32..64].try_into().map_err(|_| CredentialError::ZkVerificationFailed)?),
        },
    };

    let request = zk_verifier::AccessRequest {
        user: user.clone(),
        resource_id,
        proof,
        public_inputs,
        expires_at,
        nonce,
    };

    let is_valid = client.verify_access(&request);
    if is_valid {
        super::events::emit_zk_credential_verified(env, user.clone(), true);
    }
    Ok(is_valid)
}