use std::hash::Hasher;

use anyhow::{anyhow, Result};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{batch_inversion, BigInteger, Field, One, PrimeField, Zero};
use ark_groth16::{Groth16, Proof as ArkGroth16Proof, VerifyingKey as ArkGroth16VerifyingKey};
use ark_snark::SNARK;

use crate::{constants::{
    ALPHA, BETA, ERR_BSB22_COMMITMENT_MISMATCH, ERR_INVALID_POINT, ERR_INVALID_WITNESS,
    ERR_INVERSE_NOT_FOUND, ERR_OPENING_POLY_MISMATCH, GAMMA, ZETA,
}, converter::g1_to_bytes, element::PlonkFr, kzg::{self, is_in_subgroup}, prove, prove_ark, transcript::Transcript};


#[allow(dead_code)]
pub struct Groth16G1 {
    pub alpha: G1Affine,
    pub beta: G1Affine,
    pub delta: G1Affine,
    pub k: Vec<G1Affine>,
}

#[derive(Debug)]
pub struct Groth16G2 {
    pub beta: G2Affine,
    pub delta: G2Affine,
    pub gamma: G2Affine,
}

#[allow(dead_code)]
pub struct PedersenVerifyingKey {
    pub g: G2Affine,
    pub g_root_sigma_neg: G2Affine,
}

#[allow(dead_code)]
pub struct Groth16VerifyingKey {
    pub g1: Groth16G1,
    pub g2: Groth16G2,
    pub commitment_key: PedersenVerifyingKey,
    pub public_and_commitment_committed: Vec<Vec<u32>>,
}

pub fn verify_groth16(
    vk: &Groth16VerifyingKey,
    proof: &prove_ark::Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool> {
    let proof: ArkGroth16Proof<Bn254> = ArkGroth16Proof {
        a: proof.ar,
        b: proof.bs,
        c: proof.krs,
    };
    let vk: ArkGroth16VerifyingKey<Bn254> = ArkGroth16VerifyingKey {
        alpha_g1: vk.g1.alpha,
        beta_g2: vk.g2.beta,
        gamma_g2: vk.g2.gamma,
        delta_g2: vk.g2.delta,
        gamma_abc_g1: vk.g1.k.clone(),
    };

    let pvk = Groth16::<Bn254>::process_vk(&vk)?;

    Ok(Groth16::<Bn254>::verify_with_processed_vk(
        &pvk,
        public_inputs,
        &proof,
    )?)
}


fn derive_randomness(
    transcript: &mut Transcript,
    challenge: &str,
    points: Option<Vec<G1Affine>>,
) -> Result<Fr> {
    if let Some(points) = points {
        for point in points {
            let buf = g1_to_bytes(&point)?;
            transcript.bind(challenge, &buf)?;
        }
    }

    let b = transcript.compute_challenge(challenge)?;
    let x = PlonkFr::set_bytes(&b.as_slice())?.into_fr()?;
    Ok(x)
}

fn batch_invert(elements: &[Fr]) -> Result<Vec<Fr>> {
    let mut elements = elements.to_vec();
    batch_inversion(&mut elements);
    Ok(elements)
}
