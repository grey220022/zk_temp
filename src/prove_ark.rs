use ark_bn254::{G1Affine, G2Affine};

use crate::kzg::{BatchOpeningProof, Digest, OpeningProof};

#[derive(Debug)]
#[allow(dead_code)]
pub struct Groth16Proof {
    pub ar: G1Affine,
    pub krs: G1Affine,
    pub bs: G2Affine,
    pub commitments: Vec<G1Affine>,
    pub commitment_pok: G1Affine,
}
