use anyhow::{anyhow, Error, Result};
use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, SerializationError};
use std::{
    cmp::{Ord, Ordering},
    ops::Neg,
};

use crate::{
    constants::{
        ERR_FAILED_TO_GET_X, ERR_FAILED_TO_GET_Y, ERR_INVALID_GNARK_X_LENGTH,
        ERR_UNEXPECTED_GNARK_FLAG,
    },
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    prove_ark::{Groth16Proof},
    verify_ark::{Groth16G1, Groth16G2, Groth16VerifyingKey, PedersenVerifyingKey},
};

const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_COMPRESSED_POSTIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSTIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8> {
    let gnark_flag = msb & GNARK_MASK;

    let ark_flag = match gnark_flag {
        GNARK_COMPRESSED_POSTIVE => ARK_COMPRESSED_POSTIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => {
            let err_msg = format!("{}: {}", ERR_UNEXPECTED_GNARK_FLAG, gnark_flag);
            return Err(anyhow!(err_msg));
        }
    };

    Ok(msb & !ARK_MASK | ark_flag)
}

/// Convert big-endian gnark compressed x bytes to litte-endian ark compressed x for g1 and g2 point
fn ganrk_commpressed_x_to_ark_commpressed_x(x: &Vec<u8>) -> Result<Vec<u8>> {
    if x.len() != 32 && x.len() != 64 {
        let err_msg = format!("{}: {}", ERR_INVALID_GNARK_X_LENGTH, x.len());
        return Err(anyhow!(err_msg));
    }
    let mut x_copy = x.clone();

    let msb = gnark_flag_to_ark_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

fn gnark_compressed_x_to_g1_point(buf: &[u8]) -> Result<G1Affine> {
    if buf.len() != 32 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let m_data = buf[0] & GNARK_MASK;
    if m_data == GNARK_COMPRESSED_INFINITY {
        if !is_zeroed(buf[0] & !GNARK_MASK, &buf[1..32])? {
            return Err(anyhow!(SerializationError::InvalidData));
        }
        Ok(G1Affine::identity())
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !GNARK_MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes.to_vec());
        let (y, neg_y) = G1Affine::get_ys_from_x_unchecked(x)
            .ok_or(SerializationError::InvalidData)
            .map_err(Error::msg)?;

        let mut final_y = y;
        if y.cmp(&neg_y) == Ordering::Greater {
            if m_data == GNARK_COMPRESSED_POSTIVE {
                final_y = y.neg();
            }
        } else {
            if m_data == GNARK_COMPRESSED_NEGATIVE {
                final_y = y.neg();
            }
        }

        let p = G1Affine::new_unchecked(x, final_y);
        if !p.is_on_curve() {
            return Err(anyhow!(SerializationError::InvalidData));
        }
        Ok(p)
    }
}

fn is_zeroed(first_byte: u8, buf: &[u8]) -> Result<bool> {
    if first_byte != 0 {
        return Ok(false);
    }
    for &b in buf {
        if b != 0 {
            return Ok(false);
        }
    }

    Ok(true)
}

fn gnark_compressed_x_to_g2_point(buf: &[u8]) -> Result<G2Affine> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let bytes = ganrk_commpressed_x_to_ark_commpressed_x(&buf.to_vec())?;
    let p = G2Affine::deserialize_compressed::<&[u8]>(&bytes).map_err(Error::msg)?;
    Ok(p)
}

pub fn gnark_uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<G1Affine> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_be_bytes_mod_order(&x_bytes.to_vec());
    let y = Fq::from_be_bytes_mod_order(&y_bytes.to_vec());
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(anyhow!(SerializationError::InvalidData));
    }
    Ok(p)
}

pub fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof> {
    let ar = gnark_compressed_x_to_g1_point(&buffer[..32])?;
    let bs = gnark_compressed_x_to_g2_point(&buffer[32..96])?;
    let krs = gnark_compressed_x_to_g1_point(&buffer[96..128])?;

    Ok(Groth16Proof {
        ar,
        bs,
        krs,
        commitments: Vec::new(),
        commitment_pok: G1Affine::identity(),
    })
}

pub fn load_groth16_verifying_key_from_bytes(buffer: &[u8]) -> Result<Groth16VerifyingKey> {
    let g1_alpha = gnark_compressed_x_to_g1_point(&buffer[..32])?;
    let g1_beta = gnark_compressed_x_to_g1_point(&buffer[32..64])?;
    let g2_beta = gnark_compressed_x_to_g2_point(&buffer[64..128])?;
    let g2_gamma = gnark_compressed_x_to_g2_point(&buffer[128..192])?;
    let g1_delta = gnark_compressed_x_to_g1_point(&buffer[192..224])?;
    let g2_delta = gnark_compressed_x_to_g2_point(&buffer[224..288])?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        k.push(point);
        offset += 32;
    }

    let num_of_array_of_public_and_commitment_committed = u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;
    for _ in 0..num_of_array_of_public_and_commitment_committed {
        let num = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        for _ in 0..num {
            offset += 4;
        }
    }

    let commitment_key_g = gnark_compressed_x_to_g2_point(&buffer[offset..offset + 64])?;
    let commitment_key_g_root_sigma_neg =
        gnark_compressed_x_to_g2_point(&buffer[offset + 64..offset + 128])?;

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 {
            alpha: g1_alpha,
            beta: g1_beta,
            delta: g1_delta,
            k,
        },
        g2: Groth16G2 {
            beta: g2_beta,
            gamma: g2_gamma,
            delta: g2_delta,
        },
        commitment_key: PedersenVerifyingKey {
            g: commitment_key_g,
            g_root_sigma_neg: commitment_key_g_root_sigma_neg,
        },
        public_and_commitment_committed: vec![vec![0u32; 0]],
    })
}

pub fn g1_to_bytes(g1: &G1Affine) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    let value_x = g1
        .x()
        .expect(ERR_FAILED_TO_GET_X)
        .into_bigint()
        .to_bytes_be();
    let value_y = g1
        .y()
        .expect(ERR_FAILED_TO_GET_Y)
        .into_bigint()
        .to_bytes_be();
    bytes.extend_from_slice(&value_x);
    bytes.extend_from_slice(&value_y);
    Ok(bytes)
}
