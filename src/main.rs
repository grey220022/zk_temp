
#[tokio::main]
async fn main() {}

#[cfg(test)]
mod test {
    use std::fs;
    use ark_bn254::g2::G2Affine;
    use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_snark::SNARK;
    use ark_std::UniformRand;
    use borsh::{to_vec, BorshDeserialize, BorshSerialize};
    use log::{info, LevelFilter};
    use rand::thread_rng;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_program::alt_bn128::compression::prelude::convert_endianness;
    use solana_program::alt_bn128::prelude::{alt_bn128_pairing, ALT_BN128_PAIRING_ELEMENT_LEN};
    use solana_program::instruction::{AccountMeta, Instruction};
    use solana_program::pubkey::Pubkey;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_sdk::signature::{Keypair, Signer};
    use solana_sdk::transaction::Transaction;
    use solana_zk_client_example::byte_utils::{convert_endianness_128, convert_endianness_64};
    use solana_zk_client_example::circuit::ExampleCircuit;
    use solana_zk_client_example::prove::{generate_proof_package, setup};
    use solana_zk_client_example::verify::verify_proof_package;
    use solana_zk_client_example::verify_lite::{build_verifier, convert_ark_public_input, convert_arkworks_verifying_key_to_solana_verifying_key, convert_arkworks_verifying_key_to_solana_verifying_key_prepared, prepare_inputs, Groth16VerifierPrepared, Groth16VerifyingKeyPrepared};
    use std::ops::{Mul, Neg};
    use std::str::FromStr;
    use solana_zk_client_example::converter;

    fn init() {
        let _ = env_logger::builder().filter_level(LevelFilter::Info).is_test(true).try_init();
    }

    #[derive(BorshSerialize, BorshDeserialize)]
    pub enum ProgramInstruction {
        VerifyProof(Groth16VerifierPrepared),
    }

    async fn request_airdrop(
        client: &RpcClient,
        pubkey: &Pubkey,
        amount: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signature = client.request_airdrop(pubkey, amount).await?;

        // Wait for the transaction to be confirmed
        loop {
            let confirmation = client.confirm_transaction(&signature).await.unwrap();
            if confirmation {
                break;
            }
        }
        Ok(())
    }


    #[test]
    fn test_slm_gnark_2() {
        let input_values = [
            "200104116116112115058047047115101099117114101116111107101110046103111",
            "200111103108101046099111109047115107108111103105110045051053102050054",
            "200115107108111103105110045051053102050054",
            "8221293801905454488570447792679227103271972158867850021273786099763738695508",
            "190382143502568173121953655840023021428",
            "268907290496916820827766377268916025917",
            "1714857600",
            "10007",
        ];


        let public_inputs: Vec<Fr> = input_values
            .iter()
            .filter_map(|value| match Fr::from_str(value) {
                Ok(fr_value) => Some(fr_value),
                Err(_) => {
                    eprintln!("Failed to convert value: {}", value);
                    None
                }
            })
            .collect();

        let proofbin = [142, 245, 130, 187, 237, 98, 207, 201, 220, 155, 251, 10, 141, 66, 108, 126, 88, 139, 247, 254, 105, 15, 233, 79, 19, 229, 68, 243, 4, 50, 242, 163, 150, 62, 200, 212, 23, 66, 235, 192, 145, 147, 96, 241, 207, 12, 192, 179, 94, 253, 102, 41, 63, 55, 223, 102, 70, 149, 112, 161, 166, 198, 127, 68, 7, 205, 235, 126, 244, 187, 149, 34, 102, 194, 15, 196, 54, 197, 174, 177, 67, 0, 59, 184, 161, 45, 44, 93, 80, 239, 237, 1, 82, 175, 207, 113, 146, 115, 3, 59, 108, 193, 22, 10, 133, 186, 160, 88, 13, 231, 33, 93, 91, 140, 87, 197, 251, 16, 235, 161, 65, 234, 201, 1, 135, 192, 232, 172, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let vkbin = [210, 2, 2, 82, 42, 33, 80, 170, 18, 193, 122, 143, 64, 37, 71, 149, 135, 170, 95, 86, 94, 188, 107, 111, 10, 68, 196, 111, 101, 106, 246, 158, 163, 161, 106, 152, 157, 250, 18, 153, 1, 215, 235, 213, 76, 128, 4, 159, 125, 243, 196, 170, 142, 130, 93, 228, 74, 183, 245, 135, 244, 241, 196, 254, 235, 118, 248, 61, 162, 112, 113, 162, 66, 181, 29, 69, 186, 169, 217, 199, 39, 25, 194, 87, 22, 109, 111, 38, 155, 245, 15, 157, 85, 46, 186, 181, 9, 190, 238, 58, 174, 154, 189, 105, 122, 35, 251, 247, 34, 62, 46, 167, 236, 110, 156, 139, 136, 173, 20, 164, 9, 160, 25, 202, 243, 62, 109, 85, 152, 158, 167, 72, 57, 77, 77, 25, 106, 213, 188, 213, 199, 114, 62, 5, 102, 12, 210, 108, 129, 106, 108, 68, 78, 124, 73, 189, 8, 167, 77, 228, 1, 23, 175, 25, 240, 143, 155, 128, 110, 210, 213, 253, 60, 101, 164, 156, 95, 32, 24, 41, 148, 70, 119, 253, 27, 78, 160, 8, 2, 168, 115, 163, 143, 43, 123, 247, 147, 3, 226, 150, 173, 105, 163, 178, 108, 188, 177, 179, 1, 13, 48, 68, 138, 90, 97, 236, 11, 55, 215, 59, 17, 240, 181, 172, 193, 10, 125, 154, 171, 92, 20, 197, 53, 158, 174, 119, 90, 223, 80, 183, 184, 53, 38, 126, 209, 120, 166, 55, 36, 159, 50, 254, 244, 55, 68, 199, 23, 250, 248, 185, 28, 158, 62, 75, 32, 40, 169, 216, 28, 94, 126, 36, 94, 60, 196, 196, 197, 202, 149, 226, 159, 118, 85, 147, 98, 254, 156, 101, 0, 0, 0, 9, 138, 131, 152, 51, 139, 49, 105, 171, 25, 9, 163, 96, 26, 204, 236, 0, 237, 175, 121, 20, 235, 7, 16, 198, 151, 53, 149, 208, 143, 32, 211, 217, 144, 83, 225, 179, 155, 7, 13, 20, 38, 196, 5, 110, 96, 193, 29, 52, 28, 22, 179, 191, 90, 33, 157, 8, 170, 10, 189, 170, 119, 97, 89, 6, 136, 169, 252, 131, 128, 215, 55, 252, 101, 61, 143, 123, 248, 242, 43, 99, 101, 162, 201, 222, 164, 151, 48, 149, 65, 252, 231, 143, 240, 142, 2, 104, 200, 212, 180, 160, 165, 81, 153, 163, 24, 191, 124, 56, 103, 138, 162, 39, 154, 39, 76, 46, 196, 72, 92, 154, 73, 196, 39, 175, 112, 104, 170, 16, 159, 235, 9, 125, 231, 228, 224, 96, 167, 15, 87, 12, 251, 4, 110, 214, 143, 2, 134, 55, 113, 153, 243, 201, 17, 229, 143, 80, 148, 110, 160, 172, 213, 77, 82, 27, 70, 125, 205, 226, 213, 183, 10, 250, 131, 155, 162, 184, 221, 186, 176, 107, 215, 149, 19, 60, 70, 48, 131, 178, 253, 133, 51, 192, 159, 40, 87, 69, 95, 102, 221, 53, 154, 28, 197, 171, 15, 186, 55, 132, 55, 197, 39, 31, 43, 96, 34, 111, 120, 192, 35, 59, 139, 129, 200, 57, 156, 156, 140, 117, 164, 144, 60, 225, 182, 106, 113, 97, 49, 70, 2, 109, 5, 143, 1, 236, 75, 175, 3, 110, 120, 3, 26, 235, 114, 189, 182, 67, 146, 66, 106, 63, 197, 41, 97, 248, 184, 95, 105, 48, 39, 90, 205, 239, 142, 242, 254, 113, 8, 11, 208, 128, 4, 200, 148, 150, 76, 170, 218, 38, 0, 0, 0, 0, 193, 221, 183, 86, 201, 123, 73, 196, 127, 56, 174, 6, 115, 95, 196, 176, 10, 125, 21, 64, 56, 170, 84, 24, 59, 201, 230, 237, 202, 157, 215, 222, 2, 101, 92, 227, 241, 163, 91, 34, 14, 20, 238, 248, 91, 77, 189, 21, 255, 2, 101, 109, 202, 199, 190, 6, 158, 138, 61, 152, 214, 136, 39, 23, 201, 180, 98, 150, 25, 117, 184, 95, 78, 141, 222, 112, 89, 144, 198, 105, 2, 215, 249, 96, 143, 220, 2, 29, 180, 46, 114, 21, 209, 0, 29, 69, 31, 242, 23, 105, 210, 195, 68, 125, 46, 221, 63, 235, 76, 117, 122, 116, 105, 107, 124, 55, 39, 218, 8, 76, 59, 97, 99, 122, 0, 35, 89, 216];

        let proof_temp  = converter::load_groth16_proof_from_bytes(&proofbin).unwrap();
        let vk_temp = converter::load_groth16_verifying_key_from_bytes(&vkbin).unwrap();

        let vk_arks = VerifyingKey::<Bn254> {
            alpha_g1: vk_temp.g1.alpha,
            beta_g2: vk_temp.g2.beta,
            gamma_g2: vk_temp.g2.gamma,
            delta_g2: vk_temp.g2.delta,
            gamma_abc_g1: vk_temp.g1.k,
        };

        let proof_arks = Proof::<Bn254> {
            a: proof_temp.ar,
            b: proof_temp.bs,
            c: proof_temp.krs,
        };

        let proof_with_neg_a = Proof::<Bn254> {
            a: proof_arks.a.neg(),
            b: proof_arks.b,
            c: proof_arks.c,
        };

        let mut proof_bytes = Vec::with_capacity(proof_with_neg_a.serialized_size(Compress::No));
        proof_with_neg_a
            .serialize_uncompressed(&mut proof_bytes)
            .expect("Error serializing proof");

        let mut vk_bytes = Vec::with_capacity(vk_arks.serialized_size(Compress::No));
        vk_arks.serialize_uncompressed(&mut vk_bytes).expect("");
        
        let pvk = prepare_verifying_key(&vk_arks);
        let mut pvk_bytes = Vec::with_capacity(pvk.serialized_size(Compress::No));
        pvk.serialize_uncompressed(&mut pvk_bytes).expect("");

        let projective: G1Projective = prepare_inputs(&vk_arks, &public_inputs)
            .expect("Error preparing inputs with public inputs and prepared verifying key");

        let mut g1_bytes = Vec::with_capacity(projective.serialized_size(Compress::No));
        projective.serialize_uncompressed(&mut g1_bytes).expect("");

        let proof_a: [u8; 64] =
            convert_endianness::<32, 64>(proof_bytes[0..64].try_into().unwrap());
        let proof_b: [u8; 128] =
            convert_endianness::<64, 128>(proof_bytes[64..192].try_into().unwrap());
        let proof_c: [u8; 64] =
            convert_endianness::<32, 64>(proof_bytes[192..256].try_into().unwrap());

        let prepared_public_input =
            convert_endianness::<32, 64>(<&[u8; 64]>::try_from(g1_bytes.as_slice()).unwrap());

        let groth_vk_prepared = convert_arkworks_verifying_key_to_solana_verifying_key_prepared(&vk_arks);

        let mut verifier: Groth16VerifierPrepared = Groth16VerifierPrepared::new(
            proof_a,
            proof_b,
            proof_c,
            prepared_public_input,
            groth_vk_prepared,
        )
            .unwrap();

        match verifier.verify() {
            Ok(true) => {
                info!("Proof verification succeeded");
                println!("proof success")
            }
            Ok(false) => {
                info!("Proof verification failed");
                println!("proof failed")
            }
            Err(error) => {
                info!("Proof verification failed with error: {:?}", error);
                println!("proof error")
            }
        }

    }

    fn serialize_g1(_output: &mut Vec<u8>, point: &G1Affine) {
        let mut serialized = Vec::new();
        point.serialize_uncompressed(&mut serialized).unwrap();

        // Reverse bytes for each coordinate (32 bytes each for x and y)
        // for chunk in serialized.chunks_exact(32) {
        //     output.extend(chunk.iter().rev());
        // }
    }

    fn serialize_g2(_output: &mut Vec<u8>, point: &G2Affine) {
        let mut serialized = Vec::new();
        point.serialize_uncompressed(&mut serialized).unwrap();

        // Reverse bytes for each coordinate (64 bytes each for x and y, as they are elements of Fp2)
        // for chunk in serialized.chunks_exact(64) {
        //     output.extend(chunk.iter().rev());
        // }
    }
}
