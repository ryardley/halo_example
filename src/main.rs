mod example1;
mod example2;

fn main() {}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufReader, Write};
    use std::path::Path;
    use std::time::Instant;

    // use halo2_proofs::plonk::Error;

    use halo2_proofs::plonk::{create_proof, verify_proof, SingleVerifier};
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use rand::rngs::OsRng;

    // use crate::example1;
    use crate::example2;

    // #[test]
    // fn test_example1() -> Result<(), Error> {
    //     example1::test_example1()
    // }

    #[test]
    fn test_sha256() {
        use halo2_proofs::{
            pasta::EqAffine,
            plonk::{keygen_pk, keygen_vk},
            poly::commitment::Params,
        };
        println!("setting k");
        let k = 17;

        println!("empty circuit");
        let empty_circuit = example2::MyCircuit {};
        println!("params");

        let params_dir = Path::new("./benches/sha256_assets");
        std::fs::create_dir_all(params_dir).expect("Failed to create params dir");

        // Initialize the polynomial commitment parameters
        let params_path = Path::new("./benches/sha256_assets/sha256_params");
        if File::open(&params_path).is_err() {
            let params: Params<EqAffine> = Params::new(k);
            let mut buf = Vec::new();

            params.write(&mut buf).expect("Failed to write params");
            let mut file = File::create(&params_path).expect("Failed to create sha256_params");

            file.write_all(&buf[..])
                .expect("Failed to write params to file");
        }

        let params_fs = File::open(&params_path).expect("couldn't load sha256_params");
        let params: Params<EqAffine> =
            Params::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

        // Initialize the proving key
        println!("Generating verification key");
        let start = Instant::now();
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let duration = start.elapsed();
        println!("Verification key generation: {:?}", duration);

        println!("Generating proving key");
        let start = Instant::now();
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        let duration = start.elapsed();
        println!("Proving key generation: {:?}", duration);

        let circuit = example2::MyCircuit {};
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let start = Instant::now();
        create_proof(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let duration = start.elapsed();
        println!("Proof creation time: {:?}", duration);
        let proof: Vec<u8> = transcript.finalize();
        println!("{}", hex::encode(&proof));
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let start = Instant::now();
        assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
        let duration = start.elapsed();
        println!("Verification time: {:?}", duration);
    }
}
