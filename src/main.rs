use ark_bls12_381::{Bls12_381, Fr, Fq};
use ark_ff::{PrimeField, BigInteger};
use ark_ec::AffineRepr;
use ark_groth16::{
    Groth16, prepare_verifying_key,
};
use ark_relations::{
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use ark_serialize::{CanonicalSerialize, Compress, SerializationError};
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use ark_std::vec::Vec;
use ark_std::{One, Zero}; // Import the One and Zero traits for Fr::one() and Fr::zero()
use std::fs::File;
use std::io::{Write};
use std::error::Error;
use serde_json::json;

// Constraint synthesizer for R1CS files
struct CircuitFromR1CS {
    public_inputs: Vec<Fr>,
    witness: Vec<Fr>,
}

impl CircuitFromR1CS {
    // Create a new circuit with default values
    fn new(num_public_inputs: usize, num_variables: usize) -> Self {
        let mut witness = vec![Fr::one()]; // First witness is always 1 (ONE_WIRE)
        
        // Fill with public inputs (we'll use some test values)
        for i in 0..num_public_inputs {
            witness.push(Fr::from(i as u64 + 1));
        }
        
        // Fill remaining private inputs with dummy values
        let private_inputs = num_variables - num_public_inputs - 1;
        for i in 0..private_inputs {
            witness.push(Fr::from(i as u64 + 42));
        }
        
        // Extract public inputs (excluding ONE_WIRE)
        let public_inputs = witness[1..num_public_inputs+1].to_vec();
        
        CircuitFromR1CS {
            public_inputs,
            witness,
        }
    }
}

impl ConstraintSynthesizer<Fr> for CircuitFromR1CS {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>, // Fixed: Changed from &mut ConstraintSystem<Fr> to ConstraintSystemRef<Fr>
    ) -> Result<(), SynthesisError> {
        // Allocate variables based on witness values
        let mut variables = Vec::with_capacity(self.witness.len());
        
        // ONE_WIRE is always the first variable
        variables.push(cs.new_input_variable(|| Ok(Fr::one()))?);
        
        // Allocate public input variables
        for i in 0..self.public_inputs.len() {
            let idx = i + 1; // +1 because ONE_WIRE is at index 0
            variables.push(cs.new_input_variable(|| Ok(self.witness[idx]))?);
        }
        
        // Allocate remaining private variables
        for i in (self.public_inputs.len() + 1)..self.witness.len() {
            variables.push(cs.new_witness_variable(|| Ok(self.witness[i]))?);
        }
        
        // Add some simple constraints for demonstration purposes
        // In a real implementation, these would come from the R1CS file
        // For the Decoder@multiplexer circuit, we'll add a constraint that models its behavior
        // For simplicity, we'll keep x + y = z constraint
        cs.enforce_constraint(
            lc!() + variables[1], // x
            lc!() + variables[2], // y
            lc!() + variables[3], // z
        )?;
        
        Ok(())
    }
}

/// A tiny “iszero” circuit: enforces input * 1 == 0
struct IsZeroCircuit {
    pub_input: Fr,
}

impl ConstraintSynthesizer<Fr> for IsZeroCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // allocate the public input
        let a_var = cs.new_input_variable(|| Ok(self.pub_input))?;
        // constant 1
        let one = Fr::one();
        // enforce a * 1 == 0  ⇒ a == 0
        cs.enforce_constraint(
            lc!() + a_var,
            lc!() + (one, Variable::One),  // use Variable::One for the constant term
            lc!(),                          // zero
        )?;
        Ok(())
    }
}

// Serialize Fq for G1/G2 coordinates in 48-byte compressed format
fn serialize_fq_compressed(f: &Fq) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::with_capacity(f.compressed_size());
    f.serialize_with_mode(&mut bytes, Compress::Yes)?;
    if bytes.len() != 48 {
        eprintln!("Warning: Fq compressed size is not 48 bytes, but {}", bytes.len());
        return Err(SerializationError::InvalidData);
    }
    Ok(bytes)
}

// Serialize Fr to 32-byte little-endian format with front padding
fn serialize_fr_to_32_bytes_le_padded_front(f: &Fr) -> Vec<u8> {
    let fr_bytes_le = f.into_bigint().to_bytes_le();
    let target_len = 32;
    let mut padded_bytes = vec![0u8; target_len]; // Initialize with zeros

    // Copy fr_bytes_le to the end of padded_bytes (front padding)
    let start_index = target_len.saturating_sub(fr_bytes_le.len());
    for (i, byte) in fr_bytes_le.iter().enumerate() {
        if start_index + i < target_len {
             padded_bytes[start_index + i] = *byte;
        }
    }
    padded_bytes
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(0u64);

    // ==== TEMP: use minimal iszero circuit (a * 1 == 0) ====
    // one public input = 0
    let zero = Fr::zero();
    let public_inputs = vec![zero];
    let circuit = IsZeroCircuit { pub_input: zero };

    // 1. Setup
    println!("Generating Groth16 parameters for iszero...");
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)?;
    // 2. Prove
    println!("Generating iszero proof...");
    let proof = Groth16::<Bls12_381>::prove(&pk, IsZeroCircuit { pub_input: zero }, &mut rng)?;
    // 3. Local verify
    let pvk = prepare_verifying_key(&vk);
    assert!(Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof)?);
    println!("iszero proof verified locally.");

    // 4. Serialization (exactly as your code does, but note public_inputs.len()==1)
    // 8.1 Serialize Proof components (π_Α, π_Β, π_C) - 8 items
    let mut proof_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(8);
    // π_Α (G1)
    proof_items_bytes.push(serialize_fq_compressed(proof.a.x().unwrap())?);
    proof_items_bytes.push(serialize_fq_compressed(proof.a.y().unwrap())?);
    // π_Β (G2) - coordinates are Fq2, containing c0, c1 (both Fq)
    let b_affine = proof.b;
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.x().unwrap().c0)?);
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.x().unwrap().c1)?);
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.y().unwrap().c0)?);
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.y().unwrap().c1)?);
    // π_C (G1)
    proof_items_bytes.push(serialize_fq_compressed(proof.c.x().unwrap())?);
    proof_items_bytes.push(serialize_fq_compressed(proof.c.y().unwrap())?);
    assert_eq!(proof_items_bytes.len(), 8);

    // 8.2 Serialize Public Inputs - 1 item
    let mut public_input_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(1);
    public_input_items_bytes.push(serialize_fr_to_32_bytes_le_padded_front(&public_inputs[0]));
    assert_eq!(public_input_items_bytes.len(), 1);

    // 8.3 Serialize Verifying Key (VK) and chunk - 6 items
    let mut vk_bytes = Vec::new();
    // Serialization order: alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1
    vk.alpha_g1.serialize_compressed(&mut vk_bytes)?;
    vk.beta_g2.serialize_compressed(&mut vk_bytes)?;
    vk.gamma_g2.serialize_compressed(&mut vk_bytes)?;
    vk.delta_g2.serialize_compressed(&mut vk_bytes)?;
    
    // For 1 public input, gamma_abc_g1 length should be 1 (constant term) + 1 (input term) = 2
    assert_eq!(vk.gamma_abc_g1.len(), public_inputs.len() + 1, 
               "VK gamma_abc_g1 length mismatch");
               
    for g1 in &vk.gamma_abc_g1 {
        g1.serialize_compressed(&mut vk_bytes)?;
    }
    
    // Check expected size: 48 (alpha_g1) + 96*3 (beta_g2, gamma_g2, delta_g2) + 48*2 (gamma_abc_g1)
    assert_eq!(vk_bytes.len(), 48 + 96*3 + 48*2, 
               "Serialized VK size is not 432 bytes");

    // Split VK into 6 chunks of 72 bytes each
    let vk_chunks: Vec<Vec<u8>> = vk_bytes.chunks(72).map(|chunk| chunk.to_vec()).collect();
    assert_eq!(vk_chunks.len(), 6, "VK did not split into 6 chunks");

    // 8.4 Assemble final 16 stack items in Dogecoin script push order:
    //    πA_x, πA_y,
    //    πB_x0, πB_x1, πB_y0, πB_y1,
    //    πC_x, πC_y,
    //    pub_input0,
    //    vk_chunk0…vk_chunk5,
    //    mode (0)
    let mut stack_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(16);
    // Proof πA
    stack_items_bytes.push(proof_items_bytes[0].clone());
    stack_items_bytes.push(proof_items_bytes[1].clone());
    // Proof πB
    stack_items_bytes.push(proof_items_bytes[2].clone());
    stack_items_bytes.push(proof_items_bytes[3].clone());
    stack_items_bytes.push(proof_items_bytes[4].clone());
    stack_items_bytes.push(proof_items_bytes[5].clone());
    // Proof πC
    stack_items_bytes.push(proof_items_bytes[6].clone());
    stack_items_bytes.push(proof_items_bytes[7].clone());
    // Public input
    stack_items_bytes.push(public_input_items_bytes[0].clone());
    // VK chunks
    for chunk in &vk_chunks {
        stack_items_bytes.push(chunk.clone());
    }
    // Mode 0
    stack_items_bytes.push(vec![0u8]);
    assert_eq!(stack_items_bytes.len(), 16);

    // 8.5 Convert to hex strings
    let hex_items: Vec<String> = stack_items_bytes
        .iter()
        .map(|bytes| hex::encode(bytes))
        .collect();

    println!("Serialization complete.");

    // 9. Output to files
    // 9.1 Output text format (for compatibility with QA1)
    let text_filename = "zkp_stack_dip69.txt";
    println!("Writing serialized stack items to {}...", text_filename);
    let mut f = File::create(text_filename)?;
    for (i, hex_str) in hex_items.iter().enumerate() {
        // Output format: index:hex_string
        writeln!(f, "{}:{}", i, hex_str)?;
    }
    println!("Serialized stack items saved to {}", text_filename);

    // 9.2 Output JSON format (according to DIP-0069)
    let json_output = json!(hex_items);
    let json_filename = "zkp_stack_dip69.json";
    println!("Also writing JSON format to {}...", json_filename);
    
    let mut f_json = File::create(json_filename)?;
    f_json.write_all(serde_json::to_string_pretty(&json_output)?.as_bytes())?;
    println!("JSON data saved to {}", json_filename);

    // 9.3 Generate Dogecoin script
    println!("Generating Dogecoin scriptPubKey...");
    let mut script_buf = Vec::new();
    for item_bytes in stack_items_bytes.iter() {
        let item_len = item_bytes.len();
        match item_len {
            1 if item_bytes[0] == 0 => {
                // OP_0
                script_buf.push(0x00);
            }
            1..=75 => {
                // single‐byte push
                script_buf.push(item_len as u8);
                script_buf.extend_from_slice(item_bytes);
            }
            76..=255 => {
                // OP_PUSHDATA1
                script_buf.push(0x4c);
                script_buf.push(item_len as u8);
                script_buf.extend_from_slice(item_bytes);
            }
            _ => {
                // OP_PUSHDATA2
                script_buf.push(0x4d);
                script_buf.push((item_len & 0xff) as u8);
                script_buf.push((item_len >> 8) as u8);
                script_buf.extend_from_slice(item_bytes);
            }
        }
    }
    // finally OP_CHECKZKP
    script_buf.push(0xb9);

    let script_hex = hex::encode(&script_buf);
    let mut f_script = File::create("dogecoin_script.txt")?;
    writeln!(f_script, "{}", script_hex)?;
    println!("Dogecoin scriptPubKey hex saved to dogecoin_script.txt");

    println!("Processing complete!");
    println!("Generated a compatible dogecoin script with OP_CHECKZKP for the iszero circuit.");

    Ok(())
}