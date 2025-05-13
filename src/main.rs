mod r1cs;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{Zero, One};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::io;
use std::path::PathBuf;
use std::fs;
use ark_snark::SNARK;

struct CircuitFromR1CS {
    r1cs: r1cs::R1CS,
    witness_values: Vec<Fr>,
}

impl CircuitFromR1CS {
    fn new(r1cs: r1cs::R1CS) -> Self {
        let num_wires = r1cs.num_wires() as usize;
        let mut witness_values = vec![Fr::zero(); num_wires];
        
        // Set ONE wire
        witness_values[0] = Fr::one();
        
        // For demonstration, set simple values for public inputs
        // In a real scenario, these would be the actual input values
        for i in 1..=r1cs.num_public_values() as usize {
            if i < witness_values.len() {
                witness_values[i] = Fr::from(i as u64);
            }
        }
        
        // For private inputs, set some sample values
        for i in (r1cs.num_public_values() as usize + 1)..num_wires {
            witness_values[i] = Fr::from((i * 10) as u64);
        }
        
        println!("Initialized witness values:");
        for (i, val) in witness_values.iter().enumerate().take(10) {
            println!("  x{} = {:?}", i, val);
        }
        if num_wires > 10 {
            println!("  ... and {} more values", num_wires - 10);
        }
        
        Self {
            r1cs,
            witness_values,
        }
    }
    
    // Get the public inputs for verification
    fn get_public_inputs(&self) -> Vec<Fr> {
        let mut public_inputs = Vec::new();
        
        // Add public outputs and inputs
        let public_count = self.r1cs.num_public_values() as usize;
        for i in 1..=public_count {
            if i < self.witness_values.len() {
                public_inputs.push(self.witness_values[i]);
            }
        }
        
        public_inputs
    }
}

impl ConstraintSynthesizer<Fr> for CircuitFromR1CS {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        println!("Generating constraints for R1CS circuit...");
        
        // Allocate variables
        let num_wires = self.r1cs.num_wires() as usize;
        let num_public = self.r1cs.num_public_values() as usize;
        
        println!("Allocating {} variables ({} public, {} private)...", 
                 num_wires, num_public + 1, num_wires - num_public - 1);
        
        // Allocate ONE wire (constant 1)
        let one_var = cs.new_input_variable(|| Ok(Fr::one()))?;
        
        let mut variables = vec![one_var];
        
        // Allocate public input variables (public outputs + public inputs)
        for i in 1..=num_public {
            if i < self.witness_values.len() {
                let var = cs.new_input_variable(|| Ok(self.witness_values[i]))?;
                variables.push(var);
            }
        }
        
        // Allocate private witness variables
        for i in (num_public + 1)..num_wires {
            if i < self.witness_values.len() {
                let var = cs.new_witness_variable(|| Ok(self.witness_values[i]))?;
                variables.push(var);
            }
        }
        
        // Add constraints
        let constraints = self.r1cs.constraints();
        println!("Adding {} constraints to the circuit...", constraints.len());
        
        for (idx, constraint) in constraints.iter().enumerate() {
            // Create linear combinations for A, B, and C
            let mut a_lc = ark_relations::r1cs::LinearCombination::<Fr>::zero();
            for term in &constraint.a_terms {
                if term.wire_id as usize >= variables.len() {
                    return Err(SynthesisError::AssignmentMissing);
                }
                a_lc = a_lc + (term.coefficient, variables[term.wire_id as usize]);
            }
            
            let mut b_lc = ark_relations::r1cs::LinearCombination::<Fr>::zero();
            if constraint.b_terms.is_empty() {
                // If B is empty, use 1 (ONE_WIRE)
                b_lc = b_lc + (Fr::one(), variables[0]);
            } else {
                for term in &constraint.b_terms {
                    if term.wire_id as usize >= variables.len() {
                        return Err(SynthesisError::AssignmentMissing);
                    }
                    b_lc = b_lc + (term.coefficient, variables[term.wire_id as usize]);
                }
            }
            
            let mut c_lc = ark_relations::r1cs::LinearCombination::<Fr>::zero();
            for term in &constraint.c_terms {
                if term.wire_id as usize >= variables.len() {
                    return Err(SynthesisError::AssignmentMissing);
                }
                c_lc = c_lc + (term.coefficient, variables[term.wire_id as usize]);
            }
            
            // Enforce the constraint: A * B = C
            cs.enforce_constraint(a_lc, b_lc, c_lc)?;
            
            if idx < 3 || idx == constraints.len() - 1 {
                println!("  Added constraint #{}: {}", idx, constraint);
            } else if idx == 3 {
                println!("  ... and {} more constraints", constraints.len() - 4);
            }
        }
        
        println!("Circuit generation complete with {} constraints", constraints.len());
        Ok(())
    }
}

fn main() -> io::Result<()> {
    // Use the hardcoded path directly without any search logic
    let r1cs_path = PathBuf::from("/Users/hiranokaoru/localwork/work/circomlib-cff5ab6/Decoder@multiplexer.r1cs");
    println!("📂 Using R1CS file: {}", r1cs_path.display());
    
    // Parse the R1CS file
    let r1cs = match r1cs::R1CS::read(&r1cs_path) {
        Ok(r1cs) => {
            println!("✅ Successfully parsed R1CS file");
            r1cs
        },
        Err(e) => {
            println!("❌ Failed to read R1CS file: {}", e);
            return Err(e);
        }
    };
    
    // Print detailed R1CS information
    r1cs.print_info();
    
    // Create circuit from R1CS
    println!("\nCreating circuit from R1CS...");
    let circuit = CircuitFromR1CS::new(r1cs);
    
    // Generate Groth16 parameters
    println!("\nRunning Groth16 setup...");
    let mut rng = StdRng::seed_from_u64(123456789);
    
    let params = match Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        circuit,
        &mut rng,
    ) {
        Ok(params) => {
            println!("✅ Successfully generated Groth16 parameters");
            params
        },
        Err(e) => {
            println!("❌ Failed to generate Groth16 parameters: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", e)));
        }
    };
    
    // We need to read the R1CS file again for proof generation
    let r1cs = r1cs::R1CS::read(&r1cs_path)?;
    let circuit_for_proving = CircuitFromR1CS::new(r1cs);
    
    // Get public inputs for verification
    let public_inputs = circuit_for_proving.get_public_inputs();
    println!("\nPublic inputs for verification: {} values", public_inputs.len());
    for (i, input) in public_inputs.iter().enumerate() {
        println!("  Public input #{}: {:?}", i, input);
    }
    
    // Generate proof
    println!("\nGenerating Groth16 proof...");
    let proof = match Groth16::<Bls12_381>::prove(&params, circuit_for_proving, &mut rng) {
        Ok(proof) => {
            println!("✅ Successfully generated proof");
            proof
        },
        Err(e) => {
            println!("❌ Failed to generate proof: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", e)));
        }
    };
    
    // Verify proof locally
    println!("\nVerifying proof locally...");
    let pvk = prepare_verifying_key(&params.vk);
    
    match Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof) {
        Ok(true) => println!("✅ Proof verified successfully!"),
        Ok(false) => println!("❌ Proof verification failed!"),
        Err(e) => println!("❌ Error during verification: {}", e),
    }
    
    println!("\nR1CS processing complete!");
    
    Ok(())
}