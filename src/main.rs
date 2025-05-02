use ark_bls12_381::{Bls12_381, Fr, Fq};
use ark_ff::{PrimeField, BigInteger};
use ark_ec::AffineRepr;
use ark_groth16::{
    Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_serialize::{CanonicalSerialize, Compress, SerializationError};
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use ark_std::vec::Vec;
use std::fs::File;
use std::io::Write;
use std::error::Error;
use serde_json::json;

// 定义电路结构体 (a + b = c，含两个公共输入 c 和 d)
#[derive(Copy, Clone)]
pub struct AddCircuitWithTwoInputs {
    pub a: Option<Fr>, // 秘密输入 a
    pub b: Option<Fr>, // 秘密输入 b
    pub c: Option<Fr>, // 公共输入 c (第一个)
    pub d: Option<Fr>, // 公共输入 d (第二个, 虚拟)
}

// 为电路实现 ConstraintSynthesizer trait
impl ConstraintSynthesizer<Fr> for AddCircuitWithTwoInputs {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1. 分配变量
        let a_var =
            FpVar::<Fr>::new_witness(cs.clone(), || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var =
            FpVar::<Fr>::new_witness(cs.clone(), || self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c_var =
            FpVar::<Fr>::new_input(cs.clone(), || self.c.ok_or(SynthesisError::AssignmentMissing))?;
        let _d_var = // 分配但不使用 d_var，以满足公共输入数量要求
            FpVar::<Fr>::new_input(cs.clone(), || self.d.ok_or(SynthesisError::AssignmentMissing))?;

        // 2. 定义约束 a + b = c
        let sum_ab = a_var + b_var;
        sum_ab.enforce_equal(&c_var)?;

        Ok(())
    }
}

// 辅助函数: 序列化 Fq (G1/G2 坐标或其部分) 为 48 字节压缩格式
// 注意: ark-bls12-381 的 Fq 压缩大小确实是 48 字节
fn serialize_fq_compressed(f: &Fq) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::with_capacity(f.compressed_size());
    f.serialize_with_mode(&mut bytes, Compress::Yes)?;
    if bytes.len() != 48 {
        eprintln!("Warning: Fq compressed size is not 48 bytes, but {}", bytes.len());
        // 对于 ark-bls12-381 的 Fq, 压缩大小就是 48
        return Err(SerializationError::InvalidData);
    }
    Ok(bytes)
}

// 辅助函数: 序列化 Fr 元素为 32 字节小端序 (前面补零)
fn serialize_fr_to_32_bytes_le_padded_front(f: &Fr) -> Vec<u8> {
    let fr_bytes_le = f.into_bigint().to_bytes_le();
    let target_len = 32;
    let mut padded_bytes = vec![0u8; target_len]; // 初始化 32 个零

    // 计算起始位置，将 fr_bytes_le 复制到末尾（实现前导零填充）
    let start_index = target_len.saturating_sub(fr_bytes_le.len());
    for (i, byte) in fr_bytes_le.iter().enumerate() {
        if start_index + i < target_len {
             padded_bytes[start_index + i] = *byte;
        }
    }
    padded_bytes
}

// 主函数
fn main() -> Result<(), Box<dyn Error>> {
    // 使用确定性种子进行测试，以便每次运行结果一致
    let mut rng = StdRng::seed_from_u64(0u64);

    // == 1. Setup ==
    println!("Generating Groth16 parameters (using deterministic seed)...");
    let circuit_for_setup = AddCircuitWithTwoInputs { a: None, b: None, c: None, d: None };
    let pk: ProvingKey<Bls12_381> =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit_for_setup, &mut rng)?;
    let vk: VerifyingKey<Bls12_381> = pk.vk.clone();
    println!("Parameters generated.");

    // == 2. Proving ==
    println!("Preparing inputs and generating proof...");
    let a_val = Fr::from(3u64);
    let b_val = Fr::from(5u64);
    let c_val = Fr::from(8u64);
    let d_val = Fr::from(0u64); // 虚拟公共输入

    let circuit_for_proving = AddCircuitWithTwoInputs {
        a: Some(a_val),
        b: Some(b_val),
        c: Some(c_val),
        d: Some(d_val),
    };

    // 公共输入向量 [c, d]
    let public_inputs: Vec<Fr> = vec![c_val, d_val];

    let proof: Proof<Bls12_381> =
        Groth16::<Bls12_381>::prove(&pk, circuit_for_proving, &mut rng)?;
    println!("Proof generated.");

    // == (Optional) Local Verification ==
    println!("Performing local proof verification...");
    let pvk = prepare_verifying_key(&vk);
    let verified = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof)?;
    if !verified {
         return Err("Local proof verification failed!".into());
    }
    println!("Proof verified locally.");

    // == 3. Serialization according to DIP-69 ==
    println!("Serializing components for Dogecoin OP_CHECKZKP...");

    // 3.1 Serialize Proof components (π_Α, π_Β, π_C) - 8 items
    let mut proof_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(8);
    // π_Α (G1) - 使用 unwrap() 处理 Option
    proof_items_bytes.push(serialize_fq_compressed(proof.a.x().unwrap())?); // π_Α_x
    proof_items_bytes.push(serialize_fq_compressed(proof.a.y().unwrap())?); // π_Α_y
    // π_Β (G2) - 坐标是 Fq2, 包含 c0, c1 (均为 Fq) - 使用 unwrap() 处理 Option
    let b_affine = proof.b;
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.x().unwrap().c0)?); // π_Β_x_0
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.x().unwrap().c1)?); // π_Β_x_1
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.y().unwrap().c0)?); // π_Β_y_0
    proof_items_bytes.push(serialize_fq_compressed(&b_affine.y().unwrap().c1)?); // π_Β_y_1
    // π_C (G1) - 使用 unwrap() 处理 Option
    proof_items_bytes.push(serialize_fq_compressed(proof.c.x().unwrap())?); // π_C_x
    proof_items_bytes.push(serialize_fq_compressed(proof.c.y().unwrap())?); // π_C_y
    assert_eq!(proof_items_bytes.len(), 8);

    // 3.2 Serialize Public Inputs - 2 items
    let mut public_input_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(2);
    public_input_items_bytes.push(serialize_fr_to_32_bytes_le_padded_front(&public_inputs[0])); // Public Input 0 (c)
    public_input_items_bytes.push(serialize_fr_to_32_bytes_le_padded_front(&public_inputs[1])); // Public Input 1 (d)
    assert_eq!(public_input_items_bytes.len(), 2);

    // 3.3 Serialize Verifying Key (VK) and chunk - 6 items
    let mut vk_bytes = Vec::new();
    // 序列化顺序: alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1
    vk.alpha_g1.serialize_compressed(&mut vk_bytes)?; // 48 bytes
    vk.beta_g2.serialize_compressed(&mut vk_bytes)?;  // 96 bytes
    vk.gamma_g2.serialize_compressed(&mut vk_bytes)?; // 96 bytes
    vk.delta_g2.serialize_compressed(&mut vk_bytes)?; // 96 bytes
    // 对于 2 个公共输入, gamma_abc_g1 长度应为 1 (常数项) + 2 (公共输入项) = 3
    assert_eq!(vk.gamma_abc_g1.len(), public_inputs.len() + 1, "VK gamma_abc_g1 length mismatch");
    for g1 in &vk.gamma_abc_g1 {
        g1.serialize_compressed(&mut vk_bytes)?; // 3 * 48 = 144 bytes
    }
    assert_eq!(vk_bytes.len(), 48 + 96 * 3 + 144, "Serialized VK size is not 480 bytes"); // 48+288+144 = 480

    // 分割 VK 为 6 个 80 字节的块
    let vk_chunks: Vec<Vec<u8>> = vk_bytes.chunks(80).map(|chunk| chunk.to_vec()).collect();
    assert_eq!(vk_chunks.len(), 6, "VK did not split into 6 chunks");

    // 3.4 Assemble final 17 stack items in Dogecoin script push order (Index 0 to 16)
    let mut stack_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(17);
    stack_items_bytes.push(vec![0u8]);                     // Index 0: Mode 0
    stack_items_bytes.extend_from_slice(&vk_chunks);       // Index 1-6: VK chunks 0-5
    stack_items_bytes.push(public_input_items_bytes[1].clone()); // Index 7: Public Input 1 (d)
    stack_items_bytes.push(public_input_items_bytes[0].clone()); // Index 8: Public Input 0 (c)
    stack_items_bytes.push(proof_items_bytes[7].clone());  // Index 9: π_C_y
    stack_items_bytes.push(proof_items_bytes[6].clone());  // Index 10: π_C_x
    stack_items_bytes.push(proof_items_bytes[5].clone());  // Index 11: π_Β_y_1
    stack_items_bytes.push(proof_items_bytes[4].clone());  // Index 12: π_Β_y_0
    stack_items_bytes.push(proof_items_bytes[3].clone());  // Index 13: π_Β_x_1
    stack_items_bytes.push(proof_items_bytes[2].clone());  // Index 14: π_Β_x_0
    stack_items_bytes.push(proof_items_bytes[1].clone());  // Index 15: π_Α_y
    stack_items_bytes.push(proof_items_bytes[0].clone());  // Index 16: π_Α_x
    assert_eq!(stack_items_bytes.len(), 17, "Incorrect number of final stack items");

    // 3.5 Convert byte vectors to hex strings
    let hex_items: Vec<String> = stack_items_bytes
        .iter()
        .map(|bytes| hex::encode(bytes))
        .collect();

    println!("Serialization complete.");

    // == 4. Output to files ==
    // 4.1 Output text format (for compatibility)
    let text_filename = "zkp_stack_dip69.txt";
    println!("Writing serialized stack items to {}...", text_filename);
    let mut f = File::create(text_filename)?;
    for (i, hex_str) in hex_items.iter().enumerate() {
        // 输出格式: index:hex_string
        writeln!(f, "{}:{}", i, hex_str)?;
    }
    println!("Serialized stack items saved to {}", text_filename);

    // 4.2 Output JSON format (according to DIP-0069)
    let json_output = json!(hex_items);
    let json_filename = "zkp_stack_dip69.json";
    println!("Also writing JSON format to {}...", json_filename);
    
    let mut f_json = File::create(json_filename)?;
    f_json.write_all(serde_json::to_string_pretty(&json_output)?.as_bytes())?;
    println!("JSON data saved to {}", json_filename);

    Ok(())
}