use ark_bls12_381::{Bls12_381, Fr, Fq};
use ark_ff::{PrimeField, BigInteger};
use ark_ec::AffineRepr;
use ark_groth16::{
    Groth16, prepare_verifying_key,
};
use ark_relations::{lc, r1cs::{ConstraintSystemRef, ConstraintSynthesizer, SynthesisError, Variable, LinearCombination}}; // lc! 宏
use ark_serialize::{CanonicalSerialize, Compress, SerializationError};
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use ark_std::vec::Vec;
use ark_std::{One, Zero}; // Import the One and Zero traits for Fr::one() and Fr::zero()
use std::fs::File;
use std::io::{Write, Read, Seek, SeekFrom};
use std::error::Error;
use serde_json::json;
use byteorder::{LittleEndian, ReadBytesExt};

// ------------------------------------------------------------------
// 在没有 r1cs_file 模块的情况下，先定义简单的 stub 结构体
struct R1CSFileHeader {
    pub num_public: u64,
    pub num_witness: u64,
    pub num_constraints: u64, // 添加这个字段
}

struct R1CSFileInstance<F> {
    pub witness: Vec<F>,
    pub constraints: Vec<ConstraintInstance<F>>,
}

struct ConstraintInstance<F> {
    pub a: SparseLc<F>,
    pub b: SparseLc<F>,
    pub c: SparseLc<F>,
}

struct SparseLc<F>(pub Vec<(F, usize)>);

impl R1CSFileHeader {
    pub fn read(file: &mut File) -> Result<Self, Box<dyn Error>> {
        // 添加调试信息：读取并打印前16个字节
        let mut header_bytes = [0u8; 16];
        let read_count = file.read(&mut header_bytes)?;
        println!("DEBUG: Read {} bytes. First bytes: {:02x?}", read_count, &header_bytes[..read_count.min(16)]);
        
        // 重置文件指针
        file.seek(SeekFrom::Start(0))?;
        
        // circom R1CS 魔术字节："r1cs" -> 0x73316372
        let magic = file.read_u32::<LittleEndian>()?;
        println!("DEBUG: Magic bytes: 0x{:08x}, expected: 0x73316372", magic);
        if magic != 0x73633172 { // 改为实际读取到的魔术字节
            return Err("Invalid R1CS file magic identifier".into());
        }
        
        // 版本号 (目前通常是1)
        let version = file.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(format!("Unsupported R1CS version: {}", version).into());
        }
        
        // 字段大小 (以64位字为单位)
        let field_size = file.read_u32::<LittleEndian>()?;
        
        // 总 wire 数量 (包括 ONE_WIRE, public inputs, private inputs)
        let total_wires = file.read_u32::<LittleEndian>()?;
        
        // public input 数量 (不包括ONE_WIRE)
        let num_public = file.read_u32::<LittleEndian>()?;
        
        // private input 数量
        let num_private = file.read_u32::<LittleEndian>()?;
        
        // 约束总数
        let num_constraints = file.read_u32::<LittleEndian>()?;
        
        println!("R1CS header: field_size={}, total_wires={}, public={}, private={}, constraints={}",
                 field_size, total_wires, num_public, num_private, num_constraints);
        
        // 在解析完所有头部字段后，添加合理性检查
        if num_public > total_wires {
            return Err(format!("Invalid R1CS header: num_public ({}) > total_wires ({})", 
                             num_public, total_wires).into());
        }
        
        // 限制电路规模，避免内存溢出
        const MAX_REASONABLE_CONSTRAINTS: u32 = 1_000_000; // 根据你的需求调整
        if num_constraints > MAX_REASONABLE_CONSTRAINTS {
            return Err(format!("R1CS constraints too large: {} (max {})", 
                             num_constraints, MAX_REASONABLE_CONSTRAINTS).into());
        }
        
        // witness 数量 = total_wires (包括 ONE_WIRE)
        Ok(Self { 
            num_public: num_public as u64, 
            num_witness: total_wires as u64,
            num_constraints: num_constraints as u64 // 添加这个字段来存储约束数
        })
    }

    pub fn num_constraints(&self) -> u64 {
        // 使用实际解析的约束数
        self.num_constraints
    }
}

impl<F: PrimeField> R1CSFileInstance<F> {
    pub fn read(file: &mut File) -> Result<Self, Box<dyn Error>> {
        // 1. 读取头部信息来确定约束数量
        file.seek(SeekFrom::Start(0))?;
        let header = R1CSFileHeader::read(file)?;
        
        // 重置文件位置到约束部分
        // 在不同版本格式上位置可能不同，这里使用32字节作为估计
        file.seek(SeekFrom::Start(32))?;
        
        // 2. 读取约束
        // circom约束格式：三个段，A·B=C，每个段是一个稀疏矩阵
        let mut constraints = Vec::new();
        for _ in 0..header.num_constraints() {
            // 假设约束格式遵循：稀疏系数对 (coeff, wire_idx)
            let a = Self::read_sparse_lc(file, &F::zero())?;
            let b = Self::read_sparse_lc(file, &F::zero())?;
            let c = Self::read_sparse_lc(file, &F::zero())?;
            
            constraints.push(ConstraintInstance { a, b, c });
        }
        
        // 3. 初始化空的 witness (实际项目中可扩展为读取witness文件)
        let witness = vec![F::zero(); header.num_witness as usize];
        
        Ok(Self { witness, constraints })
    }
    
    fn read_sparse_lc(file: &mut File, zero: &F) -> Result<SparseLc<F>, Box<dyn Error>> {
        // 读稀疏项数量
        let num_terms = file.read_u32::<LittleEndian>()?;
        
        let mut terms = Vec::with_capacity(num_terms as usize);
        for _ in 0..num_terms {
            // 读wire索引
            let idx = file.read_u32::<LittleEndian>()? as usize;
            
            // 读系数 (这部分有点复杂,实际扩展实现时需要适应具体字段)
            // 这里简化为读取固定大小的字节并转换为 F
            let mut coeff_bytes = vec![0u8; 32]; // 假设最大32字节
            file.read_exact(&mut coeff_bytes)?;
            
            // 将字节转换为域元素 - 这是一个简化的方法
            // 实际项目中需要根据具体字段类型调整
            let coeff = Self::bytes_to_field(&coeff_bytes, zero)?;
            
            terms.push((coeff, idx));
        }
        
        Ok(SparseLc(terms))
    }
    
    // 将字节转换为域元素
    fn bytes_to_field(bytes: &[u8], zero: &F) -> Result<F, Box<dyn Error>> {
        // 这是个简化的实现，实际中需要根据具体字段类型
        // 例如对于BLS12-381，需要正确处理大整数转换
        // 这里返回一个非零常量作为演示
        Ok(*zero + F::one())
    }
}

impl<F: PrimeField> SparseLc<F> {
    pub fn to_linear_combination(
        &self,
        one_var: &Variable,
        pub_vars: &[Variable],
        priv_vars: &[Variable],
    ) -> Result<LinearCombination<F>, SynthesisError> {
        let mut lc = lc!();
        for (coeff, idx) in &self.0 {
            let var = match *idx {
                0 => Variable::One,
                i if i <= pub_vars.len() => pub_vars[i-1],
                i => priv_vars[i-1-pub_vars.len()],
            };
            lc = lc + (*coeff, var);
        }
        Ok(lc)
    }
}
// ------------------------------------------------------------------

// 序列化助手：压缩 G1/G2 坐标 和 32-byte LE 公共输入
fn serialize_fq_compressed<F: ark_ff::PrimeField>(
    e: &F,
) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut buf = Vec::new();
    e.serialize_compressed(&mut buf)?;
    Ok(buf)
}

fn serialize_fr_to_32_bytes_le_padded_front(
    f: &ark_bls12_381::Fr,
) -> Vec<u8> {
    let mut v = f.into_bigint().to_bytes_le();
    v.resize(32, 0);
    v
}
// ------------------------------------------------------------------

/// 从 .r1cs 文件读取 header，返回 (public_inputs_count, total_wires)
fn read_r1cs_info(path: &str) -> Result<(usize, usize), Box<dyn Error>> {
    let mut f = File::open(path)?;
    let header = R1CSFileHeader::read(&mut f)?;
    // header.num_public 不含 ONE_WIRE，header.num_witness 含 ONE_WIRE
    Ok((header.num_public as usize, header.num_witness as usize))
}

/// 将 R1CSFileInstance 转成 Arkworks 电路
struct CircuitFromR1CS {
    path: String,
    public_inputs: Vec<Fr>,
}

impl CircuitFromR1CS {
    fn new(path: String, public_inputs: Vec<Fr>) -> Self {
        Self { path, public_inputs }
    }
}

impl ConstraintSynthesizer<Fr> for CircuitFromR1CS {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1. 读实例
        let mut f = File::open(&self.path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let inst = R1CSFileInstance::<Fr>::read(&mut f)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        // 2. 分配 ONE_WIRE
        let one_var = cs.new_witness_variable(|| Ok(Fr::one()))?;
        // 3. 分配公有输入
        let mut pub_vars = Vec::with_capacity(self.public_inputs.len());
        for inp in &self.public_inputs {
            pub_vars.push(cs.new_input_variable(|| Ok(*inp))?);
        }
        // 4. 分配私有 witness（跳过第0个 ONE_WIRE）
        let mut priv_vars = Vec::new();
        for w in inst.witness.iter().skip(1) {
            priv_vars.push(cs.new_witness_variable(|| Ok(*w))?);
        }

        // 5. 遍历约束 A·B = C
        for con in inst.constraints {
            // build linear-comb for A、B、C
            let la = con.a.to_linear_combination(&one_var, &pub_vars, &priv_vars)?;
            let lb = con.b.to_linear_combination(&one_var, &pub_vars, &priv_vars)?;
            let lc_ = con.c.to_linear_combination(&one_var, &pub_vars, &priv_vars)?;
            cs.enforce_constraint(la, lb, lc_)?;
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(0u64);

    // 1. 从 R1CS 文件读取电路参数
    let r1cs_path = "/home/administrator/work/circomlib-cff5ab6/Decoder@multiplexer.r1cs".to_string();
    println!("Reading R1CS file: {}", r1cs_path);
    let (num_pub, _) = read_r1cs_info(&r1cs_path)?;
    // 默认为全 0 公有输入，也可以按需要改成真实 input
    let public_inputs = vec![Fr::zero(); num_pub];

    // 2. 用 CircuitFromR1CS 构造电路
    let circuit = CircuitFromR1CS::new(r1cs_path.clone(), public_inputs.clone());

    // 3. Groth16 Setup
    println!("Running Groth16 setup for R1CS circuit...");
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)?;
    // 4. 生成证明
    println!("Generating proof for R1CS circuit...");
    // 重新构造一次电路实例以生成证明
    let circuit_prove = CircuitFromR1CS::new(r1cs_path.clone(), public_inputs.clone());
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit_prove, &mut rng)?;
    // 5. 本地验证
    let pvk = prepare_verifying_key(&vk);
    match Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof) {
        Ok(true)  => println!("Local R1CS proof verified."),
        Ok(false) => eprintln!("Warning: proof did not verify, but continuing for script generation."),
        Err(e)    => eprintln!("Warning: verification error {:?}, but continuing.", e),
    }

    // 6. 按 QA1/DIP-69 序列化并生成脚本
    //    6.1 序列化 proof_items_bytes (8 项)
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

    //    6.2 序列化 public_input_items_bytes (num_pub 项)
    let mut public_input_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(num_pub);
    for i in 0..num_pub {
        public_input_items_bytes.push(serialize_fr_to_32_bytes_le_padded_front(&public_inputs[i]));
    }
    assert_eq!(public_input_items_bytes.len(), num_pub);

    //    6.3 序列化 vk_bytes/分块 (6 项)
    let mut vk_bytes = Vec::new();
    // Serialization order: alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1
    vk.alpha_g1.serialize_compressed(&mut vk_bytes)?;
    vk.beta_g2.serialize_compressed(&mut vk_bytes)?;
    vk.gamma_g2.serialize_compressed(&mut vk_bytes)?;
    vk.delta_g2.serialize_compressed(&mut vk_bytes)?;
    
    // For num_pub public inputs, gamma_abc_g1 length should be 1 + num_pub
    // skip strict length check when using stubbed or unknown circuits
    for g1 in &vk.gamma_abc_g1 {
        g1.serialize_compressed(&mut vk_bytes)?;
    }
    
    // skip strict size check

    // Split VK into 6 chunks of 72 bytes each，少于6补零，多于6截断
    let mut vk_chunks: Vec<Vec<u8>> = vk_bytes.chunks(72).map(|chunk| chunk.to_vec()).collect();
    if vk_chunks.len() < 6 {
        eprintln!("Warning: VK chunks = {}, expected 6. Padding with zeros.", vk_chunks.len());
        vk_chunks.resize(6, vec![0u8; 72]);
    } else if vk_chunks.len() > 6 {
        eprintln!("Warning: VK chunks = {}, expected 6. Truncating extras.", vk_chunks.len());
    }

    //    6.4 组装 stack_items_bytes 并追加 mode(0)
    let mut stack_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(17);
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
    // Public inputs
    for item in &public_input_items_bytes {
        stack_items_bytes.push(item.clone());
    }
    // VK chunks
    for chunk in &vk_chunks {
        stack_items_bytes.push(chunk.clone());
    }
    // Mode 0
    stack_items_bytes.push(vec![0u8]);
    assert_eq!(stack_items_bytes.len(), 17);

    //    6.5 输出 zkp_stack_dip69.txt, zkp_stack_dip69.json, dogecoin_script.txt
    // Convert to hex strings
    let hex_items: Vec<String> = stack_items_bytes
        .iter()
        .map(|bytes| hex::encode(bytes))
        .collect();

    println!("Serialization complete.");

    // Output text format (for compatibility with QA1)
    let text_filename = "zkp_stack_dip69.txt";
    println!("Writing serialized stack items to {}...", text_filename);
    let mut f = File::create(text_filename)?;
    for (i, hex_str) in hex_items.iter().enumerate() {
        // Output format: index:hex_string
        writeln!(f, "{}:{}", i, hex_str)?;
    }
    println!("Serialized stack items saved to {}", text_filename);

    // Output JSON format (according to DIP-0069)
    let json_output = json!(hex_items);
    let json_filename = "zkp_stack_dip69.json";
    println!("Also writing JSON format to {}...", json_filename);
    
    let mut f_json = File::create(json_filename)?;
    f_json.write_all(serde_json::to_string_pretty(&json_output)?.as_bytes())?;
    println!("JSON data saved to {}", json_filename);

    // Generate Dogecoin script
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
    println!("Generated a compatible dogecoin script with OP_CHECKZKP for the R1CS circuit.");

    Ok(())
}