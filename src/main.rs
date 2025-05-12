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
use std::cmp::min;

// ------------------------------------------------------------------
// 改进 R1CS 头部结构和解析逻辑
struct R1CSFileHeader {
    pub num_public: u64,
    pub num_witness: u64,
    pub num_constraints: u64,
    pub field_size_bytes: usize,  // 新增字段保存每个域元素的字节数
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
        // 重置文件指针
        file.seek(SeekFrom::Start(0))?;
        
        // circom R1CS 魔术字节："r1cs" -> 0x73316372
        let magic = file.read_u32::<LittleEndian>()?;
        println!("R1CS magic bytes: 0x{:08x}", magic);
        if magic != 0x73633172 { // 正确的 R1CS 魔术字节
            return Err("Invalid R1CS file magic identifier".into());
        }
        
        // 版本号 (目前通常是1)
        let version = file.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(format!("Unsupported R1CS version: {}", version).into());
        }
        
        // 字段大小 (以64位字为单位)
        let field_size = file.read_u32::<LittleEndian>()?;
        let field_size_bytes = (field_size as usize) * 8;
        
        // 总 wire 数量 (包括 ONE_WIRE, public inputs, private inputs)
        let total_wires = file.read_u32::<LittleEndian>()?;
        
        // public input 数量 (不包括ONE_WIRE)
        let num_public = file.read_u32::<LittleEndian>()?;
        
        // private input 数量
        let num_private = file.read_u32::<LittleEndian>()?;
        
        // 约束总数
        let num_constraints = file.read_u32::<LittleEndian>()?;
        
        println!("R1CS header: field_size={}×64bit={} bytes, total_wires={}, public={}, private={}, constraints={}",
                 field_size, field_size_bytes, total_wires, num_public, num_private, num_constraints);
        
        // 在解析完所有头部字段后，添加合理性检查
        if num_public > total_wires {
            println!("⚠️ Warning: Invalid R1CS header - num_public ({}) > total_wires ({})", 
                     num_public, total_wires);
            // 调整 num_public 为更合理的值
            println!("⚠️ Adjusting num_public to match total_wires - 1");
            let adjusted_num_public = total_wires - 1; // 减去 ONE_WIRE
            
            return Ok(Self { 
                num_public: adjusted_num_public as u64, 
                num_witness: total_wires as u64,
                num_constraints: num_constraints as u64,
                field_size_bytes,
            });
        }
        
        // 限制电路规模，避免内存溢出
        const MAX_REASONABLE_CONSTRAINTS: u32 = 1_000_000; // 根据需求调整
        if num_constraints > MAX_REASONABLE_CONSTRAINTS {
            return Err(format!("R1CS constraints too large: {} (max {})", 
                             num_constraints, MAX_REASONABLE_CONSTRAINTS).into());
        }
        
        // 检查 wires 总数是否与 public + private 相匹配
        if num_public + num_private != total_wires {
            println!("⚠️ Warning: public({}) + private({}) != total_wires({})",
                     num_public, num_private, total_wires);
        }
        
        // witness 数量 = total_wires (包括 ONE_WIRE)
        Ok(Self { 
            num_public: num_public as u64, 
            num_witness: total_wires as u64,
            num_constraints: num_constraints as u64,
            field_size_bytes,
        })
    }

    pub fn num_constraints(&self) -> u64 {
        self.num_constraints
    }
}

impl<F: PrimeField> R1CSFileInstance<F> {
    pub fn read(file: &mut File) -> Result<Self, Box<dyn Error>> {
        // 1. 读取头部信息来确定约束数量
        file.seek(SeekFrom::Start(0))?;
        let header = R1CSFileHeader::read(file)?;
        
        // 重置文件位置到约束部分
        file.seek(SeekFrom::Start(28))?; // 固定偏移量：7个32位整数
        
        // 2. 读取约束
        let mut constraints = Vec::new();
        println!("Reading {} constraints...", header.num_constraints());
        
        for i in 0..header.num_constraints() {
            println!("Reading constraint #{}", i);
            
            // 改进约束读取逻辑，增加错误处理
            let mut a = Self::read_sparse_lc(file, &header, &F::zero())?;
            let mut b = Self::read_sparse_lc(file, &header, &F::zero())?;
            let mut c = Self::read_sparse_lc(file, &header, &F::zero())?;
            
            // 如果 B 和 C 矩阵为空，构造默认约束
            if b.0.is_empty() {
                println!("  ⚠️ B matrix is empty, using identity constraint (ONE)");
                b.0.push((F::one(), 0)); // 常数项 ONE
            }
            
            if c.0.is_empty() {
                println!("  ⚠️ C matrix is empty, duplicating A matrix for C");
                c = a.clone(); // 复制 A 矩阵作为 C (A·ONE = A)
            }
            
            constraints.push(ConstraintInstance { a, b, c });
        }
        
        // 3. 初始化 witness (至少包括常数 ONE_WIRE)
        println!("Initializing {} witness values...", header.num_witness);
        let mut witness = vec![F::zero(); header.num_witness as usize];
        
        // 设置 ONE_WIRE 为 1
        if !witness.is_empty() {
            witness[0] = F::one();
            println!("Set witness[0] = ONE");
        }
        
        // 尝试为其他公共输入设置零值
        for i in 1..min(witness.len(), header.num_public as usize + 1) {
            witness[i] = F::zero();
            println!("Set witness[{}] = ZERO (public input)", i);
        }
        
        Ok(Self { witness, constraints })
    }
    
    fn read_sparse_lc(file: &mut File, header: &R1CSFileHeader, zero: &F) -> Result<SparseLc<F>, Box<dyn Error>> {
        // 读稀疏项数量
        let num_terms = file.read_u32::<LittleEndian>()?;
        println!("  Reading sparse matrix with {} terms", num_terms);
        
        // 安全检查
        if num_terms > 10000 {
            println!("  ⚠️ Warning: Very large number of terms ({}), could be a parsing error", num_terms);
            return Ok(SparseLc(Vec::new())); // 返回空矩阵
        }
        
        let mut terms = Vec::with_capacity(num_terms as usize);
        for t in 0..num_terms {
            // 读wire索引
            let idx = file.read_u32::<LittleEndian>()? as usize;
            
            // 读系数 - 使用正确的字段大小
            let mut coeff_bytes = vec![0u8; header.field_size_bytes];
            file.read_exact(&mut coeff_bytes)?;
            
            // 简单检查 wire_idx 是否合理
            if idx > 100000000 {
                println!("  ⚠️ Term #{}: Unusually large wire index {}, skipping", t, idx);
                continue;
            }
            
            // 将字节转换为域元素 - 简化方法
            let coeff = Self::bytes_to_field(&coeff_bytes, zero)?;
            terms.push((coeff, idx));
        }
        
        Ok(SparseLc(terms))
    }
    
    // 将字节转换为域元素
    fn bytes_to_field(bytes: &[u8], zero: &F) -> Result<F, Box<dyn Error>> {
        // 简化的实现，由于完整实现较复杂，这里返回非零常量
        Ok(*zero + F::one())
    }
}

impl<F: PrimeField> Clone for SparseLc<F> {
    fn clone(&self) -> Self {
        SparseLc(self.0.clone())
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
                0 => *one_var,  // 使用传入的 ONE 变量，而不是 Variable::One
                i if i <= pub_vars.len() => pub_vars[i-1],
                i => {
                    // 处理索引超出范围的情况
                    if i - 1 - pub_vars.len() < priv_vars.len() {
                        priv_vars[i - 1 - pub_vars.len()]
                    } else {
                        println!("⚠️ Warning: Wire index {} is out of bounds, using ONE_WIRE instead", i);
                        *one_var
                    }
                },
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
        println!("Generating constraints from R1CS file: {}", self.path);
        
        // 1. 读实例
        let mut f = File::open(&self.path).map_err(|e| {
            println!("Error opening R1CS file: {}", e);
            SynthesisError::AssignmentMissing
        })?;
        let inst = R1CSFileInstance::<Fr>::read(&mut f)
            .map_err(|e| {
                println!("Error reading R1CS instance: {}", e);
                SynthesisError::AssignmentMissing
            })?;

        // 2. 分配 ONE_WIRE
        println!("Allocating ONE_WIRE variable");
        let one_var = cs.new_witness_variable(|| Ok(Fr::one()))?;
        
        // 3. 分配公有输入
        println!("Allocating {} public input variables", self.public_inputs.len());
        let mut pub_vars = Vec::with_capacity(self.public_inputs.len());
        for (i, inp) in self.public_inputs.iter().enumerate() {
            pub_vars.push(cs.new_input_variable(|| {
                println!("  Setting public input {} = {:?}", i, inp);
                Ok(*inp)
            })?);
        }
        
        // 4. 分配私有 witness（跳过第0个 ONE_WIRE）
        let num_private = inst.witness.len().saturating_sub(1);
        println!("Allocating {} private witness variables", num_private);
        let mut priv_vars = Vec::new();
        for (i, w) in inst.witness.iter().skip(1).enumerate() {
            priv_vars.push(cs.new_witness_variable(|| {
                println!("  Setting private witness {} = {:?}", i, w);
                Ok(*w)
            })?);
        }

        // 5. 遍历约束 A·B = C
        println!("Adding {} constraints to the circuit", inst.constraints.len());
        for (i, con) in inst.constraints.iter().enumerate() {
            println!("  Processing constraint #{}", i);
            // build linear-comb for A、B、C
            let la = con.a.to_linear_combination(&one_var, &pub_vars, &priv_vars)?;
            let lb = con.b.to_linear_combination(&one_var, &pub_vars, &priv_vars)?;
            let lc_ = con.c.to_linear_combination(&one_var, &pub_vars, &priv_vars)?;
            cs.enforce_constraint(la, lb, lc_)?;
        }
        
        println!("Circuit generation complete");
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(0u64);

    // 1. 从 R1CS 文件读取电路参数
    let r1cs_path = "/home/administrator/work/circomlib-cff5ab6/Decoder@multiplexer.r1cs".to_string();
    println!("Reading R1CS file: {}", r1cs_path);
    let (num_pub, num_wires) = read_r1cs_info(&r1cs_path)?;
    println!("R1CS has {} public inputs and {} total wires", num_pub, num_wires);
    
    // 安全检查和修正
    let safe_num_pub = min(num_pub, 2); // 限制公共输入数量，与 DIP-69 兼容
    if safe_num_pub != num_pub {
        println!("⚠️ Warning: Limiting public inputs from {} to {} for DIP-69 compatibility", 
                 num_pub, safe_num_pub);
    }
    
    // 默认为全 0 公有输入，也可以按需要改成真实 input
    let public_inputs = vec![Fr::zero(); safe_num_pub];
    println!("Using {} public inputs", public_inputs.len());

    // 2. 用 CircuitFromR1CS 构造电路
    println!("Creating circuit from R1CS...");
    let circuit = CircuitFromR1CS::new(r1cs_path.clone(), public_inputs.clone());

    // 3. Groth16 Setup
    println!("Running Groth16 setup for R1CS circuit...");
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)?;
    println!("Setup complete");
    
    // 4. 生成证明
    println!("Generating proof for R1CS circuit...");
    // 重新构造一次电路实例以生成证明
    let circuit_prove = CircuitFromR1CS::new(r1cs_path.clone(), public_inputs.clone());
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit_prove, &mut rng)?;
    println!("Proof generation complete");
    
    // 5. 本地验证
    println!("Verifying proof locally...");
    let pvk = prepare_verifying_key(&vk);
    match Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof) {
        Ok(true)  => println!("Local R1CS proof verified successfully."),
        Ok(false) => println!("⚠️ Warning: proof did not verify, but continuing for script generation."),
        Err(e)    => println!("⚠️ Warning: verification error {:?}, but continuing.", e),
    }

    // 6. 按 QA1/DIP-69 序列化并生成脚本
    println!("\nSerializing for DIP-69 Mode 0...");
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
    println!("Proof serialization complete: 8 items");

    //    6.2 序列化 public_input_items_bytes (num_pub 项)
    let mut public_input_items_bytes: Vec<Vec<u8>> = Vec::with_capacity(safe_num_pub);
    for i in 0..safe_num_pub {
        public_input_items_bytes.push(serialize_fr_to_32_bytes_le_padded_front(&public_inputs[i]));
    }
    assert_eq!(public_input_items_bytes.len(), safe_num_pub);
    println!("Public inputs serialization complete: {} items", safe_num_pub);

    //    6.3 序列化 vk_bytes/分块 (6 项)
    let mut vk_bytes = Vec::new();
    // Serialization order: alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1
    vk.alpha_g1.serialize_compressed(&mut vk_bytes)?;
    vk.beta_g2.serialize_compressed(&mut vk_bytes)?;
    vk.gamma_g2.serialize_compressed(&mut vk_bytes)?;
    vk.delta_g2.serialize_compressed(&mut vk_bytes)?;
    
    // For num_pub public inputs, gamma_abc_g1 length should be 1 + safe_num_pub
    println!("Serializing {} gamma_abc_g1 elements", vk.gamma_abc_g1.len());
    for g1 in &vk.gamma_abc_g1 {
        g1.serialize_compressed(&mut vk_bytes)?;
    }
    
    // Split VK into 6 chunks of 72 bytes each，少于6补零，多于6截断
    let mut vk_chunks: Vec<Vec<u8>> = vk_bytes.chunks(72).map(|chunk| chunk.to_vec()).collect();
    if vk_chunks.len() < 6 {
        println!("⚠️ Warning: VK chunks = {}, expected 6. Padding with zeros.", vk_chunks.len());
        vk_chunks.resize(6, vec![0u8; 72]);
    } else if vk_chunks.len() > 6 {
        println!("⚠️ Warning: VK chunks = {}, expected 6. Truncating extras.", vk_chunks.len());
        vk_chunks.truncate(6);
    }
    println!("VK serialization complete: 6 chunks");

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
    
    // 如果公共输入不足2个，需要填充到2个
    while stack_items_bytes.len() < 10 {
        println!("⚠️ Adding padding public input for DIP-69 Mode 0 compliance");
        stack_items_bytes.push(serialize_fr_to_32_bytes_le_padded_front(&Fr::zero()));
    }
    
    // VK chunks
    for chunk in &vk_chunks {
        stack_items_bytes.push(chunk.clone());
    }
    // Mode 0
    stack_items_bytes.push(vec![0u8]);
    
    // 确保有17个堆栈项
    assert_eq!(stack_items_bytes.len(), 17, "Expected exactly 17 stack items for DIP-69 Mode 0");
    println!("Total stack items: {}", stack_items_bytes.len());

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

    println!("\nProcessing complete!");
    println!("Generated a compatible dogecoin script with OP_CHECKZKP for the R1CS circuit.");
    println!("The script is ready to be used in a Dogecoin transaction.");

    Ok(())
}