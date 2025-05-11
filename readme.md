# Circom R1CS 到 Dogecoin OP_CHECKZKP 转换工具

## 功能概述

本工具实现了将 Circom 生成的 R1CS（Rank-1 Constraint System）文件转换为符合 Dogecoin QA1/DIP-69 规范的 OP_CHECKZKP 验证脚本的完整流程。主要功能包括：

1. 读取 R1CS 电路文件
2. 基于电路生成 Groth16 零知识证明
3. 按 DIP-69 Mode 0 规范序列化证明、公共输入和验证密钥
4. 生成可直接用于 Dogecoin 交易的 scriptPubKey

## 实现原理

### 1. R1CS 电路解析

工具通过 `read_r1cs_info` 函数读取 R1CS 文件的头部信息，提取电路的关键参数：
- 公共输入数量（`num_pub`）
- 变量/约束数量（`num_vars`）

```rust
fn read_r1cs_info(_path: &str) -> Result<(usize, usize), Box<dyn Error>> {
    // 当前为 stub 版本，待实现真正的 R1CS header 解析
    Ok((2, 4))  // 返回 2 个公共输入，4 个变量
}
```

### 2. Groth16 证明生成

基于 R1CS 信息构建 `CircuitFromR1CS` 实例，该实例实现了 `ConstraintSynthesizer` trait：
- 创建包含公共输入和私有变量的电路
- 分配变量并添加必要约束
- 使用 Arkworks 库生成和验证 Groth16 证明

```rust
// 生成证明
let circuit = CircuitFromR1CS::new(num_pub, num_vars);
let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)?;
let proof = Groth16::<Bls12_381>::prove(&pk, circuit_prove, &mut rng)?;
```

### 3. DIP-69 Mode 0 序列化

按照严格的 DIP-69 Mode 0 规范序列化 17 个堆栈项：

```
堆栈项顺序（自顶向下）：
1. πA_x, πA_y      (2项，G1点)
2. πB_x0, πB_x1, πB_y0, πB_y1 (4项，G2点)
3. πC_x, πC_y      (2项，G1点)
4. 公共输入        (num_pub项，当前实现中为2项)
5. VK分块          (6项，各72字节)
6. Mode 0          (1项)
```

每一项都按特定格式进行压缩和序列化：
- G1/G2 点坐标使用 48 字节压缩格式
- 域元素使用 32 字节小端格式（前置填充）
- 验证密钥分为 6 个均等大小的块

### 4. Dogecoin 脚本生成

基于序列化的堆栈项生成符合 Dogecoin 规范的脚本字节序列：
- 根据数据长度选择正确的 push 操作码（直接推送、OP_PUSHDATA1、OP_PUSHDATA2）
- 最后追加 OP_CHECKZKP (0xb9) 操作码

```rust
// 示例：生成 push 指令
match item_len {
    1 if item_bytes[0] == 0 => script_buf.push(0x00), // OP_0
    1..=75 => {
        script_buf.push(item_len as u8);
        script_buf.extend_from_slice(item_bytes);
    },
    // 处理更长的数据...
}
// 最后加上 OP_CHECKZKP
script_buf.push(0xb9);
```

## 输出文件

工具生成三个关键输出文件：

1. **zkp_stack_dip69.txt**：文本格式的堆栈项，每行为 "index:hex_string"
2. **zkp_stack_dip69.json**：JSON 格式的堆栈项数组
3. **dogecoin_script.txt**：最终可用于 Dogecoin 交易的完整脚本（十六进制格式）

## 使用方式

1. 确保已安装 Rust 环境
2. 配置 R1CS 文件路径：
   ```rust
   let r1cs_path = "/path/to/your/circuit.r1cs";
   ```
3. 运行程序：
   ```bash
   cargo run --bin dogecoin_zkp_generator_qa1
   ```
4. 获取生成的 `dogecoin_script.txt` 并用于构建 Dogecoin 交易

## Known Issues

- **R1CS Header Parsing Stub**  
  当前 `read_r1cs_info`/`R1CSFileHeader::read` 实现仅作调试演示，可能导致  
  - `num_public` > `num_witness`  
  - 非法或矛盾的头部信息直接报错  

- **不完整的稀疏矩阵解析**  
  - 目前 `read_sparse_lc` 仅简单读取固定 32 字节并返回常量域元素。  
  - 真正的 BLS12-381 字节→域元素转换未实现。  

- **约束 B·C Stub**  
  为避免越界，`R1CSFileInstance::read` 只读取 A，B/C 被硬编码为恒等约束 (`A·1 = A`)。  
  完整解析 B 和 C 逻辑尚未完成。  

- **动态 Wire 大小 Hack**  
  当前根据约束中出现的最大 wire index 动态分配 `witness` 数组，  
  替代了原始 header 提供的 `total_wires`，这是一种临时兼容方案。  

- **缺失真实 Witness**  
  `R1CSFileInstance::read` 返回的 `witness` 全部置零，未从实际文件或外部输入加载。  

## Roadmap

- 完整实现 R1CS 文件头部和约束块的解析  
- 正确将 coefficient bytes 转换为 BLS12-381 域元素  
- 支持读取和注入真实的 witness 值  
- 移除所有临时 stub，恢复标准 `A·B=C` 解析  
- 增加单元测试以覆盖各部分逻辑  