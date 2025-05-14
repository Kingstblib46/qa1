# Circom R1CS → Dogecoin OP_CHECKZKP 转换工具

## 简介

本工具将 Circom 生成的 R1CS + WASM 电路，经过 Arkworks Groth16  
流程（setup → prove → verify），最终生成符合 Dip-69 Mode 0 的  
Dogecoin 脚本堆栈项（text / JSON / script 三种格式）。

---

## 当前支持的输入格式

1. **R1CS 文件**  
   - 必须符合 [iden3/r1csfile v1](https://github.com/iden3/r1csfile) 二进制规范；  
   - 运行时通过命令行参数指定：  
     ```bash
     cargo run -- <circuit>.r1cs [<circuit>.wasm]
     ```  
     如果省略 `<circuit>.wasm`，程序会尝试按 `<stem>_js/<stem>.wasm` 查找。  

2. **WASM 见证计算器**  
   - 位于 `<电路名>_js/<电路名>.wasm`，与 R1CS 同目录；  
   - 由 Circom `--wasm` 生成，供 `ark_circom::WitnessCalculator` 调用。  

3. **私有输入 JSON**  
   - 在源码中以 `{"signal_name": ["v1","v2",…]}` 形式硬编码；  
   - **必须**手动填写正确的信号名和值，脚本无法自动推断。  

4. **曲线和字段**  
   - 固定使用 BLS12-381 (`ark_bls12_381::Fr`)；  
   - 目前**不**支持其他曲线或域。  

---

## 输出格式

- **zkp_stack_dip69.txt**  
  每行 `index:hex`，按堆栈从顶到底（proof → pub inputs → VK chunks → mode）。  
- **zkp_stack_dip69.json**  
  纯 hex 字符串数组，同上顺序。  
- **dogecoin_script.txt**  
  生成完整的 Dogecoin 脚本（OP_PUSHDATA + OP_CHECKZKP）。  

---

## 已知限制

- **路径/命名**  
  已改为由用户在命令行指定 R1CS 和可选 WASM 路径，不再完全依赖固定目录或命名，但两者必须对应同一电路。
- **私有信号需手动配置**  
  无法从 R1CS/WASM 自动识别私有输入名称与数量。  
- **仅支持 Circom + Ark-Groth16**  
  依赖 `ark-circom` 的 witness 计算及 `generate_random_parameters_with_reduction`。  
- **只兼容 iden3 v1、BLS12-381**  
  其他 R1CS 版本／曲线需手动改造。  

---

## 使用指南

1. 编辑 `main.rs` 中的  
   ```rust
   let inputs_json_str = r#"{"<signal>": ["<value>"]}"#;