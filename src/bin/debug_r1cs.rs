use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::error::Error;
use byteorder::{LittleEndian, ReadBytesExt};

/// 打印一个域元素，尝试以多种格式解释它
fn print_field_element(buf: &[u8], indent: &str) {
    println!("{}As hex: 0x{}", indent, hex::encode(buf));
    
    // 尝试解释为小端序 u32/u64（整数）
    if buf.len() >= 4 {
        let u32_val = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        println!("{}As u32 (LE): {}", indent, u32_val);
    }
    if buf.len() >= 8 {
        let u64_val = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        println!("{}As u64 (LE): {}", indent, u64_val);
    }
    
    // 尝试解释为 ASCII
    let ascii: String = buf.iter()
        .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
        .collect();
    println!("{}As ASCII: \"{}\"", indent, ascii);
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = "/home/administrator/work/circomlib-cff5ab6/Decoder@multiplexer.r1cs";
    println!("=============== DETAILED R1CS ANALYZER ===============");
    println!("Analyzing file: {}\n", path);
    let mut f = File::open(path)?;
    let sz = f.metadata()?.len();
    println!("File size: {} bytes\n", sz);

    // === HEADER 部分 ===
    println!("┌───────────────────────────────────────────┐");
    println!("│           SECTION 1: HEADER               │");
    println!("└───────────────────────────────────────────┘");
    f.seek(SeekFrom::Start(0))?;
    let magic       = f.read_u32::<LittleEndian>()?;
    let version     = f.read_u32::<LittleEndian>()?;
    let field_size  = f.read_u32::<LittleEndian>()?;    // in 64-bit words
    let total_wires = f.read_u32::<LittleEndian>()?;
    let num_pub     = f.read_u32::<LittleEndian>()?;
    let num_priv    = f.read_u32::<LittleEndian>()?;
    let num_cons    = f.read_u32::<LittleEndian>()?;
    
    println!("Magic identifier: 0x{:08x} (\"{}\")", magic, 
             (0..4).map(|i| ((magic >> (i*8)) & 0xFF) as u8 as char).collect::<String>());
    println!("Version:         {}", version);
    println!("Field size:      {} (64-bit words)", field_size);
    println!("                 {} bytes per field element", field_size * 8);
    println!("Total wires:     {}", total_wires);
    println!("Public inputs:   {}", num_pub);
    println!("Private inputs:  {}", num_priv);
    println!("Constraints:     {}", num_cons);
    
    // 合理性检查
    println!("\n** Sanity checks:");
    if num_pub + num_priv != total_wires {
        println!("⚠️  WARNING: public({}) + private({}) != total_wires({})!", 
                 num_pub, num_priv, total_wires);
    } else {
        println!("✓ public + private = total_wires");
    }
    if field_size == 0 || field_size > 100 {
        println!("⚠️  WARNING: Unusual field_size ({}), might be incorrect!", field_size);
    }
    if num_pub > total_wires {
        println!("⚠️  WARNING: public_inputs({}) > total_wires({})!", num_pub, total_wires);
    }
    
    let coeff_len = (field_size as usize) * 8;
    
    // === 约束部分 ===
    println!("\n┌───────────────────────────────────────────┐");
    println!("│        SECTION 2: CONSTRAINTS             │");
    println!("└───────────────────────────────────────────┘");
    println!("Starting from offset: {} (0x{:x})", 7*4, 7*4);
    f.seek(SeekFrom::Start(7 * 4))?;
    
    for ci in 0..num_cons {
        println!("\n==== CONSTRAINT #{} ====", ci);
        println!("This represents: A·B = C  (dot product)");
        
        // 读取并分析 A、B、C 矩阵
        for (midx, &mat) in ["A","B","C"].iter().enumerate() {
            let terms = f.read_u32::<LittleEndian>()?;
            println!("\n-- {} Matrix: {} non-zero terms --", mat, terms);
            
            if terms > 1000 {
                println!("⚠️  WARNING: Unusually large number of terms ({}), possible parsing error", terms);
                continue;  // 跳过这部分以避免潜在的无限循环
            }
            
            for ti in 0..terms {
                let wire_idx = f.read_u32::<LittleEndian>()?;
                
                // 读取系数
                let mut coeff = vec![0u8; coeff_len];
                let read_bytes = f.read(&mut coeff)?;
                if read_bytes < coeff_len {
                    println!("⚠️  WARNING: Could only read {} of {} bytes for coefficient", read_bytes, coeff_len);
                    break;
                }
                
                // 输出详细信息
                println!("\n  Term #{}:", ti);
                println!("    Wire index: {} {}", wire_idx, 
                         if wire_idx == 0 {"(constant ONE)"} 
                         else if wire_idx <= num_pub as u32 {"(public input)"} 
                         else {"(private witness)"});
                println!("    Coefficient:");
                print_field_element(&coeff, "      ");
            }
            
            // 验证该矩阵在文件结构中的位置
            println!("\n  Current file position: {} bytes", f.stream_position()?);
        }
    }
    
    // === WITNESS 部分 ===
    println!("\n┌───────────────────────────────────────────┐");
    println!("│           SECTION 3: WITNESS              │");
    println!("└───────────────────────────────────────────┘");
    println!("Starting from offset: {} (0x{:x})", f.stream_position()?, f.stream_position()?);
    
    for wi in 0..total_wires {
        let mut buf = vec![0u8; coeff_len];
        let read_bytes = f.read(&mut buf)?;
        if read_bytes < coeff_len {
            println!("⚠️  WARNING: Could only read {} of {} bytes for witness[{}]", 
                     read_bytes, coeff_len, wi);
            break;
        }
        
        println!("\n-- Wire #{} {} --", wi, 
                 if wi == 0 {"(ONE constant)"} 
                 else if wi <= num_pub as u32 {"(public input)"} 
                 else {"(private witness)"});
        print_field_element(&buf, "  ");
    }
    
    // === 剩余数据 ===
    let pos = f.stream_position()?;
    if pos < sz {
        println!("\n┌───────────────────────────────────────────┐");
        println!("│         SECTION 4: REMAINING DATA         │");
        println!("└───────────────────────────────────────────┘");
        println!("Bytes {}-{} of {} total:", pos, sz-1, sz);
        
        let mut remaining = Vec::new();
        f.read_to_end(&mut remaining)?;
        
        // 分块显示
        for (i, chunk) in remaining.chunks(32).enumerate() {
            println!("\nBlock {}:", i);
            println!("  Hex: {}", hex::encode(chunk));
            
            // 尝试解释为 field 元素
            if chunk.len() >= 4 {
                let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                println!("  As u32 (first 4 bytes): {}", value);
            }
            
            // ASCII 表示
            let ascii: String = chunk.iter()
                .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                .collect();
            println!("  ASCII: \"{}\"", ascii);
        }
        
        // 尝试寻找可能的结构模式
        println!("\nPossible structural patterns in remaining data:");
        if remaining.len() > 8 {
            let first_u32 = u32::from_le_bytes([
                remaining[0], remaining[1], remaining[2], remaining[3]
            ]);
            println!("  First u32 value: {} (could be a count or identifier)", first_u32);
        }
    }
    
    println!("\n=============== ANALYSIS COMPLETE ===============");
    Ok(())
}