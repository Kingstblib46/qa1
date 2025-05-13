use std::fs::File;
use std::path::Path;
use std::io::{self, Read, Seek, SeekFrom};
use std::fmt;
use byteorder::{LittleEndian, ReadBytesExt};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;

/// Wrapper for R1CS file data with additional utility methods
pub struct R1CS {
    header: R1CSHeader,
    constraints: Vec<R1CSConstraint>,
}

/// Structure to hold R1CS header information
#[derive(Debug, Clone)]
pub struct R1CSHeader {
    pub field_size: u32,
    pub prime_bytes: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prvt_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
}

/// Represents a term in a linear combination (wire index and coefficient)
#[derive(Debug, Clone)]
pub struct Term {
    pub wire_id: u32,
    pub coefficient: Fr,
}

/// Represents an R1CS constraint in a more accessible format
#[derive(Debug, Clone)]
pub struct R1CSConstraint {
    pub a_terms: Vec<Term>,
    pub b_terms: Vec<Term>,
    pub c_terms: Vec<Term>,
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}·x{}", self.coefficient, self.wire_id)
    }
}

impl fmt::Display for R1CSConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format A terms
        let a_str = if self.a_terms.is_empty() {
            "0".to_string()
        } else {
            self.a_terms.iter()
                .map(|t| format!("{}", t))
                .collect::<Vec<_>>()
                .join(" + ")
        };

        // Format B terms
        let b_str = if self.b_terms.is_empty() {
            "0".to_string()
        } else {
            self.b_terms.iter()
                .map(|t| format!("{}", t))
                .collect::<Vec<_>>()
                .join(" + ")
        };

        // Format C terms
        let c_str = if self.c_terms.is_empty() {
            "0".to_string()
        } else {
            self.c_terms.iter()
                .map(|t| format!("{}", t))
                .collect::<Vec<_>>()
                .join(" + ")
        };

        write!(f, "({}) · ({}) = {}", a_str, b_str, c_str)
    }
}

impl R1CS {
    /// Read and parse an R1CS file using direct I/O operations
    pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        println!("Reading R1CS file from: {}", path.as_ref().display());
        
        let mut file = File::open(&path)?;
        
        // Read magic bytes "r1cs"
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        
        if &magic != b"r1cs" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid R1CS file: wrong magic bytes"
            ));
        }
        
        // Read version
        let version = file.read_u32::<LittleEndian>()?;
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported R1CS version: {}", version)
            ));
        }
        
        // Read number of sections
        let num_sections = file.read_u32::<LittleEndian>()?;
        println!("R1CS file has {} sections", num_sections);
        
        // Initialize header with default values
        let mut header = R1CSHeader {
            field_size: 0,
            prime_bytes: Vec::new(),
            n_wires: 0,
            n_pub_out: 0,
            n_pub_in: 0,
            n_prvt_in: 0,
            n_labels: 0,
            n_constraints: 0,
        };
        
        // Read sections
        let mut constraints = Vec::new();
        
        for _ in 0..num_sections {
            let section_type = file.read_u32::<LittleEndian>()?;
            let section_size = file.read_u64::<LittleEndian>()?;
            
            match section_type {
                1 => { // Header section
                    println!("Reading header section of size {} bytes", section_size);
                    header = Self::read_header_section(&mut file)?;
                }
                2 => { // Constraints section
                    println!("Reading constraints section of size {} bytes", section_size);
                    // For now, we'll just skip this section
                    let current_pos = file.seek(SeekFrom::Current(0))?;
                    file.seek(SeekFrom::Start(current_pos + section_size))?;
                }
                3 => { // Wire map section
                    println!("Skipping wire map section of size {} bytes", section_size);
                    let current_pos = file.seek(SeekFrom::Current(0))?;
                    file.seek(SeekFrom::Start(current_pos + section_size))?;
                }
                4 | 5 => { // Custom gates sections (UltraPlonk specific)
                    println!("Skipping custom gates section of size {} bytes", section_size);
                    let current_pos = file.seek(SeekFrom::Current(0))?;
                    file.seek(SeekFrom::Start(current_pos + section_size))?;
                }
                _ => {
                    println!("Skipping unknown section type {} of size {} bytes", section_type, section_size);
                    let current_pos = file.seek(SeekFrom::Current(0))?;
                    file.seek(SeekFrom::Start(current_pos + section_size))?;
                }
            }
        }
        
        println!("Successfully parsed R1CS file header");
        
        // For now, we'll return without fully parsing the constraints
        // This is enough to get the metadata we need
        Ok(Self { 
            header,
            constraints,
        })
    }
    
    fn read_header_section(file: &mut File) -> io::Result<R1CSHeader> {
        // Read field element size (in bytes)
        let field_size = file.read_u32::<LittleEndian>()?;
        println!("  Field size: {} bytes", field_size);
        
        // Read prime field modulus
        let mut prime_bytes = vec![0u8; field_size as usize];
        file.read_exact(&mut prime_bytes)?;
        
        // Read number of wires
        let n_wires = file.read_u32::<LittleEndian>()?;
        println!("  Number of wires: {}", n_wires);
        
        // Read number of public outputs
        let n_pub_out = file.read_u32::<LittleEndian>()?;
        println!("  Number of public outputs: {}", n_pub_out);
        
        // Read number of public inputs
        let n_pub_in = file.read_u32::<LittleEndian>()?;
        println!("  Number of public inputs: {}", n_pub_in);
        
        // Read number of private inputs
        let n_prvt_in = file.read_u32::<LittleEndian>()?;
        println!("  Number of private inputs: {}", n_prvt_in);
        
        // Read number of labels
        let n_labels = file.read_u64::<LittleEndian>()?;
        println!("  Number of labels: {}", n_labels);
        
        // Read number of constraints
        let n_constraints = file.read_u32::<LittleEndian>()?;
        println!("  Number of constraints: {}", n_constraints);
        
        Ok(R1CSHeader {
            field_size,
            prime_bytes,
            n_wires,
            n_pub_out,
            n_pub_in,
            n_prvt_in,
            n_labels,
            n_constraints,
        })
    }
    
    /// Get the number of wires in the circuit
    pub fn num_wires(&self) -> u32 {
        self.header.n_wires
    }
    
    /// Get the number of public outputs in the circuit
    pub fn num_public_outputs(&self) -> u32 {
        self.header.n_pub_out
    }
    
    /// Get the number of public inputs in the circuit
    pub fn num_public_inputs(&self) -> u32 {
        self.header.n_pub_in
    }
    
    /// Get the total number of public values (outputs + inputs)
    pub fn num_public_values(&self) -> u32 {
        self.header.n_pub_out + self.header.n_pub_in
    }
    
    /// Get the number of private inputs in the circuit
    pub fn num_private_inputs(&self) -> u32 {
        self.header.n_prvt_in
    }
    
    /// Get the number of constraints in the circuit
    pub fn num_constraints(&self) -> u32 {
        self.header.n_constraints
    }
    
    /// Get the prime field modulus from the R1CS file
    pub fn prime_field_modulus(&self) -> &[u8] {
        &self.header.prime_bytes
    }
    
    /// Get all constraints in the circuit, converted to our internal format
    pub fn constraints(&self) -> &Vec<R1CSConstraint> {
        &self.constraints
    }
    
    /// Print detailed information about the R1CS circuit
    pub fn print_info(&self) {
        println!("R1CS Circuit Information:");
        println!("  Total wires: {}", self.num_wires());
        println!("  Public outputs: {}", self.num_public_outputs());
        println!("  Public inputs: {}", self.num_public_inputs());
        println!("  Private inputs: {}", self.num_private_inputs());
        println!("  Constraints: {}", self.num_constraints());
        
        // Print the first few bytes of the prime field modulus
        let prime_bytes = self.prime_field_modulus();
        let display_bytes = if prime_bytes.len() > 8 { 8 } else { prime_bytes.len() };
        println!("  Prime field modulus (first {} bytes): {:?}", 
                 display_bytes, &prime_bytes[..display_bytes]);
    }
}

/// Simple A+B=C circuit for testing when no R1CS file is available
pub fn create_hardcoded_r1cs() -> io::Result<R1CS> {
    println!("Creating hardcoded R1CS for testing purposes...");
    
    // For now we'll just return an error - if needed, we can implement
    // a hardcoded simple circuit later
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Hardcoded R1CS not implemented - please provide a valid R1CS file"
    ))
}