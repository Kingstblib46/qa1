use std::fs::File;
use std::path::Path;
use std::io::{self, Read, Seek, SeekFrom};
use std::fmt;
use byteorder::{LittleEndian, ReadBytesExt};
use ark_bls12_381::Fr;
use ark_ff::{PrimeField, Zero};
use ark_serialize::SerializationError;

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
        
        // Store section positions to handle out-of-order sections
        struct SectionInfo {
            section_type: u32,
            position: u64,
            size: u64,
        }
        
        let mut sections = Vec::with_capacity(num_sections as usize);
        
        // First pass: collect information about all sections
        for _ in 0..num_sections {
            let section_type = file.read_u32::<LittleEndian>()?;
            let section_size = file.read_u64::<LittleEndian>()?;
            let section_pos = file.seek(SeekFrom::Current(0))?;
            
            sections.push(SectionInfo {
                section_type,
                position: section_pos,
                size: section_size,
            });
            
            // Skip to next section
            file.seek(SeekFrom::Start(section_pos + section_size))?;
        }
        
        // Look for the header section first
        let mut header = None;
        
        for section in &sections {
            if section.section_type == 1 {
                file.seek(SeekFrom::Start(section.position))?;
                println!("Reading header section of size {} bytes", section.size);
                header = Some(Self::read_header_section(&mut file)?);
                break;
            }
        }
        
        let header = match header {
            Some(h) => h,
            None => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "R1CS file is missing header section"
            )),
        };
        
        // Now look for constraints section
        let mut constraints = Vec::new();
        
        for section in &sections {
            if section.section_type == 2 {
                file.seek(SeekFrom::Start(section.position))?;
                println!("Reading constraints section of size {} bytes", section.size);
                constraints = Self::read_constraint_section(&mut file, &header)?;
                break;
            }
        }
        
        if constraints.is_empty() && header.n_constraints > 0 {
            println!("Warning: Failed to read any constraints despite header indicating {} constraints", 
                     header.n_constraints);
        }
        
        println!("Successfully parsed R1CS file with {} constraints", constraints.len());
        
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
        let _n_labels = file.read_u64::<LittleEndian>()?; // Read but ignore if not used
        
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
            n_constraints,
        })
    }
    
    fn read_constraint_section(file: &mut File, header: &R1CSHeader) -> io::Result<Vec<R1CSConstraint>> {
        let mut constraints = Vec::with_capacity(header.n_constraints as usize);
        
        for i in 0..header.n_constraints {
            // Read A terms
            let a_terms = Self::read_linear_combination(file, header.field_size)?;
            
            // Read B terms
            let b_terms = Self::read_linear_combination(file, header.field_size)?;
            
            // Read C terms
            let c_terms = Self::read_linear_combination(file, header.field_size)?;
            
            // Capture the lengths before moving the constraint
            let a_len = a_terms.len();
            let b_len = b_terms.len();
            let c_len = c_terms.len();
            
            let constraint = R1CSConstraint { a_terms, b_terms, c_terms };
            constraints.push(constraint);
            
            if i < 3 || i == header.n_constraints - 1 {
                println!("  Read constraint #{}: {} A terms, {} B terms, {} C terms", 
                         i, a_len, b_len, c_len);
            } else if i == 3 {
                println!("  ... and {} more constraints", header.n_constraints - 4);
            }
        }
        
        Ok(constraints)
    }
    
    fn read_linear_combination(file: &mut File, field_size: u32) -> io::Result<Vec<Term>> {
        // Read number of terms in this linear combination
        let term_count = file.read_u32::<LittleEndian>()?;
        let mut terms = Vec::with_capacity(term_count as usize);
        
        for _ in 0..term_count {
            // Read wire ID
            let wire_id = file.read_u32::<LittleEndian>()?;
            
            // Read coefficient as a field element
            let mut coef_bytes = vec![0u8; field_size as usize];
            file.read_exact(&mut coef_bytes)?;
            
            // Convert to Fr element
            // Note: The bytes in R1CS files are in little-endian order
            let coefficient = match Self::deserialize_fr(&coef_bytes) {
                Ok(fr) => fr,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize field element: {:?}", e)
                    ));
                }
            };
            
            terms.push(Term { wire_id, coefficient });
        }
        
        Ok(terms)
    }
    
    // Helper to deserialize Fr elements from R1CS format
    fn deserialize_fr(bytes: &[u8]) -> Result<Fr, SerializationError> {
        // The R1CS file uses little-endian encoding with possible leading/trailing zeros
        // We need to handle this carefully when deserializing to Fr
        
        // Create a smaller buffer with meaningful bytes only
        let mut meaningful_bytes = Vec::new();
        let mut started = false;
        
        // Process in reverse (from most significant to least)
        for &byte in bytes.iter().rev() {
            if byte != 0 || started {
                started = true;
                meaningful_bytes.push(byte);
            }
        }
        
        // If all bytes were zero
        if meaningful_bytes.is_empty() {
            return Ok(Fr::zero());
        }
        
        // Reverse back to little-endian for Fr deserialization
        meaningful_bytes.reverse();
        
        // Using from_bytes_le for Fr elements
        Ok(Fr::from_le_bytes_mod_order(&meaningful_bytes))
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
        println!("  Constraints loaded: {}", self.constraints.len());
        
        // Print the first few bytes of the prime field modulus
        let prime_bytes = self.prime_field_modulus();
        let display_bytes = if prime_bytes.len() > 8 { 8 } else { prime_bytes.len() };
        println!("  Prime field modulus (first {} bytes): {:?}", 
                 display_bytes, &prime_bytes[..display_bytes]);
        
        // Print a few sample constraints if available
        if !self.constraints.is_empty() {
            println!("\nSample constraints:");
            for (i, constraint) in self.constraints.iter().enumerate().take(3) {
                println!("  Constraint #{}: {}", i, constraint);
            }
            if self.constraints.len() > 3 {
                println!("  ... and {} more constraints", self.constraints.len() - 3);
            }
        }
    }
}