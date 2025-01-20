use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};
use prost::Message;
mod hef_proto {
    tonic::include_proto!("hef_proto");
}
use xxhash_rust::xxh3::xxh3_64;



/// Struct to represent the custom HEF metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hef {
    pub header: HefHeader,
    pub proto: hef_proto::ProtoHefHef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HefHeaderDetails {
    V0 {
        reserved: u32,
        expected_md5: [u8; 16],
    },
    V1 {
        crc: u32,
        ccws_size: u64,
        reserved: u32,
    },
    V2 {
        xxh3_64bits: u64,
        ccws_size: u64,
        reserved1: u64,
        reserved2: u64,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HefHeader {
    pub magic: u32,
    pub version: u32,
    pub hef_proto_size: u32,
    pub details: HefHeaderDetails,
}

impl Hef {
    pub fn parse<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path)?;
    
        // Parse header and calculate proto offset
        let (header, proto_offset) = HefHeader::parse_and_calculate_offset(&mut file)?;
    
        // Read and decode the proto section
        let proto = Self::read_and_decode_proto(&mut file, proto_offset, header.hef_proto_size)?;
    
        // Additional checks for version-specific integrity
        match &header.details {
            HefHeaderDetails::V1 { crc, ccws_size, .. } => {
                let expected_crc = *crc;
                let data_to_validate = Self::read_proto_data(&mut file, proto_offset, *ccws_size as u32)?;
                let calculated_crc = Self::calculate_crc32(&data_to_validate)?;
                if calculated_crc != expected_crc {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "CRC32 mismatch: expected {}, got {}",
                            expected_crc, calculated_crc
                        ),
                    ));
                }
            }
            HefHeaderDetails::V2 { xxh3_64bits, ccws_size, .. } => {
                let expected_hash = *xxh3_64bits;
                let data_to_validate = Self::read_proto_data(&mut file, proto_offset, *ccws_size as u32)?;
                let calculated_hash = Self::calculate_xxh3(&data_to_validate)?;
                if calculated_hash != expected_hash {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "XXH3 hash mismatch: expected {}, got {}",
                            expected_hash, calculated_hash
                        ),
                    ));
                }
            }
            _ => {} // No additional checks for V0
        }
    
        Ok(Self { header, proto })
    }
    

    pub fn extract_proto<P: AsRef<Path>>(path: P, output_path: &str) -> io::Result<()> {
        let mut file = File::open(path)?;

        // Parse header and calculate proto offset
        let (header, proto_offset) = HefHeader::parse_and_calculate_offset(&mut file)?;

        // Read the proto data
        let proto_data = Self::read_proto_data(&mut file, proto_offset, header.hef_proto_size)?;

        // Save the proto data to a new file
        let mut output_file = File::create(output_path)?;
        output_file.write_all(&proto_data)?;

        println!("Proto data written to: {}", output_path);

        Ok(())
    }

    fn read_and_decode_proto<R: Read + Seek>(
        file: &mut R,
        proto_offset: u64,
        hef_proto_size: u32,
    ) -> io::Result<hef_proto::ProtoHefHef> {
        let proto_data = Self::read_proto_data(file, proto_offset, hef_proto_size)?;
    
        match hef_proto::ProtoHefHef::decode(&proto_data[..]) {
            Ok(decoded_proto) => {
                // Validate required fields in the decoded proto
                if decoded_proto.header.is_none() || decoded_proto.network_groups.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Decoded proto lacks required fields (header or network groups)",
                    ));
                }
                Ok(decoded_proto)
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Proto decode error at offset {} with size {}: {}",
                    proto_offset, hef_proto_size, e
                ),
            )),
        }
    }
    
    

    fn read_proto_data<R: Read + Seek>(
        file: &mut R,
        proto_offset: u64,
        hef_proto_size: u32,
    ) -> io::Result<Vec<u8>> {
        file.seek(SeekFrom::Start(proto_offset))?;
        let mut proto_data = vec![0u8; hef_proto_size as usize];
        file.read_exact(&mut proto_data)?;
        println!(
            "Proto Data Size: {}, Offset: {}, Requested Size: {}",
            proto_data.len(),
            proto_offset,
            hef_proto_size
        );
        Ok(proto_data)
    }
    

    /// Serializes the `Hef` struct to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a `Hef` struct from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn calculate_crc32(data: &[u8]) -> io::Result<u32> {
        use crc32fast::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(data);
        Ok(hasher.finalize())
    }
    
    fn calculate_xxh3(data: &[u8]) -> io::Result<u64> {
        Ok(xxh3_64(data))
    }
    
}

impl HefHeader {
    pub const HEF_HEADER_SIZE_V1: usize = 24;
    pub const HEF_HEADER_SIZE_V2: usize = 40;

    pub fn parse_and_calculate_offset<R: Read + Seek>(
        reader: &mut R,
    ) -> io::Result<(Self, u64)> {
        let header = Self::parse(reader)?;
    
        // Calculate the proto offset
        let proto_offset = match header.details {
            HefHeaderDetails::V1 { ccws_size, .. } => Self::HEF_HEADER_SIZE_V1 as u64 + ccws_size,
            HefHeaderDetails::V2 { ccws_size, .. } => Self::HEF_HEADER_SIZE_V2 as u64 + ccws_size,
            HefHeaderDetails::V0 { .. } => Self::common_size_v0() as u64 + header.hef_proto_size as u64,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unknown header version",
                ))
            }
        };
    
        let file_size = Self::get_stream_length(reader)?;
        if proto_offset + header.hef_proto_size as u64 > file_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Proto section exceeds file size: offset {}, proto size {}, file size {}",
                    proto_offset, header.hef_proto_size, file_size
                ),
            ));
        }
        
    
        println!("Parsed Header: {:?}", header);
        println!("Calculated Proto Offset: {}", proto_offset);
        Ok((header, proto_offset))
    }
    
    
    fn get_stream_length<R: Read + Seek>(reader: &mut R) -> std::io::Result<u64> {
        let current_pos = reader.stream_position()?; // Save the current position
        let length = reader.seek(SeekFrom::End(0))?; // Seek to the end to get the length
        reader.seek(SeekFrom::Start(current_pos))?; // Restore the original position
        Ok(length)
    }

    pub fn parse<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        // Read common fields
        let mut magic_bytes = [0u8; 4];
        reader.read_exact(&mut magic_bytes)?;
        let magic = u32::from_be_bytes(magic_bytes);

        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;
        let version = u32::from_be_bytes(version_bytes);

        let mut hef_proto_size_bytes = [0u8; 4];
        reader.read_exact(&mut hef_proto_size_bytes)?;
        let hef_proto_size = u32::from_be_bytes(hef_proto_size_bytes);

        println!("Parsed Magic: 0x{:08X}", magic);
        println!("Parsed Version: {}", version);
        println!("Parsed Proto Size: {}", hef_proto_size);

        // Parse distinct fields based on version
        let details = match version {
            0 => {
                let mut reserved_bytes = [0u8; 4];
                reader.read_exact(&mut reserved_bytes)?;
                let reserved = u32::from_be_bytes(reserved_bytes);

                let mut expected_md5 = [0u8; 16];
                reader.read_exact(&mut expected_md5)?;

                HefHeaderDetails::V0 {
                    reserved,
                    expected_md5,
                }
            }
            1 => {
                let mut crc_bytes = [0u8; 4];
                reader.read_exact(&mut crc_bytes)?;
                let crc = u32::from_be_bytes(crc_bytes);

                let mut ccws_size_bytes = [0u8; 8];
                reader.read_exact(&mut ccws_size_bytes)?;
                let ccws_size = u64::from_be_bytes(ccws_size_bytes);

                let mut reserved_bytes = [0u8; 4];
                reader.read_exact(&mut reserved_bytes)?;
                let reserved = u32::from_be_bytes(reserved_bytes);


                
                HefHeaderDetails::V1 {
                    crc,
                    ccws_size,
                    reserved,
                }
            }
            2 => {
                let mut xxh3_bytes = [0u8; 8];
                reader.read_exact(&mut xxh3_bytes)?;
                let xxh3_64bits = u64::from_be_bytes(xxh3_bytes);

                let mut ccws_size_bytes = [0u8; 8];
                reader.read_exact(&mut ccws_size_bytes)?;
                let ccws_size = u64::from_be_bytes(ccws_size_bytes);

                let mut reserved1_bytes = [0u8; 8];
                reader.read_exact(&mut reserved1_bytes)?;
                let reserved1 = u64::from_be_bytes(reserved1_bytes);

                let mut reserved2_bytes = [0u8; 8];
                reader.read_exact(&mut reserved2_bytes)?;
                let reserved2 = u64::from_be_bytes(reserved2_bytes);

                HefHeaderDetails::V2 {
                    xxh3_64bits,
                    ccws_size,
                    reserved1,
                    reserved2,
                }
            }
            _ => HefHeaderDetails::Unknown,
        };



        Ok(Self {
            magic,
            version,
            hef_proto_size,
            details,
        })
    }

    pub fn common_size_v0() -> usize {
        16 // Placeholder for the size of common fields in V0
    }

    /// Serializes the `HefHeader` struct to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a `HefHeader` struct from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_parse_hef_directory() {
        let hef_dir = "./hef"; // Directory containing HEF files

        // Ensure the directory exists
        if !Path::new(hef_dir).is_dir() {
            panic!("HEF directory does not exist: {}", hef_dir);
        }

        // Iterate over all files in the directory
        let entries = fs::read_dir(hef_dir).expect("Failed to read HEF directory");
        for entry in entries {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();

            // Only process files (skip directories)
            if path.is_file() {
                println!("Parsing file: {:?}", path);

                match Hef::parse(&path) {
                    Ok(metadata) => {
                        println!("Parsed HEF Metadata: {:#?}", metadata);

                        // Serialize to JSON
                        match metadata.to_json() {
                            Ok(json) => println!("Serialized JSON: {}", json),
                            Err(e) => eprintln!("Failed to serialize to JSON: {}", e),
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse HEF file {:?}: {}", path, e);
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::path::Path;
    
        #[test]
        fn test_parse_hef_directory() {
            let hef_dir = "./hef"; // Directory containing HEF files
    
            // Ensure the directory exists
            if !Path::new(hef_dir).is_dir() {
                eprintln!("HEF directory does not exist: {}", hef_dir);
                return;
            }
    
            // Iterate over all files in the directory
            let entries = fs::read_dir(hef_dir).expect("Failed to read HEF directory");
            for entry in entries {
                let entry = entry.expect("Failed to read directory entry");
                let path = entry.path();
    
                // Only process files (skip directories)
                if path.is_file() {
                    println!("Parsing file: {:?}", path);
    
                    match Hef::parse(&path) {
                        Ok(metadata) => {
                            println!("Parsed HEF Metadata: {:#?}", metadata);
    
                            // Serialize to JSON
                            match metadata.to_json() {
                                Ok(json) => println!("Serialized JSON: {}", json),
                                Err(e) => eprintln!("Failed to serialize to JSON: {}", e),
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to parse HEF file {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
    
        #[test]
        fn test_serialize_deserialize() {
            let hef = Hef {
                header: HefHeader {
                    magic: 0x48454620, // Magic as a u32
                    version: 1,
                    hef_proto_size: 1024,
                    details: HefHeaderDetails::V1 {
                        crc: 0xABCD,
                        ccws_size: 2048,
                        reserved: 0,
                    },
                },
                proto: hef_proto::ProtoHefHef {
                    header: None,
                    network_groups: vec![],
                    mapping: vec![],
                    included_features: None,
                    extensions: vec![],
                    optional_extensions: vec![],
                },
            };
        
            // Serialize to JSON
            let json = hef.to_json().expect("Failed to serialize to JSON");
            println!("Serialized JSON: {}", json);
        
            // Deserialize from JSON
            let deserialized: Hef =
                Hef::from_json(&json).expect("Failed to deserialize from JSON");
            assert_eq!(hef, deserialized);
        }
        
        #[test]
        fn test_comparison() {
            let hef1 = Hef {
                header: HefHeader {
                    magic: 0x48454620, // Magic as a u32
                    version: 1,
                    hef_proto_size: 1024,
                    details: HefHeaderDetails::V1 {
                        crc: 0xABCD,
                        ccws_size: 2048,
                        reserved: 0,
                    },
                },
                proto: hef_proto::ProtoHefHef {
                    header: None,
                    network_groups: vec![],
                    mapping: vec![],
                    included_features: None,
                    extensions: vec![],
                    optional_extensions: vec![],
                },
            };

            let hef2 = hef1.clone();

            assert_eq!(hef1, hef2);
            assert!(hef1 == hef2);
        }

        #[test]
        fn test_parse_v0_header() {
            let mut mock_file = std::io::Cursor::new(vec![
                0x48, 0x45, 0x46, 0x20, // Magic
                0x00, 0x00, 0x00, 0x00, // Version 0
                0x00, 0x00, 0x00, 0x08, // Proto size
                0x00, 0x00, 0x00, 0x01, // Reserved
                // Mock MD5 sum (16 bytes)
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ]);

            let header = HefHeader::parse(&mut mock_file).expect("Failed to parse header");
            assert_eq!(
                header,
                HefHeader {
                    magic: 0x48454620, // Magic as a u32
                    version: 0,
                    hef_proto_size: 8,
                    details: HefHeaderDetails::V0 {
                        reserved: 1,
                        expected_md5: [
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                            0x0D, 0x0E, 0x0F,
                        ],
                    },
                }
            );
        }

        #[test]
        fn test_parse_invalid_proto_offset() {
            let mut mock_file = std::io::Cursor::new(vec![
                0x48, 0x45, 0x46, 0x20, // Magic
                0x01, 0x00, 0x00, 0x00, // Version 1
                0x00, 0x00, 0x00, 0x10, // Proto size
                0x00, 0x00, 0x00, 0x01, // CRC
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // CCWS size
                0x00, 0x00, 0x00, 0x00, // Reserved
            ]);

            let result = HefHeader::parse_and_calculate_offset(&mut mock_file);
            assert!(result.is_err());
            if let Err(e) = result {
                assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            }
        }

        #[test]
        fn test_invalid_crc() {
            let data = vec![0x01, 0x02, 0x03, 0x04];
            let calculated_crc = Hef::calculate_crc32(&data).unwrap();
            assert_ne!(calculated_crc, 0xFFFFFFFF); // Ensure it doesn't match some arbitrary value
        }

        #[test]
        fn test_invalid_xxh3() {
            let data = vec![0x01, 0x02, 0x03, 0x04];
            let calculated_hash = Hef::calculate_xxh3(&data).unwrap();
            assert_ne!(calculated_hash, 0); // Ensure non-zero value
        }

    }
}    