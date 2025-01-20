
use prost::Message;
use std::fs::File;
use std::io::Write;

mod hef_proto {
    tonic::include_proto!("hef_proto");
}
use hef_proto::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    /* 
    // Define the network group and its details
    let network_group = hef_proto::ProtoHefNetworkGroup {
        name: "lightface_slim".to_string(),
        context: "Single Context".to_string(),
        networks: vec![hef_proto::ProtoHefNetwork {
            name: "lightface_slim/lightface_slim".to_string(),
            vstream_infos: vec![
                hef_proto::ProtoHefVStreamInfo {
                    name: "lightface_slim/input_layer1".to_string(),
                    data_type: hef_proto::ProtoHefDataType::Uint8 as i32,
                    format: hef_proto::ProtoHefDataFormat::Nhwc as i32,
                    dimensions: Some(hef_proto::ProtoHefDimensions {
                        height: 240,
                        width: 320,
                        channels: 3,
                    }),
                },
                hef_proto::ProtoHefVStreamInfo {
                    name: "lightface_slim/conv23".to_string(),
                    data_type: hef_proto::DataType::Uint8 as i32,
                    format: hef_proto::ProtoHefDataFormat::Fcr as i32,
                    dimensions: Some(hef_proto::ProtoHefDimensions {
                        height: 30,
                        width: 40,
                        channels: 12,
                    }),
                },
                hef_proto::ProtoHefVStreamInfo {
                    name: "lightface_slim/conv22".to_string(),
                    data_type: hef_proto::ProtoHefDataType::Uint8 as i32,
                    format: hef_proto::ProtoHefDataFormat::Nhwc as i32,
                    dimensions: Some(hef_proto::ProtoHefDimensions {
                        height: 30,
                        width: 40,
                        channels: 6,
                    }),
                },
                // Add the remaining outputs similarly...
            ],
        }],
    };

    // Create the ProtoHefHef object
    let proto_hef = ProtoHefHef {
        header: Some(hef_proto::ProtoHefHeader {
            hw_arch: 8,
            timestamp: 0,
            sdk_version: "123".to_string(),
            version: 0,
        }),
        network_groups: vec![network_group],
        extensions: vec![],
        included_features: None,
        mapping: vec![],
        optional_extensions: vec![],
    };

    // Serialize the data to binary
    let mut buffer = Vec::new();
    proto_hef.encode(&mut buffer)?;

    // Write to a binary file
    let mut file = File::create("test_lightface_slim.bin")?;
    file.write_all(&buffer)?;

    println!("Binary file generated: test_lightface_slim.bin");

    */
    Ok(())
}
