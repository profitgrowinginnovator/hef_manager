use std::env;

fn main() {
    println!("cargo:rerun-if-changed=proto/hef.proto");


    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");
    let proto_file = "./proto/hef.proto";

    // Debugging output
    println!("Debug: Starting code generation...");
    println!("Debug: Output directory is {}", out_dir);

    // Compile the proto file
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        // Exclude `Eq` for specific types
        .type_attribute(
            ".ProtoHefExtensionType",
            r#"#[derive(PartialEq, serde::Serialize, serde::Deserialize)]"#,
        )
        .type_attribute(
            ".ProtoHefHwArch",
            r#"#[derive(PartialEq, serde::Serialize, serde::Deserialize)]"#,
        )
        .type_attribute(
            ".ProtoHefLogitsType",
            r#"#[derive(PartialEq, serde::Serialize, serde::Deserialize)]"#,
        )
        .type_attribute(
            ".ProtoHefNmsOp",
            r#"#[derive(PartialEq, serde::Serialize, serde::Deserialize)]"#,
        )
        .type_attribute(
            ".ProtoHefEdgeLayerDirection",
            r#"#[derive(PartialEq, serde::Serialize, serde::Deserialize)]"#,
        )
        .out_dir(out_dir)
        .compile_protos(&[proto_file], &["proto"])
        .expect("Failed to compile proto files");

    // Rename the generated `_.rs` to `proto_generated.rs`
    //let generated_file = Path::new(out_dir).join("_.rs");
    //let new_file_name = Path::new(out_dir).join("hef_generated.rs");

    /*if generated_file.exists() {
        fs::rename(&generated_file, &new_file_name).expect("Failed to rename generated file");
        println!("Debug: Renamed file to proto_generated.rs");
    } else {
        println!("Warning: Expected generated file _.rs not found!");
    }*/

    println!("Debug: Code generation completed.");
}
