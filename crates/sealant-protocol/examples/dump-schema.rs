//! Emit the protocol JSON Schema bundle to stdout for TypeScript type generation.
//!
//! Run with: `cargo run -p sealant-protocol --example dump-schema`

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = sealant_protocol::json_schema();
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
}
