use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .default_package_filename("protos")
        .compile_protos(
            &[
                "src/protos/steamnetworkingsockets_messages.proto",
                "src/protos/steamnetworkingsockets_messages_certs.proto",
                "src/protos/steamnetworkingsockets_messages_udp.proto",
                ],
            &["src/protos"]
        )?;
    Ok(())
}