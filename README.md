# gnosis
A toolkit for inspecting Valve GNS traffic

## Building
You will need Rust installed to compile this code (`https://rustup.rs` is recommended.) Build the gns-proxy tool using `cargo build --release`, and then run `./target/release/gns-proxy --help` for parameters.

## Usage
Run the following command (replacing parameters with the appropriate values):
```
gns-proxy -l 0.0.0.0:2456 -r <SERVER_IP_ADDRESS>:2456 --client-steam-id <CLIENT_STEAM_ID> --server-steam-id <SERVER_STEAM_ID>
```
After the proxy is running, you should be able to point your game client to the IP address and port of your proxy machine, and it should forward game traffic to the game server at SERVER_IP_ADDRESS
