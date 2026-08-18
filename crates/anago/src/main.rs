//! anago CLI — dispatch skeleton. Real commands land with M0
//! (DESIGN.md §8); until then this only proves the workspace shape.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-V") | Some("--version") | Some("version") => {
            println!("anago {}", env!("CARGO_PKG_VERSION"));
        }
        _ => {
            eprintln!("anago {} — design stage; see docs/DESIGN.md", env!("CARGO_PKG_VERSION"));
            eprintln!("usage (planned): anago server init --domain <d> | anago join <domain> <code>");
        }
    }
}
