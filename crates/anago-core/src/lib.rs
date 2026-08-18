//! anago-core — pure-std library: protocol types, IP allocation, wg
//! config generation, join-code validation. No external crates, ever
//! (DESIGN.md §4 principle 4). The binary crate is a thin shell around
//! these pure functions.

pub mod code;
pub mod json;
pub mod name;
pub mod proto;
pub mod state;
pub mod subnet;
pub mod token;
pub mod wgconf;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_compiles() {
        assert_eq!(2 + 2, 4);
    }
}
