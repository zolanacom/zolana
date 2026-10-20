// Reuse the upstream CLI with this workspace's exact native program linkage.
// Its optional jemalloc feature belongs to the upstream package, not this one.
#[allow(unexpected_cfgs)]
#[path = "../../../agave/validator/src/main.rs"]
mod imported;

fn main() {
    imported::main();
}
