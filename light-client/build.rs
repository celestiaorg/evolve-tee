use sp1_build::build_program_with_args;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_program_with_args("../circuit", Default::default());
    Ok(())
}
