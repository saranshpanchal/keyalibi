fn main() {
    let code = match keyalibi::cli::entry() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("keyalibi: {err}");
            1
        }
    };
    std::process::exit(code);
}
