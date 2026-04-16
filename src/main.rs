use backflow::app;

fn main() {
    env_logger::init();

    if let Err(error) = app::run() {
        eprintln!("backflow failed: {error:#}");
        std::process::exit(1);
    }
}
