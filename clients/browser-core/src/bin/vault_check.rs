//! Network-free disposable creation/recovery reference. No user input accepted.
fn main() {
    if std::env::args_os().count() != 1 {
        eprintln!("the disposable vault checker accepts no arguments");
        std::process::exit(1);
    }
    match browser_core::vault::acceptance_json() {
        Ok(report) => println!("{report}"),
        Err(_) => {
            eprintln!("disposable vault creation/recovery verification failed");
            std::process::exit(1);
        }
    }
}
