// Programs run directly with separate arguments.
use std::process::Command;

pub fn archive(dir: &str) -> std::io::Result<std::process::Output> {
    Command::new("tar").arg("czf").arg("/tmp/out.tgz").arg(dir).output()
}

pub fn windows_list(user_path: &str) -> std::io::Result<std::process::Output> {
    Command::new("where.exe").args(["/R", user_path, "*"]).output()
}

pub fn version() -> std::io::Result<std::process::Output> {
    Command::new("git").args(["-c", "core.pager=cat", "log"]).output()
}
