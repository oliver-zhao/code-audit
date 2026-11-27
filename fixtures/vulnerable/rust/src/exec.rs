// Shell commands built from user input.
use std::process::Command;

pub fn archive(dir: &str) -> std::io::Result<std::process::Output> {
    Command::new("sh").arg("-c").arg(format!("tar czf /tmp/out.tgz {}", dir)).output()
}

pub fn windows_list(user_path: &str) -> std::io::Result<std::process::Output> {
    let script = format!("dir {}", user_path);
    Command::new("cmd").args(["/C", &script]).output()
}

pub fn run_tool(tool: &str, input: &str) -> std::io::Result<std::process::Output> {
    Command::new(tool).arg(input).output()
}

pub fn run_script(script: &str) -> std::io::Result<std::process::Output> {
    Command::new("bash")
        .arg("-c")
        .arg(script)
        .output()
}

pub fn login_shell(cmd: &str) -> std::io::Result<std::process::Output> {
    std::process::Command::new("sh")
        .arg("-lc")
        .arg(cmd)
        .output()
}
