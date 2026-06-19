use std::process::Command;

fn handler(req: Request) {
    let raw = req.param("count");
    let count = raw.parse::<i32>().unwrap();
    Command::new(format!("sleep {}", count));
}
