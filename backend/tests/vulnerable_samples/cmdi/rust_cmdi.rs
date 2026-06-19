use std::process::Command;

fn handler(req: Request) {
    let name = req.param("name");
    Command::new(name);
}
