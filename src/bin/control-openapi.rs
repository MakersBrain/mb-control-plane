fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        None => println!(
            "{}",
            serde_json::to_string_pretty(&mb_control_plane::openapi::document())?
        ),
        Some("--typescript") => {
            let path = arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("--typescript requires an output path"))?;
            if arguments.next().is_some() {
                anyhow::bail!("unexpected control-openapi argument");
            }
            let target = std::path::Path::new(&path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(target, mb_control_plane::openapi::typescript_client())?;
        }
        Some("--json") => {
            let path = arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("--json requires an output path"))?;
            if arguments.next().is_some() {
                anyhow::bail!("unexpected control-openapi argument");
            }
            std::fs::write(
                path,
                serde_json::to_vec_pretty(&mb_control_plane::openapi::document())?,
            )?;
        }
        Some(argument) => anyhow::bail!("unknown control-openapi argument {argument}"),
    }
    Ok(())
}
