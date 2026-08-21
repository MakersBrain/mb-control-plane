fn main() {
    // sqlx embeds migrations in the binaries; invalidate cached Cargo builds
    // whenever that embedded directory changes.
    println!("cargo:rerun-if-changed=migrations");
}
