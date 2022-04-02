use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "./public"]
pub struct Assets;
