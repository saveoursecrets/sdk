use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../browser/dist"]
pub struct Assets;
