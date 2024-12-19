use sos_platform_authenticator::local_auth;
fn main() {
    if local_auth::supported() {
        let verified = local_auth::authenticate(Default::default());
        if verified {
            println!("Authorized");
        } else {
            println!("Unauthorized");
        }
    } else {
        println!("Unsupported platform");
    }
}
