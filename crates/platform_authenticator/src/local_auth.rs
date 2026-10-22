//! Interface to the platform authenticator.

#[cfg(not(target_os = "linux"))]
mod supported {
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, Policy, PolicyBuilder, Text,
        WindowsText,
    };

    /// Options for platform authentication.
    pub struct AuthenticateOptions {
        /// Biometrics strength.
        pub biometrics: BiometricStrength,
        /// Password fallback.
        pub password: bool,
        /// Text for android.
        pub android: AndroidText<'static, 'static, 'static>,
        /// Text for apple.
        pub apple: &'static str,
        /// Text for windows.
        pub windows: WindowsText<'static, 'static>,
    }

    impl Default for AuthenticateOptions {
        fn default() -> Self {
            Self {
                biometrics: BiometricStrength::Strong,
                password: true,
                android: AndroidText {
                    title: "Authenticate",
                    subtitle: None,
                    description: None,
                },
                apple: "authenticate",
                windows: WindowsText::new(
                    "Save Our Secrets",
                    "Verify your identity to authenticate",
                )
                .unwrap(),
            }
        }
    }

    /// Authenticate using the platform authenticator.
    pub fn authenticate(options: AuthenticateOptions) -> bool {
        let policy: Policy = PolicyBuilder::new()
            .biometrics(Some(options.biometrics))
            .password(options.password)
            .companion(true)
            .build()
            .unwrap();

        let text: Text = Text {
            android: options.android,
            apple: options.apple,
            windows: options.windows,
        };

        // 0.3 reports the result through a callback, and on Apple,
        // Windows, and Android that callback runs after this call
        // returns. Block until it fires so callers still get a bool.
        let (tx, rx) = std::sync::mpsc::channel();
        let context = Context::new(());
        if context
            .authenticate(text, &policy, move |result| {
                let _ = tx.send(result.is_ok());
            })
            .is_err()
        {
            return false;
        }
        rx.recv().unwrap_or(false)
    }

    /// Determine if local platform authentication is supported.
    pub fn supported() -> bool {
        true
    }
}
#[cfg(not(target_os = "linux"))]
pub use supported::*;

#[cfg(target_os = "linux")]
mod unsupported {
    /// Options for platform authentication.
    #[derive(Default)]
    pub struct AuthenticateOptions {}

    /// Authenticate using the platform authenticator.
    pub fn authenticate(_options: AuthenticateOptions) -> bool {
        false
    }

    /// Determine if local platform authentication is supported.
    pub fn supported() -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
pub use unsupported::*;
