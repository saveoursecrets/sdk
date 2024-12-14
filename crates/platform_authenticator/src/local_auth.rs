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
            windows: WindowsText::new("Title", "Description").unwrap(),
        }
    }
}

/// Authenticate using the platform authenticator.
pub fn authenticate(options: AuthenticateOptions) -> bool {
    let policy: Policy = PolicyBuilder::new()
        .biometrics(Some(options.biometrics))
        .password(options.password)
        .watch(true)
        .build()
        .unwrap();

    let text: Text = Text {
        android: options.android,
        apple: options.apple,
        windows: options.windows,
    };

    let context = Context::new(());
    context.blocking_authenticate(text, &policy).is_ok()
}
