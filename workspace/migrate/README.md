## Keychain Access Tests

The keychain access tests are behind a feature flag and require a keychain database in the standard location.

Copy the mock keychain database from the `fixtures` directory to `~/Library/Keychains`, the password is `mock-password`.

Then you can run the interactive tests for keychain access with:

```
cargo test --all-features
```
