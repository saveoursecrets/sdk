## Keychain Access

Copy the `sos-mock.keychain-db` keychain database from the `fixtures` directory to `~/Library/Keychains`, the password is `mock-password`.

### Keychain Dump

To create a dump of a keychain run:

```
security dump-keychain ~/Library/Keychains/sos-mock.keychain-db
```

If you include the `-d` option you will be prompted to enter the password for each secret so that the dump includes the secret data:

```
security dump-keychain -d ~/Library/Keychains/sos-mock.keychain-db
```

To update the standard fixtures for the parser just redirect the output:

```
security dump-keychain ~/Library/Keychains/sos-mock.keychain-db > fixtures/sos-mock.keychain-db.txt
```

### Interactive Autofill Tests

The interactive keychain access tests are behind a feature flag and require a keychain database in the standard location (see above).

Then you can run the interactive tests for keychain access with:

```
cargo test --features=interactive-keychain-tests
```

This will attempt to run some applescript to automatically fill the password prompt to access the keychain; you will need to allow your terminal application to execute the script, you should be prompted to allow this.

Navigate to `System Preferences > Security & Privacy > Privacy > Accessibility` and allow access for your terminal program to execute the Applescript in order to autofill the keychain access prompt(s).
