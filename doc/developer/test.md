# Test

Run tests using the default backend (does not include the CLI tests which can take a while due to launching the executable).

```
cargo make test
```

Run tests using a matrix of all supported backends.

```
cargo make test-all
```

To skip integration tests and just run unit tests:

```
cargo make unit
```

To generate a code coverage report in `target/llvm-cov/html` run:

```
cargo make cover
```

To run just the command line tests which would be included in test coverage:

```
cargo make test-command-line
```

These tests always use a debug version of the executable. Run with `ANTICIPATE_ECHO` to debug:

```
ANTICIPATE_ECHO=true cargo make test-command-line
```

## Test Scripts

Test scripts will prefer an executable in `target/debug` but it can be much faster to run tests using a release build installed with `cargo install --path crates/sos`.

To run all the CLI test specs (including for the `shell` command) using the version of `sos` in `target/debug`:

```
cargo make test-cli
```

Or to just test the shell command:

```
cargo make test-shell
```

The shell tests complete much faster as they don't need to launch an executable for each command.

If you need to debug the CLI tests enable echo to see the I/O, for example:

```
ANTICIPATE_ECHO=true cargo make test-cli
ANTICIPATE_ECHO=true cargo make test-shell
```

Use the `SPEC` variable to debug a specific test:

```
cargo make clean-cli && SPEC=tests/command_line/scripts/secret/add-note.sh ANTICIPATE_ECHO=true ./scripts/cli/specs.sh
```

This will run the test setup beforehand and the teardown afterwards so the test account data will exist.

## Notes

### MacOS ulimit

If you are running on MacOS and see the "too many open files" error running the tests then you will need to configure the limits.

Update your shell's ulimit by modifying the profile (eg: `~/.zshrc`):

```
ulimit -n 2048
```

And update the maxfiles limit `launchctl limit maxfiles`.

To temporarily change the maxfiles limit:

```
sudo launchctl limit maxfiles 64000 524288
```

Or to permanently change the limit create the file `/Library/LaunchDaemons/limit.maxfiles.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"> 
  <dict>
    <key>Label</key>
    <string>limit.maxfiles</string>
    <key>ProgramArguments</key>
    <array>
      <string>launchctl</string>
      <string>limit</string>
      <string>maxfiles</string>
      <string>64000</string>
      <string>524288</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ServiceIPC</key>
    <false/>
  </dict>
</plist>
```

Then run:

```
sudo chmod 600 /Library/LaunchDaemons/limit.maxfiles.plist
sudo chown root /Library/LaunchDaemons/limit.maxfiles.plist
sudo launchctl load -w /Library/LaunchDaemons/limit.maxfiles.plist
```
