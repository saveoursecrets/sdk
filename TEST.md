# Test

Run all the tests.

```
cargo make test
```

The CLI test specs can take a long time with the debug build so if you want to skip them use:

```
cargo make test-lite
```

To just test the CLI run:

```
cargo make test-cli
```

Or to just test the shell command:

```
cargo make test-shell
```

If you need to debug the CLI tests enable echo to see the I/O, for example:

```
ANTICIPATE_ECHO=true cargo make test-cli
ANTICIPATE_ECHO=true cargo make test-shell
```

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
