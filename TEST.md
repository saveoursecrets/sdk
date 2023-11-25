# Test

Generate a test keypair.

```
cargo make gen-test-key
```

Run the unit tests.

```
cargo make unit
```

Run the integration tests.

```
cargo make integration
```

## Notes

### Command Line Tests

The command line tests wait for very specific output in order to complete, inadvertently having a rogue `println!` in the code will cause the command line tests to fail.

### MacOS ulimit

If you are running on MacOS and see the "too many open files" error running the tests then you will need to configure `launchctl limit maxfiles`.

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
