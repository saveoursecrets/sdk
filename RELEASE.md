# Release

Check all the tests first.

```
cargo make test
```

Check the security audits.

```
cargo audit
```

Bump the sdk version (need to update `sos-net` dependency too), commit and check.

```
cd workspace/sdk
cargo check --all-features
cargo publish
```

Then make sure the lock file is up to date after the version change.

```
cd workspace/net
cargo generate-lockfile
```

Bump the net version (need to update the `sos` dependency too), amend the git commit then publish `sos-net`.

```
cd workspace/net
cargo publish
```

Bump the `sos` version, amend the commit and publish the binary to crates.io from the root:

```
cargo publish
```

Finally push the commits and tag to publish the release artifacts.

```
git push origin main
git tag v0.10.0
git push origin v0.10.0
```
