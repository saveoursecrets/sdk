# Release

Check all the tests first.

```
cargo make test
```

Bump the version and make sure the lock file is up to date after the version change.

```
cargo generate-lockfile
```

Check the security audits.

```
cargo audit
```

Publish the crate.

```
cargo publish
```

Publish the release artifacts.

```
git tag v0.5.5
git push origin v0.5.5
```
