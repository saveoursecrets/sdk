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

To publish a new release create a version tag and push it:

```
git tag v0.5.4
git push origin v0.5.4
```
