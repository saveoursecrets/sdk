# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands
- Build: `cargo make debug` (debug) or `cargo make release` (optimized)
- Format: `cargo make format` or check with `cargo make format-check`
- Lint: `cargo make clippy`
- Test: `cargo make test` (standard) or `cargo make test-all` (all backends)
- Unit tests only: `cargo make unit`
- Single test: `cargo nextest run -p sos-integration-tests test_name` 
- CLI tests: `cargo make test-cli` or `cargo make test-shell`
- Documentation: `cargo make doc`

## Code Style
- Use the Rust 2018 edition style
- Maximum line width: 78 characters
- Prefer `thiserror` for error handling with clear, specific error types
- Use doc comments (`///`) for public APIs
- Add `#![deny(missing_docs)]` and `#![forbid(unsafe_code)]` to crate roots
- Prefer `Result<T, Error>` with custom error types for error handling
- Implement informative Display/Debug traits for public types
- Use bitflags for flag-based enums
- Ensure proper serialization/deserialization for custom types

## Naming and Structure
- Use snake_case for variables, functions, and modules
- Use PascalCase for types and traits
- Group related functionality in modules
- Re-export important types in crate root
- Use clear, descriptive names that reflect domain concepts
- Follow vault, folder, secret terminology as defined in documentation
