# Contributing to B4AE

Thank you for your interest in contributing to B4AE! This document provides guidelines for contributing to the project.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Rust version, etc.)

### Suggesting Features

1. Check existing feature requests
2. Create a new issue with:
   - Clear description of the feature
   - Use cases and benefits
   - Potential implementation approach

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run formatting (`cargo fmt`)
6. Run linting (`cargo clippy`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Development Setup

```bash
# Clone your fork (--recursive untuk ELARA submodule)
git clone --recursive https://github.com/YOUR_USERNAME/B4AE-Beyond-For-All-Encryption-.git
cd B4AE-Beyond-For-All-Encryption-

# Jika sudah clone tanpa --recursive, update submodule:
git submodule update --init --recursive

# Add upstream remote
git remote add upstream https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git

# Install dependencies
cargo build

# Build dengan ELARA
cargo build --features elara

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Coding Standards

- Follow Rust naming conventions
- Write clear, self-documenting code
- Add comments for complex logic
- Write tests for new features
- Update documentation as needed

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, etc.)
- Keep first line under 50 characters
- Add detailed description if needed

Example:
```
Add Kyber-1024 key generation

Implements NIST-standardized Kyber-1024 KEM for post-quantum
key exchange. Includes unit tests and benchmarks.
```

### Testing

- Write unit tests for all new code
- Ensure all tests pass before submitting PR
- Add integration tests for new features
- Update benchmarks if performance-critical

### Documentation

- Update README.md if adding user-facing features
- Add inline documentation for public APIs
- Update technical documentation as needed
- Include examples for new features

## Security

**Do not** report security vulnerabilities publicly. Email security@b4ae.org instead.

## License

By contributing, you agree that your contributions will be dual-licensed under MIT and Apache 2.0.

## Questions?

Feel free to ask questions in:
- GitHub Issues
- GitHub Discussions
- Email: info@b4ae.org

Thank you for contributing to B4AE! 🚀
