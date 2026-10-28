# Contributing to PHP-Hardening-Kit

Contributions, bug reports, and new detection signatures are welcome!

## Development & Testing Guidelines

1. **Broad Compatibility**:
   * All PHP code in `guard/` must strictly maintain syntactic and functional compatibility with PHP 5.4.0 through the latest PHP releases.
   * Avoid PHP 7+ specific syntax (such as `??`, scalar return type hints, or arrow functions) inside the core guard files.

2. **Zero Dependencies**:
   * The runtime guard and CLI auditor must remain zero-dependency.

3. **Running Tests**:
   ```bash
   ./tests/run-tests.sh
   ```
   Ensure all 14 tests pass and zero false-positives are introduced.

4. **Submitting Changes**:
   * Fork the repository.
   * Create a feature branch (`git checkout -b feature/new-signature`).
   * Commit your changes and open a Pull Request with a clear description of the vector mitigated.
