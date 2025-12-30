# Requirements Files Guide

This project includes several requirements files for different use cases:

## Files Overview

### `requirements.txt`
**Core dependencies only** - Minimum required packages for the library to function.
- `lz4` - For decompressing Firefox session files
- `pycryptodomex` - For decrypting browser cookies

**Note:** Platform-specific dependencies (jeepney, dbus-python, shadowcopy) are not included here as they depend on your OS and Python version. They are automatically installed when using `pip install browser-cookie3` or `requirements-all.txt`.

### `requirements-all.txt`
**Complete dependencies** - Includes all core and platform-specific dependencies with environment markers.
- Core dependencies (lz4, pycryptodomex)
- Platform-specific dependencies with automatic platform detection:
  - `jeepney` (Linux/BSD, Python >= 3.7)
  - `dbus-python` (Linux/BSD, Python < 3.7)
  - `shadowcopy` (Windows, Python >= 3.7)
- Optional: `requests` for examples

**Recommended for:** Manual installation or when you want explicit control over all dependencies.

### `requirements-examples.txt`
**For running examples** - Includes core dependencies plus `requests` for the example scripts.
- Includes `requirements.txt`
- Adds `requests>=2.25.0` for HTTP requests in examples

**Use when:** You want to run the example scripts in `examples.py`.

### `requirements-dev.txt`
**Development dependencies** - For contributors and developers.
- Includes `requirements.txt`
- Testing: pytest, pytest-cov, pytest-timeout
- Code quality: black, flake8, mypy, isort
- Documentation: sphinx, sphinx-rtd-theme

**Use when:** You're developing or contributing to the project.

### `tests/test-requirements.txt`
**Test dependencies** - For running the test suite.
- selenium, webdriver-manager
- Core dependencies
- Testing utilities

**Use when:** Running the test suite.

## Installation Instructions

### For End Users (Recommended)

The easiest way is to install via pip, which handles platform-specific dependencies automatically:

```bash
pip install browser-cookie3
```

### For Developers

```bash
# Install core library
pip install -r requirements.txt

# Or install with all platform-specific dependencies
pip install -r requirements-all.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Install test dependencies
pip install -r tests/test-requirements.txt
```

### For Running Examples

```bash
# Install dependencies for examples
pip install -r requirements-examples.txt

# Or install the package which includes examples
pip install browser-cookie3 requests
```

## Platform-Specific Notes

### Linux/BSD
- **Python >= 3.7**: Requires `jeepney`
- **Python < 3.7**: Requires `dbus-python`

These are automatically installed when using `pip install browser-cookie3`.

### Windows
- **Python >= 3.7**: Optional but recommended `shadowcopy` for better cookie file access

### macOS
- No additional platform-specific dependencies required

## Manual Installation of Platform-Specific Dependencies

If you need to install platform-specific dependencies manually:

### Linux/BSD (Python >= 3.7)
```bash
pip install jeepney
```

### Linux/BSD (Python < 3.7)
```bash
pip install dbus-python
```

### Windows (Python >= 3.7)
```bash
pip install shadowcopy
```

## Troubleshooting

### Import Errors

If you get import errors for platform-specific modules:
1. Check your Python version: `python --version`
2. Check your platform: `python -c "import sys; print(sys.platform)"`
3. Install the appropriate dependency manually (see above)

### Missing Dependencies

If you're missing dependencies:
- Use `requirements-all.txt` for complete installation
- Or install via `pip install browser-cookie3` which handles everything automatically

## Version Compatibility

- **Python**: 3.6+ (Python 3.7+ recommended)
- **lz4**: >= 0.10.0
- **pycryptodomex**: >= 3.4.0
- **jeepney**: >= 0.4.0 (Linux/BSD, Python >= 3.7)
- **dbus-python**: >= 1.2.0 (Linux/BSD, Python < 3.7)
- **shadowcopy**: >= 0.1.0 (Windows, Python >= 3.7)

