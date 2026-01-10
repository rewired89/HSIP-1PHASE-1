# Contributing to HSIP

Thank you for your interest in contributing to HSIP (Hyper-Secure Internet Protocol)

HSIP is a community-driven privacy project that welcomes contributions from developers, security researchers, and privacy advocates.

---

## Quick Start

### Code Standards

- Follow Rust conventions (use `cargo fmt`)
- Add tests for new features
- Update documentation as needed
- No breaking changes without discussion

---

## 1. Documentation Contributions

We welcome improvements to:

- README.md
- TESTING.md
- docs/PROTOCOL_SPEC.md
- docs/API_REFERENCE.md
- docs/EXAMPLES.md
- Code comments and docstrings

**How to contribute docs:**

- Fix typos or unclear explanations
- Add missing examples
- Improve command descriptions
- Translate documentation (future)

---

## 2. Bug Reports

When reporting bugs, include:

- HSIP version (`cargo run --bin hsip-cli -- --version`)
- Operating system (Windows 10/11, Linux distro, macOS version)
- Rust version (`rustc --version`)
- Steps to reproduce
- Expected vs actual behavior
- Error messages or logs (`RUST_LOG=debug`)

**Open an issue:** https://github.com/rewired89/HSIP-1PHASE/issues/new

---

## 3. Feature Requests

We're open to new ideas! Before requesting:

- Check if it already exists in Issues
- Explain the use case and why it's needed
- Consider if it fits HSIP's privacy/consent focus

**Feature categories:**

- Core protocol improvements
- New cryptographic features
- Platform support (Linux, macOS, mobile)
- UI/UX enhancements
- Integration with other tools

---

## Contribution Guidelines

### ✅ We Accept:

- Bug fixes
- Documentation improvements
- Test coverage improvements
- Performance optimizations
- Security enhancements
- Platform compatibility fixes
- Example code and tutorials

### ❌ We Generally Reject:

- Breaking changes without discussion
- Features that weaken security/privacy
- Dependencies with restrictive licenses
- Code that violates consent principles
- Unmaintained or bloated dependencies

---

## Testing Requirements

All contributions must pass:

# 1. All tests must pass
cargo test --workspace

# 2. Code must compile without errors
cargo build --release --workspace

# 3. Clippy should pass (warnings OK, errors not)
cargo clippy --workspace

# 4. Format code
cargo fmt --all

Pull Request Process

    Create PR with clear title and description
    Link related issue (ex: "Fixes #42")
    Wait for review (we'll respond within 3-5 days)
    Address feedback if requested
    Merge once approved

PR title format:

    Add: new feature description
    Fix: bug description
    Docs: documentation improvement
    Test: test coverage for X

Community Guidelines
Be respectful:

    Constructive feedback only
    No harassment or discrimination
    Assume good intentions
    Help newcomers

Stay on topic:

    Keep discussions focused on HSIP
    Avoid off-topic conversations
    Use appropriate channels (issues for bugs, discussions for ideas)

License Agreement

By contributing to HSIP, you agree that:

    Your contributions will be licensed under the same dual-license model:
        Community License (non-commercial)
        Enterprise License (commercial)

    You have the right to submit the contribution (no copyright violations)

    You grant Nyx Systems LLC the right to use, modify, and distribute your contribution

    Your contribution does not include any patented technology without disclosure

Open Source & Community Projects

If you're building an open source project using HSIP:
✅ You're covered under the Community License!

Examples of accepted use:

    Open source privacy tools
    Educational security demos
    Research projects with published code
    Community libraries and integrations
    Non-profit organizational tools
    Hackathon projects
    Student thesis projects

Just make sure:

    Your project is open source (public GitHub repo, OSI-approved license)
    You're not generating revenue from it
    You're not providing it as a paid service

Want to feature your project? Email us at contact@hsip.io - we love showcasing community work!
Getting Help

For development questions:

    Open a GitHub Discussion
    Check existing issues and docs first
    Be specific about your problem

For licensing questions:

    Email: contact@hsip.io
    Include your use case and whether it's commercial

For security vulnerabilities:

    Do NOT open public issues
    Email: contact@hsip.io with subject "HSIP Security"
    I'll respond within 48 hours

Development Setup

# Prerequisites
# - Rust 1.87+ (install from https://rustup.rs)
# - Windows 10/11 (or Linux for core features)

# 1. Clone repo
git clone https://github.com/rewired89/HSIP-1PHASE.git
cd HSIP-1PHASE

# 2. Build
cargo build --workspace

# 3. Run tests
cargo test --workspace

# 4. Try CLI (run each command separately)
cargo run --bin hsip-cli -- init

cargo run --bin hsip-cli -- whoami

cargo run --bin hsip-cli -- diag

# 5. Check formatting
cargo fmt --all --check

# 6. Run clippy
cargo clippy --workspace

Roadmap
Current priorities:

    Complete Windows installer
    Improve test coverage
    Add more examples
    Linux/macOS compatibility
    Documentation translations

See our GitHub Issues for specific tasks.
Recognition

Contributors will be:

    Listed in CONTRIBUTORS.md (coming soon)
    Credited in release notes
    Mentioned in project documentation

Top contributors may receive:

    Early access to new features
    Direct communication channel
    Potential internship/employment opportunities at Nyx Systems

Contact

    General questions: Open a GitHub Discussion
    Bug reports: GitHub Issues
    Licensing: contact@hsip.io
    Security: security@hsip.io
    Enterprise: licensing@hsip.io

Thank you for helping make the internet more private and secure!🔒