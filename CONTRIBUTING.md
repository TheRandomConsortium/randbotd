# 🤝 Contributing to `randbotd`

First off, thank you for considering contributing to `randbotd`! `randbotd` is a community-driven, peer-to-peer daemon dedicated to building a monopolyless, decentralized Web PKI for Handshake, Tor, I2P, and clearnet infrastructure.

---

## 📜 Code of Conduct

By participating in this project, you agree to maintain a respectful, constructive, and inclusive environment. We do not tolerate harassment, discrimination, or abusive behavior of any kind.

---

## 🛠️ How to Contribute

### 1. Reporting Bugs & Proposing Features
* Search existing issues to ensure your bug or request has not already been reported.
* If opening a new issue, provide:
  * A clear, descriptive title.
  * System environment details (OS, CPU architecture, daemon version).
  * Exact steps to reproduce the issue.
  * Expected vs. actual behavior.

### 2. Fork & Setup Local Workspace

```bash
# Clone the repository
git clone https://github.com/TheRandomConsortium/randbotd.git
cd randbotd

# Verify code formatting and linting tools
cargo fmt --check
cargo clippy
```

---

## 🌿 Branching Strategy & Commit Guidelines

### Branch Naming Conventions
- `feature/<short-description>`: New functional features or modules.
- `fix/<short-description>`: Bug fixes and security patches.
- `chore/<short-description>`: Maintenance, CI/CD, documentation, or refactoring.

### Commit Messages
Use concise, imperative commit messages:
- `feat(p2p): add libp2p gossipsub topic handler for ca publication`
- `fix(acme): correct tolerance window calculation for unproven domains`
- `docs(manifesto): clarify bi-directional image cleaning tenets`

---

## 🧪 Development Workflow & Quality Gates

Before submitting a Pull Request (PR), ensure your branch passes all required quality checks:

1. **Format Check**:
   ```bash
   cargo fmt --check
   ```
2. **Lint Check**:
   ```bash
   cargo clippy --all-targets -- -D warnings
   ```
3. **Unit & Integration Tests**:
   ```bash
   cargo test
   ```

---

## 📬 Pull Request Process

1. Open your PR against the `main` branch.
2. Provide a clear summary of changes in the PR description, referencing relevant Issue numbers (e.g. `Fixes #42`).
3. Ensure all CI build checks pass.
4. Maintain active communication during code review. At least one maintainer approval is required before merging.

---

## 🔒 Security Vulnerability Disclosure

If you discover a security vulnerability within `randbotd` (e.g., cryptographic flaws, vote-stuffing exploits, Sybil vulnerabilities, or X.509 parsing bypasses):
* **Do NOT disclose the issue publicly in GitHub issues.**
* Visit the official Consortium landing page at **`the.consortium.randºm`** and look for available contact methods there, as these are continuously kept up to date.
* *(Note: Later on, `randbotd`-exclusive communication channels will be established, similar to those in place for Juanita).*
* Include detailed proof-of-concept (PoC) steps so we can investigate and publish a patch promptly.

---

## 📄 Licensing

By contributing code, scripts, or documentation to `randbotd`, you agree that your contributions will be licensed under the **Mozilla Public License 2.0 (MPL-2.0)**.
