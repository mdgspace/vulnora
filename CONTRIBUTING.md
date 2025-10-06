# Contributing Guide

Thanks for your interest in contributing to **Vulnora**
We’re thrilled to have you here!

Whether it’s fixing bugs, adding features, improving docs, or even fixing typos - all contributions are welcome.

---

## How to Contribute

### Fork & Clone
Fork the repository and clone it locally.

```bash
git clone https://github.com/mdgspace/vulnora.git
cd vulnora
```

### Set Up Development Environment

- Set up environment variables by copying `.env.sample` to `.env` and filling your credentials.
- Make sure you have set up [Docker](https://www.docker.com/get-started/) on your device and you are familiar with [basic commands](https://docs.docker.com/get-started/docker_cheatsheet.pdf).
- After setting up environment variables, run:
    ```bash
    docker compose up
    ```

---

## Creating an Issue

Before submitting a PR, make sure an issue exists:

1. Search the existing issues to avoid duplicates.
2. If not found, create a new one with a clear title and description.
3. Tag it with appropriate labels (bug, enhancement, documentation, good first issue, etc.)

---

## Creating a Pull Request
**Steps:**

1. Create a new branch:
    ```bash
    git checkout -b feature/your-feature-name
    ```

2. Make your changes.

3. Commit your work:
    ```bash
    git commit -m "feat: add X functionality"
    ```

4. Push to your fork:
    ```bash
    git push origin feature/your-feature-name
    ```

5. Open a Pull Request to the main branch of the original repo.

---

## Conventional Commits Standard (Mandatory)

We enforce **Conventional Commits** to ensure a readable and consistent commit history. This standard is crucial for automating changelog generation.

### Format

Every commit message must be structured as follows:
```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types (The most common ones):

| Type | When to Use It |
| :--- | :--- |
| **`feat`** | A new feature, enhancement, or major addition (e.g., `feat: Add CSRF attack implementation`). |
| **`fix`** | A bug fix (e.g., `fix(DDoS): Fix DDoS implementation bugs`). |
| **`docs`** | Documentation-only changes (e.g., `docs: Update README with setup instructions`). |
| **`style`** | Code styling (linting, formatting, missing semicolons, etc.); doesn't affect code logic. |
| **`refactor`** | A code change that neither fixes a bug nor adds a feature (e.g., restructuring files, cleaning up utility functions). |
| **`perf`** | A code change that improves performance (e.g., Simulation logic optimization). |
| **`test`** | Adding missing tests or correcting existing tests. |
| **`build`** | Changes that affect the build system or external dependencies (e.g., `package.json`). |
| **`chore`** | Routine tasks that don't change source code or tests (e.g., updating `.gitignore`). |

### Scope (Optional)

The scope provides context for the change, usually naming the affected component or file path (e.g., `(xss)`, `(repo)`, `(ui)`, `(auth), (nmap)`).

## Tips for Hacktoberfest Contributors
- Check for issues labeled hacktoberfest, good first issue, or help wanted.
- Read the issue carefully before claiming it.
- Be respectful and communicate clearly in PR discussions.
- You can always ask for help, we’re beginner-friendly

---

## License
By contributing, you agree that your contributions will be licensed under the same license as the [project](License).

---

## Credits
This project is maintained by the MDG Space team and open-source contributors.

---
