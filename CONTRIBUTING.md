# 🛠️ Contributing Guide

Thanks for your interest in contributing to **Vulnora** 🎉  
We’re thrilled to have you here!

Whether it’s fixing bugs, adding features, improving docs, or even fixing typos - all contributions are welcome.

---

## 🚀 How to Contribute

### 1️⃣ Fork & Clone
Fork the repository and clone it locally.

```bash
git clone https://github.com/your-username/project-name.git
cd project-name
```

### 2️⃣ Set Up Development Environment

- Set up environment variables by copying `.env.sample` to `.env` and filling your credentials.
- Make sure you have set up [Docker](https://www.docker.com/get-started/) on your device and you are familiar with [basic commands](https://docs.docker.com/get-started/docker_cheatsheet.pdf).
- After setting up environment variables, run:
    ```bash
    docker compose up
    ```

---

## 💡 Creating an Issue

Before submitting a PR, make sure an issue exists:

1. Search the existing issues to avoid duplicates.
2. If not found, create a new one with a clear title and description.
3. Tag it with appropriate labels (bug, enhancement, documentation, good first issue, etc.)

---

## 🔄 Creating a Pull Request
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

## 🏷️ Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):
```bash
feat: add new login API
fix: SQLi attack log issue
docs: update README
chore: update dependencies
```

---

## 🧠 Tips for Hacktoberfest Contributors
- Check for issues labeled hacktoberfest, good first issue, or help wanted.
- Read the issue carefully before claiming it.
- Be respectful and communicate clearly in PR discussions.
- You can always ask for help, we’re beginner-friendly ❤️

---

## 🧾 License
By contributing, you agree that your contributions will be licensed under the same license as the [project](License).

---

## 🙌 Credits
This project is maintained by the MDG Space team and open-source contributors.

---
