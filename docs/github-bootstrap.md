# GitHub bootstrap

Create an empty repository named `signport` under your personal account; do not initialize a second README or license on GitHub. Start private. From the extracted `signport` directory:

```bash
git init -b main
git add .
git diff --cached --stat
git commit -s -m "chore: initialize SignPort monorepo"
gh auth login
gh repo create signport --private --source=. --remote=origin --push
```

Confirm `gh repo view` shows the intended personal owner. If the repository already exists, add its actual remote URL instead of creating a new one, then push. Suggested description: Open-source, self-hosted digital signature infrastructure for local and cloud certificates, with ICP-Brasil support as a project goal.

Enable private vulnerability reporting when available, issues, branch protection appropriate to a solo maintainer and scaffold CI. Switch visibility only after the publication gate in [release-gates.md](release-gates.md). No real certificates, credentials or sensitive documents should enter Git history.
