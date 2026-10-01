# Contribution rules

- Use concise English Conventional Commit messages for commits and pull requests.
- Do not add emojis, co-author attribution, or development-stage labels to human or agent commits and pull requests. Dependabot-authored changes are the only exception.
- Merge pull requests with squash merge, delete the work branch, and synchronize local `main` with remote `main`.
- Run scenario-based unit tests and safe local TLS runtime tests for changed behavior. Do not add attack-capable vulnerability reproductions.
- Keep local service observations separate from deployed REG-08 conformance. Missing production authority, storage, or delegation evidence remains unverified.
