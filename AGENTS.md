# AGENTS.md

WAF-AbuseIPDB reads Cloudflare firewall events and reports the IP addresses behind them to AbuseIPDB. The Report workflow runs `main.py` every hour; see [README.md](README.md).

## Checks

```bash
pip install -r requirements-dev.txt
ruff check .
coverage run -m unittest discover -v
coverage report
```

CI runs them with Python 3.15 and requires 100% line coverage. Never run `main.py` or the Report workflow with real keys to test a change: it sends real reports to AbuseIPDB.

## Contributing for Someone Else

martinfrancois's rule for outside contributions, and for any agent working for an outside contributor: contributors shouldn't spend time on pull requests that collide with someone else's work or that he wouldn't accept. So a contribution takes one of three paths (see "Three ways to contribute" in CONTRIBUTING.md):

- Small fix (bug fix, typo, docs improvement or similar): open a pull request directly, no issue needed. If an issue for it exists, claim it first as below.
- Existing issue: check its assignees and linked pull requests, post `/take` on the issue, and start only once the assignment comes back. Never open a pull request for an issue that isn't assigned to the contributor you work for, and don't start on one that someone else holds or that an open pull request already addresses.
- New feature: open a thread in the Ideas category of GitHub Discussions. Wait until martinfrancois approves it and opens an issue, then claim that issue with `/take`. Never open a feature pull request without an approved issue assigned to your contributor.
