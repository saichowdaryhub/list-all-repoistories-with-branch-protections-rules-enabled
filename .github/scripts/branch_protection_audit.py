#!/usr/bin/env python3
import os, requests, time, csv

ORG = os.getenv("ORG_NAME")
TOKEN = os.getenv("GITHUB_TOKEN")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
SLACK_TOKEN = os.getenv("SLACK_TOKEN")
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL")
DEBUG = os.getenv("DEBUG","false").lower() == "true"


def log(m, l="INFO"):
    print(f"[{l}] {m}", flush=True)


def dbg(m):
    if DEBUG:
        log(m, "DEBUG")


H = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json"}


def get_json(url):
    r = requests.get(url, headers=H, timeout=30)
    dbg(f"GET {url} -> {r.status_code}")
    if r.status_code == 200:
        return r.json()
    if r.status_code == 404:
        return None
    log(f"Failed GET {url} -> {r.status_code}: {r.text[:150]}", "WARN")
    return None


def list_repos():
    repos, page = [], 1
    while True:
        data = get_json(f"https://api.github.com/users/{ORG}/repos?per_page=100&page={page}&type=public")
        if not data:
            break
        repos += data
        if len(data) < 100:
            break
        page += 1
    active_repos = [r for r in repos if not r.get("archived", False)]
    return active_repos


def get_rules(repo, branch):
    return get_json(f"https://api.github.com/repos/{ORG}/{repo}/rules/branches/{branch}") or []


def try_get_classic_protection(repo, branch):
    url = f"https://api.github.com/repos/{ORG}/{repo}/branches/{branch}/protection"
    r = requests.get(url, headers=H, timeout=30)
    dbg(f"GET {url} -> {r.status_code}")
    if r.status_code == 200:
        return r.json()
    return None


def upload_csv_to_slack(csv_path, token, channel, message):
    url = "https://slack.com/api/files.upload"
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "channels": channel,
        "initial_comment": message,
        "filename": os.path.basename(csv_path),
        "title": "branch-protection-results",
    }
    try:
        with open(csv_path, "rb") as fh:
            files = {"file": (os.path.basename(csv_path), fh, "text/csv")}
            r = requests.post(url, headers=headers, data=data, files=files, timeout=60)
        dbg(f"Slack upload status {r.status_code}")
        jr = r.json()
        if not jr.get("ok"):
            log(f"Slack upload error: {jr}", "WARN")
            return False
        return True
    except Exception as e:
        log(f"Slack file upload failed: {e}", "WARN")
        return False


def post_webhook(slack_webhook, message):
    try:
        r = requests.post(slack_webhook, json={"text": message}, timeout=30)
        dbg(f"Webhook post -> {r.status_code}")
        return r.status_code == 200
    except Exception as e:
        log(f"Slack webhook POST failed: {e}", "WARN")
        return False


def main():
    repos = list_repos()
    log(f"Total active public repositories found: {len(repos)}")

    rows = []
    missing, ok = [], []

    for idx, repo in enumerate(repos, start=1):
        name = repo["name"]
        default_branch = repo.get("default_branch", "main")
        log(f"\n[{idx}/{len(repos)}] Checking repository: {name}")

        row = {
            "Repository": name,
            "Default Branch": default_branch,
            "Default branch protection exists": "NO",
            "Required pull request": "NO",
            "Required approvals count": "",
            "Restrict deletions": "NO",
            "Block Force pushes": "NO",
        }

        issues = []
        rules = get_rules(name, default_branch)

        if not rules:
            classic = try_get_classic_protection(name, default_branch)
            if classic:
                row["Default branch protection exists"] = "YES"
                pr_reviews = classic.get("required_pull_request_reviews")
                if not pr_reviews:
                    issues.append("Require pull request before merging not enabled")
                else:
                    cnt = pr_reviews.get("required_approving_review_count", 0)
                    row["Required pull request"] = "YES"
                    row["Required approvals count"] = str(int(cnt)) if cnt else ""
                    if int(cnt) != 2:
                        issues.append(f"Required approvals = {cnt}, expected 2")

                if classic.get("restrictions"):
                    row["Restrict deletions"] = "YES"

                if "allow_force_pushes" in classic:
                    if not classic.get("allow_force_pushes"):
                        row["Block Force pushes"] = "YES"

                if issues:
                    missing.append({"repo": name, "issues": issues})
                else:
                    ok.append(name)
                rows.append(row)
                continue

            missing.append({"repo": name, "issues": [f"No branch protection found on '{default_branch}'"]})
            rows.append(row)
            continue

        row["Default branch protection exists"] = "YES"
        rule_types = {r.get("type"): r for r in rules}

        if "pull_request" in rule_types:
            row["Required pull request"] = "YES"
        else:
            issues.append("Require pull request before merging not enabled")

        if "required_approving_review_count" in rule_types:
            params = rule_types["required_approving_review_count"].get("parameters") or {}
            count = params.get("required_approving_review_count") or params.get("count")
            if count:
                row["Required approvals count"] = str(int(count))
                if int(count) != 2:
                    issues.append(f"Required approvals = {count}, expected 2")
            else:
                issues.append("Approvals rule present but count missing")
        else:
            issues.append("Required approving reviews rule missing")

        if "restrict_deletions" in rule_types:
            row["Restrict deletions"] = "YES"
        else:
            issues.append("Restrict deletions rule not enabled")

        if "non_fast_forward" in rule_types:
            row["Block Force pushes"] = "YES"
        else:
            issues.append("Block force pushes rule not enabled")

        if issues:
            missing.append({"repo": name, "issues": issues})
        else:
            ok.append(name)

        rows.append(row)

    # Write CSV
    csv_path = "results.csv"
    fieldnames = [
        "Repository",
        "Default Branch",
        "Default branch protection exists",
        "Required pull request",
        "Required approvals count",
        "Restrict deletions",
        "Block Force pushes",
    ]
    try:
        with open(csv_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        log(f"Wrote CSV results to {csv_path}")
    except Exception as e:
        log(f"Failed to write CSV: {e}", "WARN")

    # Upload to Slack only (prefer token+channel)
    completion_message = "Branch Protection Audit Summary has been completed and results are results.csv"
    uploaded = False
    if SLACK_TOKEN and SLACK_CHANNEL:
        uploaded = upload_csv_to_slack(csv_path, SLACK_TOKEN, SLACK_CHANNEL, completion_message)
    elif SLACK_WEBHOOK:
        # webhook can't upload file; post message only
        post_webhook(SLACK_WEBHOOK, completion_message)

    if uploaded:
        log("Uploaded CSV to Slack channel")
    else:
        if SLACK_TOKEN and SLACK_CHANNEL:
            log("Tried uploading to Slack but failed; check logs and token/channel", "WARN")
        else:
            log("No Slack token/channel configured; only printed CSV to logs", "WARN")


if __name__ == '__main__':
    main()
