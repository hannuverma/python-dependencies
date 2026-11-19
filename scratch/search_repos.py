import httpx

headers = {"User-Agent": "Mozilla/5.0"}
url = "https://api.github.com/search/repositories?q=language:python+stars:>50+size:<2000&sort=updated&order=desc&per_page=50"
r = httpx.get(url, headers=headers)
data = r.json()
print("Found repos:", len(data.get("items", [])))

candidates = []
for item in data.get("items", []):
    full_name = item["full_name"]
    branch = item["default_branch"]
    for fn in ["requirements.txt", "poetry.lock", "Pipfile.lock"]:
        url_file = f"https://raw.githubusercontent.com/{full_name}/{branch}/{fn}"
        rf = httpx.get(url_file, headers=headers)
        if rf.status_code == 200:
            lines = [l.strip() for l in rf.text.splitlines() if "==" in l or "name = \"" in l]
            if len(lines) >= 3:
                candidates.append((full_name, branch, fn, len(lines), lines[:3]))
                print(f"{full_name} ({branch}): {fn} with {len(lines)} pins")
                break
    if len(candidates) >= 10:
        break
