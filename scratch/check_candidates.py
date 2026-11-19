import httpx

candidates = [
    ('encode/httpx', '0.7.7'),
    ('encode/httpx', '0.9.3'),
    ('tiangolo/full-stack-fastapi-template', '0.2.0'),
    ('pallets-eco/flask-caching', 'v1.7.0'),
    ('sloria/environs', '7.0.0'),
    ('joke2k/faker', 'v0.8.17'),
    ('psf/black', '19.3b0'),
]

for repo, tag in candidates:
    for fn in ['Pipfile.lock', 'requirements.txt', 'backend/app/requirements.txt']:
        url = f'https://raw.githubusercontent.com/{repo}/{tag}/{fn}'
        try:
            r = httpx.get(url, timeout=3)
            if r.status_code == 200:
                pins = [l.strip() for l in r.text.splitlines() if '==' in l or '"version": "==' in l]
                if len(pins) >= 3:
                    print(f'{repo} @ {tag} ({fn}): {len(pins)} pins: {pins[:3]}')
                    break
        except Exception:
            pass
