import sys
from pathlib import Path

snippets = [
    ("python-qrcode", "real_eval/python-qrcode", "import qrcode; qrcode.make('hi')"),
    ("records", "real_eval/records", "import records; db = records.Database('sqlite:///:memory:')"),
    ("requests-html", "real_eval/requests-html", "from requests_html import HTMLSession; s = HTMLSession()"),
    ("responder", "real_eval/responder", "import responder; api = responder.API()"),
    ("requests", "real_eval/requests", "import requests; s = requests.Session()"),
]

for name, rel_path, code in snippets:
    p = str(Path(rel_path).resolve())
    sys.path.insert(0, p)
    try:
        exec(code, {"__name__": "__main__"})
        print(f"{name}: SUCCESS")
    except Exception as e:
        print(f"{name}: EXCEPTION: {type(e).__name__}: {e}")
    finally:
        if p in sys.path:
            sys.path.remove(p)
