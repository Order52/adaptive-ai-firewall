import json, sys
from pathlib import Path
from playwright.sync_api import sync_playwright
tok = (Path.home()/".config/afw/api/dashboard.token").read_text().strip()
out = Path(sys.argv[1])
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1400, "height": 3000})
    ctx.add_init_script(f"localStorage.setItem('afw_token', '{tok}')")
    pg = ctx.new_page(); errs = []; fails = []
    pg.on("console", lambda m: errs.append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None)
    pg.on("response", lambda r: fails.append(f"{r.status} {r.url}") if r.status >= 400 else None)
    pg.goto("https://10.77.50.10:8080/", wait_until="networkidle"); pg.wait_for_timeout(6000)
    pg.screenshot(path=str(out), full_page=True)
    tiles = pg.inner_text("#tiles")
    cards = pg.eval_on_selector_all("section h2", "els => els.map(e => e.textContent.trim())")
    empties = pg.eval_on_selector_all(".card", "els => els.map(e => [e.querySelector('h2')?.textContent.trim(), e.innerText.length])")
    print(json.dumps({"tiles": tiles, "cards": cards, "card_text_len": empties, "console": errs, "http_errors": fails}, indent=1))
    b.close()
