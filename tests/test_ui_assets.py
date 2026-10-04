"""Static checks for the Arco Design console (no browser needed)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "server" / "static"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_app_js_parses() -> None:
    subprocess.run(["node", "--check", str(STATIC / "app.js")], check=True)


def test_no_innerhtml_or_eval_in_app() -> None:
    src = (STATIC / "app.js").read_text()
    for banned in ("innerHTML", "dangerouslySetInnerHTML", "eval(", "new Function", "document.write"):
        assert banned not in src, banned


def test_index_references_existing_assets_only() -> None:
    html = (STATIC / "index.html").read_text()
    refs = re.findall(r'(?:src|href)="/static/([^"]+)"', html)
    assert refs and all((STATIC / r).is_file() for r in refs), refs
    assert "<script>" not in html  # CSP script-src 'self' forbids inline scripts


def test_logos_are_valid_svg() -> None:
    import xml.dom.minidom
    for name in ("logo.svg", "logo-full.svg", "favicon.svg"):
        doc = xml.dom.minidom.parse(str(STATIC / name))
        assert doc.documentElement.tagName == "svg"
        assert "currentColor" not in (STATIC / name).read_text()  # <img> SVGs don't inherit CSS color


def test_every_menu_route_has_a_page() -> None:
    src = (STATIC / "app.js").read_text()
    menu_keys = set(re.findall(r'\["([a-z-]+)", "[^"]+", I\.Icon', src))
    routed = set(re.findall(r'case "([a-z-]+)":', src))
    assert menu_keys - {"overview"} <= routed, menu_keys - routed
