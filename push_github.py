#!/usr/bin/env python3
"""
把 VPRS 标准仓库同步到公开 GitHub 仓 leo-bone/vouched-reputation-standard。

本机 git 已坏（xcrun missing），故走 GitHub REST git-database API 直接推（无本地 git）。
用法：
  python3 push_github.py          # 干跑：列出将推送的文件
  python3 push_github.py --push   # 真正推送（全量 tree，覆盖式同步）
"""
import os
import sys
import json
import base64
import subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
OWNER = "leo-bone"
REPO = "vouched-reputation-standard"
BRANCH = "main"
API = f"https://api.github.com/repos/{OWNER}/{REPO}"

SKIP_NAMES = {"__pycache__", ".DS_Store", ".pyc", "issuer.key"}
SKIP_DIRS = {"__pycache__", ".git", "node_modules"}


def get_token():
    env = os.environ.get("GH_TOKEN")
    if env:
        return env
    try:
        out = subprocess.check_output(
            ["/Users/leo/.workbuddy/binaries/gh/bin/gh", "auth", "token"],
            stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except Exception as e:
        sys.exit(f"无法获取 gh token: {e}")


TOKEN = get_token()
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
}


def api(method, path, body=None):
    import urllib.request
    import urllib.error
    data = json.dumps(body).encode() if body is not None else None
    url = path if path.startswith("https://") else API + path
    req = urllib.request.Request(url, data=data, method=method, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode() or "{}"
    except urllib.error.HTTPError as e:
        return f"HTTPERR:{e.code}:{e.read().decode()[:300]}"
    except Exception as e:
        return f"ERR:{e}"


def api_json(method, path, body=None, retries=5):
    import time
    last = None
    for attempt in range(retries):
        raw = api(method, path, body)
        if not (raw.startswith("HTTPERR") or raw.startswith("ERR")):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                last = f"NONJSON:{raw[:200]}"
        else:
            last = raw
        # 429/空响应：退避重试
        wait = 2 * (attempt + 1)
        print(f"  [retry {attempt+1}/{retries}] {last[:120]}  (wait {wait}s)")
        time.sleep(wait)
    sys.exit(f"API 失败: {last}")


def collect_files():
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in SKIP_NAMES or fn.endswith(".log"):
                continue
            full = os.path.join(dirpath, fn)
            if ".git" in full.split(os.sep):
                continue
            out.append(full)
    out.sort()
    return out


def main():
    push = "--push" in sys.argv
    files = collect_files()
    print(f"将同步 {len(files)} 个文件到 {OWNER}/{REPO}（公开）")
    for f in files[:25]:
        print("  ", os.path.relpath(f, ROOT))
    if len(files) > 25:
        print(f"  ... 其余 {len(files) - 25} 个")

    if not push:
        print("\n[干跑] 加 --push 执行真正推送。")
        return

    info = api("GET", "")
    if info.startswith("HTTPERR:404"):
        print("仓库不存在，创建公开仓 ...")
        create = api("POST", "https://api.github.com/user/repos",
                     {"name": REPO, "private": False, "auto_init": False,
                      "description": "Vouched Portable Reputation Standard (VPRS v1) — open standard + zero-dependency reference implementation for portable, payment-verified AI agent reputation.",
                      "homepage": "https://vouched.uichain.org"})
        if create.startswith("HTTPERR"):
            sys.exit(f"建仓失败: {create}")
        print("  建仓 OK")
    elif info.startswith("HTTPERR"):
        sys.exit(f"查仓失败: {info}")

    print("逐文件提交（Contents API，可在空仓上自动初始化）...")
    ok = 0
    for f in files:
        rel = os.path.relpath(f, ROOT).replace(os.sep, "/")
        with open(f, "rb") as fh:
            content = fh.read()
        b64 = base64.b64encode(content).decode()
        body = {"message": f"add {rel}", "content": b64, "encoding": "base64"}
        # 若文件已存在（重复推送/续传），带 sha 走更新模式
        head = api("GET", f"/contents/{rel}")
        if not head.startswith("HTTPERR") and head.strip():
            try:
                existing = json.loads(head)
                sha = existing.get("sha") if isinstance(existing, dict) else None
                if sha:
                    body["sha"] = sha
            except json.JSONDecodeError:
                pass
        res = api_json("PUT", f"/contents/{rel}", body, retries=6)
        if "content" not in res and "commit" not in res:
            # 某些返回仅含 commit；再放宽判断
            if isinstance(res, dict) and ("sha" in res or "path" in res):
                pass
            else:
                sys.exit(f"文件提交失败 {rel}: {res}")
        ok += 1
        print(f"  [{ok}/{len(files)}] {rel}")
    print(f"  推送完成 → {OWNER}/{REPO}@{BRANCH} ({len(files)} 文件)")


if __name__ == "__main__":
    main()
