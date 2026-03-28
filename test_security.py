#!/usr/bin/env python3
"""
安全防護驗證測試 — 測真實 production code，不複製邏輯
用法：python3 test_security.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 直接 import production code
from downloader import _safe_material_name, _safe_draft_id, _safe_draft_folder, _validate_url
from mcp_server import _filter_arguments  # 測真實白名單，不複製

# ============================================================
# 測試框架
# ============================================================
_pass_count = 0
_fail_count = 0


def expect_raise(func, args, label, exc_type=ValueError):
    global _pass_count, _fail_count
    try:
        func(*args) if isinstance(args, tuple) else func(args)
        print(f"  FAIL  {label}  （預期 raise 但沒有）")
        _fail_count += 1
    except exc_type:
        print(f"  PASS  {label}")
        _pass_count += 1
    except Exception as e:
        print(f"  PASS  {label}  （raise {type(e).__name__}）")
        _pass_count += 1


def expect_ok(func, args, expected, label):
    global _pass_count, _fail_count
    try:
        result = func(*args) if isinstance(args, tuple) else func(args)
        if result == expected:
            print(f"  PASS  {label}")
            _pass_count += 1
        else:
            print(f"  FAIL  {label}  （預期 {expected!r} 得到 {result!r}）")
            _fail_count += 1
    except Exception as e:
        print(f"  FAIL  {label}  （raise {type(e).__name__}: {e}）")
        _fail_count += 1


def expect_filtered(tool_name, args, key, label):
    global _pass_count, _fail_count
    result = _filter_arguments(tool_name, args)
    if key not in result:
        print(f"  PASS  {label}")
        _pass_count += 1
    else:
        print(f"  FAIL  {label}  （{key!r} 未被過濾）")
        _fail_count += 1


# ============================================================
# 1. _safe_material_name
# ============================================================
print("\n" + "=" * 60)
print("1. _safe_material_name")
print("=" * 60)
expect_raise(_safe_material_name, ("../../etc/passwd",), "路徑穿越")
expect_raise(_safe_material_name, ("\x00evil.txt",), "null byte")
expect_raise(_safe_material_name, ("-f mp3",), "dash 開頭（ffmpeg 注入）")
expect_raise(_safe_material_name, ("a" * 300,), "超長檔名 > 255 bytes")
expect_ok(_safe_material_name, ("normal_file.mp4",), "normal_file.mp4", "正常檔名")
expect_ok(_safe_material_name, ("path/to/file.mp4",), "file.mp4", "basename 剝離")

# ============================================================
# 2. _safe_draft_id
# ============================================================
print("\n" + "=" * 60)
print("2. _safe_draft_id")
print("=" * 60)
expect_raise(_safe_draft_id, ("../../../",), "路徑穿越")
expect_raise(_safe_draft_id, ("a" * 200,), "超長 > 128")
expect_raise(_safe_draft_id, ("中文測試",), "非 ASCII")
expect_ok(_safe_draft_id, ("dfd_cat_123_abc123",), "dfd_cat_123_abc123", "合法 ID")
expect_raise(_safe_draft_id, ("",), "空字串")

# ============================================================
# 3. _safe_draft_folder
# ============================================================
print("\n" + "=" * 60)
print("3. _safe_draft_folder")
print("=" * 60)
expect_raise(_safe_draft_folder, ("/etc/evil",), "不在白名單")
expect_ok(_safe_draft_folder, ("/Users/tkman/test",), os.path.realpath("/Users/tkman/test"), "合法路徑")
expect_ok(_safe_draft_folder, (None,), None, "None 回傳 None")
expect_raise(_safe_draft_folder, ("../../../etc",), "路徑穿越")

# ============================================================
# 4. _validate_url（含 SSRF 完整測項）
# ============================================================
print("\n" + "=" * 60)
print("4. _validate_url")
print("=" * 60)
# 基本
expect_raise(_validate_url, ("http://127.0.0.1/",), "IPv4 loopback")
expect_raise(_validate_url, ("http://10.0.0.1/",), "IPv4 private")
expect_raise(_validate_url, ("http://169.254.169.254/",), "IPv4 link-local")
expect_raise(_validate_url, ("http://[::1]/",), "IPv6 loopback")
expect_raise(_validate_url, ("ftp://evil.com/",), "非 http/https")
expect_raise(_validate_url, ("  http://localhost/",), "前導空白 CVE-2023-24329")
expect_raise(_validate_url, ("http://localhost/",), "localhost")
expect_raise(_validate_url, ("\x00http://evil.com/",), "null byte")
expect_raise(_validate_url, ("a" * 5000,), "超長 URL")
expect_raise(_validate_url, ("",), "空字串")
# SSRF 進階：shared address space / multicast / unspecified
expect_raise(_validate_url, ("http://100.64.0.1/",), "shared address 100.64.0.0/10")
expect_raise(_validate_url, ("http://224.0.0.1/",), "IPv4 multicast")
expect_raise(_validate_url, ("http://[ff00::1]/",), "IPv6 multicast")
expect_raise(_validate_url, ("http://0.0.0.0/",), "unspecified 0.0.0.0")
expect_raise(_validate_url, ("http://192.168.1.1/",), "private 192.168.x.x")
expect_raise(_validate_url, ("http://172.16.0.1/",), "private 172.16.x.x")

# ============================================================
# 5. _filter_arguments（真實 production code）
# ============================================================
print("\n" + "=" * 60)
print("5. _filter_arguments（from mcp_server.py）")
print("=" * 60)
expect_filtered("add_video", {"video_url": "x", "draft_folder": "/evil"}, "draft_folder",
                "add_video + draft_folder → 過濾")
expect_filtered("save_draft", {"draft_id": "x", "script_data": {}}, "script_data",
                "save_draft + script_data → 過濾")
expect_filtered("create_draft", {"width": 1080, "extra": "evil"}, "extra",
                "create_draft + extra_param → 過濾")

# 合法參數保留
result = _filter_arguments("add_video", {"video_url": "http://x", "draft_id": "abc"})
if "video_url" in result and "draft_id" in result:
    print(f"  PASS  合法參數 video_url/draft_id 保留")
    _pass_count += 1
else:
    print(f"  FAIL  合法參數被誤濾")
    _fail_count += 1

# ============================================================
# 6. Python 3.9 import 鏈驗證
# ============================================================
print("\n" + "=" * 60)
print("6. Import 鏈驗證（Python 3.9 相容）")
print("=" * 60)
try:
    import mcp_server
    print(f"  PASS  mcp_server import 成功")
    _pass_count += 1
except Exception as e:
    print(f"  FAIL  mcp_server import 失敗: {e}")
    _fail_count += 1

try:
    import capcut_server
    print(f"  PASS  capcut_server import 成功")
    _pass_count += 1
except Exception as e:
    print(f"  FAIL  capcut_server import 失敗: {e}")
    _fail_count += 1

# ============================================================
# 結果
# ============================================================
print("\n" + "=" * 60)
total = _pass_count + _fail_count
print(f"測試結果：{_pass_count}/{total} PASS，{_fail_count}/{total} FAIL")
if _fail_count == 0:
    print("全部通過！")
else:
    print("有失敗項目，請修復。")
print("=" * 60)
sys.exit(1 if _fail_count > 0 else 0)
