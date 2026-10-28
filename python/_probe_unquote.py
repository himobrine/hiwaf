"""一次性探针：确认 CPython unquote_plus 的边界语义 + 看 p7 的规则原文（不参与运行）。"""
import sys
from urllib.parse import unquote_plus

sys.path.insert(0, ".")
import p7_rule_mining as p7  # noqa: E402

print("=== p7.RULES ===")
for k, v in p7.RULES.items():
    print(f"{k:24s} = {v!r}")

print()
print("=== unquote_plus 边界 ===")
cases = ["a=%", "a=%2zb", "a=%%41", "a=1+2", "q=%2575nion%2520select",
         "a=%2", "a=%zz", "%41%42", "a=%25", "a=%C3%A9", "a=%E4%B8%AD"]
for c in cases:
    print(f"{c!r:30s} -> {unquote_plus(c)!r:30s} ->2x-> {unquote_plus(unquote_plus(c))!r}")

print()
print("=== 落单代理 ===")
print("chr(0xD83D) =", repr(chr(0xD83D)))
try:
    print("utf-8 encode:", chr(0xD83D).encode("utf-8"))
except Exception as e:
    print("utf-8 encode raises:", type(e).__name__, e)
