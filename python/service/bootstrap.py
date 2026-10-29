"""初始化控制面数据库与 admin 账号（幂等）。

一键安装脚本用它完成「不启动服务也能建库」；也可手动执行：

    cd python
    py -3.10 -m service.bootstrap

行为：

* 只创建缺失的表/索引，不删不改已有数据；
* 已有用户时**不覆盖** admin 密码，也不重写 `.admin_password`；
* 首次创建 admin 时，密码来源与 `service.run` 完全一致
  （`WAF_CONSOLE_ADMIN_PASSWORD` 或随机生成并写入 `service/.admin_password`）。
"""
from __future__ import annotations

import sys

from . import auth, config, db


def main() -> int:
    db.init()
    auth.ensure_admin()
    print(f"[bootstrap] DB      : {config.DB_PATH}")
    print(f"[bootstrap] logs    : {config.LOG_DIR}")
    print(f"[bootstrap] raw     : {config.RAW_DIR}")
    pw = config.HERE / ".admin_password"
    if pw.exists():
        print(f"[bootstrap] admin 密码文件: {pw}")
    print("[bootstrap] 完成（重复执行不会覆盖已有账号或密码）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
