"""初始化控制面数据库与 admin 账号（幂等）。

一键安装脚本用它完成「不启动服务也能建库」；也可手动执行：

    cd python
    py -3.10 -m service.bootstrap

行为：

* 只创建缺失的表/索引，不删不改已有数据；
* 同步 `registry_seed.json` 的预置模型代次：空库完整导入，非空库只补缺失代次
  （升级后无需删 `console.db` 就能看到新代次，如 g3）；
* 已有用户时**不覆盖** admin 密码，也不重写 `.admin_password`；
* 首次创建 admin 时，密码来源与 `service.run` 完全一致
  （`WAF_CONSOLE_ADMIN_PASSWORD` 或随机生成并写入 `service/.admin_password`）。
"""
from __future__ import annotations

import sys

from . import auth, config, db, model_registry


def main() -> int:
    db.init()
    auth.ensure_admin()
    # `install.sh --no-start` 也要把随仓库发布的代次清单导入空库 / 补入新代次，
    # 否则用户首次打开控制台前查库会看不到 g3。
    try:
        model_registry.ensure_dirs()
        synced = model_registry.sync_seed("bootstrap")
        model_registry.prune(actor="system")
        seed = synced.get("seed") or {}
        print(f"[bootstrap] models  : seed imported={seed.get('imported', 0)} "
              f"skipped={len(seed.get('skipped') or [])}")
    except Exception as e:  # noqa: BLE001 - 模型登记失败不应挡住安装
        print(f"[bootstrap] models  : 同步失败（不阻塞）：{e}")
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
