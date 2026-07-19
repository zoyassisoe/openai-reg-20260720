#!/usr/bin/env python3
"""账号密码存储：每个邮箱一个随机强密码，持久化到 data/account_passwords.json。

为什么需要
- 批量起号若所有账号共用同一个 OAI_PASSWORD，是明显的批量关联特征。
- 改为每号独立随机密码后，注册/auth取凭证/team取凭证三个环节必须都能拿到「该号自己的密码」，
  否则 OpenAI 在取凭证时要求重新验密(password_verify)会失败 → 号注册了却取不了凭证=废号。
- 因此用一份「邮箱→密码」映射，注册时即写入并持久化，后续环节按邮箱读回。

并发安全
- batch 顺序写、team 子进程并发写，可能并发访问同一文件。沿用 local_phone_api 的跨平台
  进程文件锁(msvcrt/fcntl) + 线程锁 + 原子替换写，保证不丢不串。

安全
- data/ 不在服务器同步范围、不进 git（属运行期密钥数据）。本模块不打印密码明文。
- 兜底：映射查不到时回退环境变量 OAI_PASSWORD，兼容存量号/映射缺失，绝不返回空密码。
"""
from __future__ import annotations

import json
import os
import secrets
import string
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

try:  # Windows
    import msvcrt  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]
try:  # POSIX
    import fcntl  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


_ROOT = Path(__file__).resolve().parent
_STORE_PATH = _ROOT / "data" / "account_passwords.json"
_LOCK_PATH = _ROOT / "data" / ".account_passwords.lock"
_THREAD_LOCK = threading.RLock()

# 密码字符集：大小写字母+数字+常见安全符号，满足 OpenAI 强度要求且避免易混/会被 shell 转义的字符
_PWD_LOWER = "abcdefghijkmnpqrstuvwxyz"      # 去掉 l o
_PWD_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"     # 去掉 I O
_PWD_DIGIT = "23456789"                      # 去掉 0 1
_PWD_SYMBOL = "@#%^&*-_=+"                  # 不含 $ ! ` " ' \ 空格：避免 shell 变量/历史展开与 JSON 转义问题
_PWD_ALL = _PWD_LOWER + _PWD_UPPER + _PWD_DIGIT + _PWD_SYMBOL


def _norm(email: str) -> str:
    return str(email or "").strip().lower()


def generate_password(length: int = 16) -> str:
    """生成随机强密码：保证至少各含一个大写/小写/数字/符号，长度默认 16。"""
    n = max(12, int(length or 16))
    rng = secrets.SystemRandom()
    # 先各取一个保证类别齐全
    chars = [
        rng.choice(_PWD_LOWER),
        rng.choice(_PWD_UPPER),
        rng.choice(_PWD_DIGIT),
        rng.choice(_PWD_SYMBOL),
    ]
    chars += [rng.choice(_PWD_ALL) for _ in range(n - 4)]
    rng.shuffle(chars)
    pwd = "".join(chars)
    # 首字符不能是 '-'，否则 credential_cli/register_cli 的 --password 会被 argparse 当成新选项。
    if pwd.startswith("-"):
        pwd = rng.choice(_PWD_LOWER + _PWD_UPPER + _PWD_DIGIT + "@#%^&*_=+") + pwd[1:]
    return pwd


@contextmanager
def _process_file_lock(timeout_seconds: float = 60.0):
    """跨平台进程文件锁（沿用 local_phone_api 同款模式），配合线程锁防并发写。"""
    _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with _THREAD_LOCK:
        with open(_LOCK_PATH, "a+b") as lock_file:
            while True:
                try:
                    lock_file.seek(0)
                    if msvcrt is not None:
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    elif fcntl is not None:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (OSError, BlockingIOError):
                    if time.monotonic() - started >= max(1.0, float(timeout_seconds or 60.0)):
                        raise TimeoutError(f"account_passwords 进程锁获取超时: {_LOCK_PATH}")
                    time.sleep(0.1)
            try:
                yield
            finally:
                try:
                    lock_file.seek(0)
                    if msvcrt is not None:
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                    elif fcntl is not None:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass


def _load_unlocked() -> dict:
    try:
        payload = json.loads(_STORE_PATH.read_text(encoding="utf-8-sig"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {}


def _save_unlocked(payload: dict) -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STORE_PATH.with_suffix(_STORE_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_STORE_PATH)


def _fallback_password() -> str:
    return str(os.environ.get("OAI_PASSWORD") or "").strip()


def get_or_create_password(email: str, *, length: int = 16) -> str:
    """返回该邮箱的密码：已存在则返回，不存在则生成随机密码并持久化。

    注册阶段调用：保证「该号有且只有一个稳定密码」，写盘后才用于注册。
    """
    key = _norm(email)
    if not key:
        return _fallback_password()
    with _process_file_lock():
        store = _load_unlocked()
        existing = str(store.get(key) or "").strip()
        if existing:
            return existing
        pwd = generate_password(length)
        store[key] = pwd
        _save_unlocked(store)
        return pwd


def get_password(email: str) -> str:
    """只读返回该邮箱密码；查不到则兜底环境变量 OAI_PASSWORD（兼容存量号/映射缺失）。

    auth/team 阶段调用：绝不返回空串，避免取凭证因空密码失败。
    """
    key = _norm(email)
    if not key:
        return _fallback_password()
    with _process_file_lock():
        store = _load_unlocked()
    pwd = str(store.get(key) or "").strip()
    return pwd or _fallback_password()


def set_password(email: str, password: str) -> None:
    """显式写入某邮箱密码（用于导入存量号或人工指定）。"""
    key = _norm(email)
    if not key:
        return
    with _process_file_lock():
        store = _load_unlocked()
        store[key] = str(password or "")
        _save_unlocked(store)


def _main() -> int:
    """命令行接口，供 shell 脚本调用。

    用法：
      python account_secrets.py get-or-create <email>   # 输出该号密码(无则生成)，供注册用
      python account_secrets.py get <email>             # 输出该号密码(兜底OAI_PASSWORD)
    """
    import sys
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "get-or-create":
        sys.stdout.write(get_or_create_password(args[1]))
        return 0
    if len(args) >= 2 and args[0] == "get":
        sys.stdout.write(get_password(args[1]))
        return 0
    sys.stderr.write("用法: account_secrets.py {get-or-create|get} <email>\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main())
