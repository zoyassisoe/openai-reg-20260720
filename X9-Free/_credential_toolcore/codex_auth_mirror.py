from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Optional


CODEX_AUTH_MIRROR_DIR_ENV = "AIO_CODEX_AUTH_MIRROR_DIR"


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _default_codex_auth_mirror_dir() -> Path:
    if os.name == "nt":
        return (_project_root() / "auth_states" / "codex_mirror").resolve()
    return Path("/code/CLIProxyAPI/auths")


def get_codex_auth_mirror_dir() -> Path:
    """
    功能目的：
        返回 Codex 认证文件的额外镜像目录。

    说明：
        - 默认镜像到 `/code/CLIProxyAPI/auths`；
        - 测试场景允许通过环境变量覆盖，避免写入真实目录。
    """

    default_dir = _default_codex_auth_mirror_dir()
    raw = str(os.getenv(CODEX_AUTH_MIRROR_DIR_ENV, str(default_dir)) or "").strip()
    if not raw:
        raw = str(default_dir)
    return Path(raw).expanduser()


def build_codex_auth_mirror_path(*, source_path: str | Path) -> Path:
    """
    功能目的：
        根据主认证文件路径推导镜像文件路径。
    """

    raw = str(source_path or "").strip()
    if not raw:
        raise ValueError("Codex 认证文件路径为空，无法构建镜像路径。")
    source = Path(raw).expanduser()
    filename = str(source.name or "").strip()
    if not filename:
        raise ValueError("Codex 认证文件名为空，无法构建镜像路径。")
    return get_codex_auth_mirror_dir() / filename


def _paths_equivalent(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except Exception:
        return left.as_posix() == right.as_posix()


def _write_text_atomic(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp_path.write_text(text, encoding=encoding)
        tmp_path.replace(path)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def sync_codex_auth_text(
    *,
    source_path: str | Path,
    text: str,
    encoding: str = "utf-8",
) -> tuple[Optional[Path], str]:
    """
    功能目的：
        将主认证文件内容同步到额外镜像目录。

    返回：
        (镜像路径, 错误信息)
    """

    try:
        mirror_path = build_codex_auth_mirror_path(source_path=source_path)
    except Exception as error:
        return None, str(error)

    source = Path(str(source_path).strip()).expanduser()
    if _paths_equivalent(source, mirror_path):
        return mirror_path, ""

    try:
        _write_text_atomic(mirror_path, text, encoding=encoding)
        return mirror_path, ""
    except Exception as error:
        return None, str(error)


def write_codex_auth_text(
    *,
    path: str | Path,
    text: str,
    encoding: str = "utf-8",
) -> tuple[Path, Optional[Path], str]:
    """
    功能目的：
        写入主 Codex 认证文件，并额外同步镜像目录。

    返回：
        (主路径, 镜像路径, 镜像错误信息)
    """

    raw = str(path or "").strip()
    if not raw:
        raise ValueError("Codex 认证文件路径为空。")
    primary_path = Path(raw).expanduser()
    _write_text_atomic(primary_path, text, encoding=encoding)
    mirror_path, mirror_error = sync_codex_auth_text(source_path=primary_path, text=text, encoding=encoding)
    return primary_path, mirror_path, mirror_error


def write_codex_auth_json(*, path: str | Path, payload: dict[str, Any]) -> tuple[Path, Optional[Path], str]:
    """
    功能目的：
        以 JSON 格式写入主 Codex 认证文件，并额外同步镜像目录。
    """

    text = json.dumps(payload, ensure_ascii=False, indent=2)
    return write_codex_auth_text(path=path, text=text, encoding="utf-8")


def sync_codex_auth_file(*, source_path: str | Path, encoding: str = "utf-8") -> tuple[Optional[Path], str]:
    """
    功能目的：
        读取主目录中的现有 Codex 认证文件，并同步到镜像目录。

    说明：
        - 用于补齐历史文件或兜底修复漏同步场景；
        - 不修改主文件内容，只按当前文件内容覆盖镜像。
    """

    raw = str(source_path or "").strip()
    if not raw:
        return None, "Codex 主认证文件路径为空。"

    source = Path(raw).expanduser()
    if not source.exists():
        return None, f"Codex 主认证文件不存在：{source}"

    try:
        text = source.read_text(encoding=encoding)
    except Exception as error:
        return None, str(error)
    return sync_codex_auth_text(source_path=source, text=text, encoding=encoding)


def sync_codex_auth_directory(
    *,
    source_dir: str | Path,
    pattern: str = "codex-*.json",
    encoding: str = "utf-8",
) -> dict[str, Any]:
    """
    功能目的：
        将主目录下现有的 Codex 认证文件批量同步到镜像目录。

    返回：
        {
          "scanned": int,
          "synced": int,
          "failed": int,
          "errors": [{path, error}, ...],
        }
    """

    raw = str(source_dir or "").strip()
    if not raw:
        return {"scanned": 0, "synced": 0, "failed": 0, "errors": []}

    source_root = Path(raw).expanduser()
    if not source_root.exists():
        return {"scanned": 0, "synced": 0, "failed": 0, "errors": []}

    scanned = 0
    synced = 0
    failed = 0
    errors: list[dict[str, str]] = []
    try:
        candidates = sorted(source_root.glob(pattern))
    except Exception as error:
        return {
            "scanned": 0,
            "synced": 0,
            "failed": 1,
            "errors": [{"path": str(source_root), "error": str(error)}],
        }

    for candidate in candidates:
        scanned += 1
        mirror_path, error = sync_codex_auth_file(source_path=candidate, encoding=encoding)
        if error:
            failed += 1
            errors.append({"path": str(candidate), "error": str(error)})
            continue
        if mirror_path is not None:
            synced += 1

    return {"scanned": scanned, "synced": synced, "failed": failed, "errors": errors}


def remove_codex_auth_mirror(*, source_path: str | Path) -> tuple[Optional[Path], str]:
    """
    功能目的：
        删除与主认证文件同名的镜像文件。

    返回：
        (镜像路径, 错误信息)
    """

    raw = str(source_path or "").strip()
    if not raw:
        return None, ""

    try:
        mirror_path = build_codex_auth_mirror_path(source_path=raw)
    except Exception as error:
        return None, str(error)

    try:
        mirror_path.unlink(missing_ok=True)
    except TypeError:
        try:
            if mirror_path.exists():
                mirror_path.unlink()
        except Exception as error:
            return None, str(error)
    except Exception as error:
        return None, str(error)
    return mirror_path, ""
