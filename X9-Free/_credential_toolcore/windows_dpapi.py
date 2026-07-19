"""
???????
    - Windows DPAPI ????????????? Windows ?????????
    - ?? Windows ????????????????????? Linux ?????

?????
    - Windows ?? DPAPI ?????????????
    - Linux / ? Windows ????????????????????????????
    - ???????????????????????????????
"""

from __future__ import annotations

import base64
import ctypes
import os

try:
    from ctypes import wintypes
except Exception:  # pragma: no cover - ????????????
    wintypes = None  # type: ignore[assignment]


class DpapiUnavailableError(RuntimeError):
    """???????? Windows DPAPI?"""


_DWORD = wintypes.DWORD if wintypes is not None else ctypes.c_uint32


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", _DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


DPAPI_AVAILABLE = os.name == "nt" and hasattr(ctypes, "windll")

if DPAPI_AVAILABLE:
    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        _DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        _DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL

    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
else:
    _crypt32 = None
    _kernel32 = None


# ???????????????????????????????
_AIO_ENTROPY = b"AIO_TEAM_POOL_V1"


def is_available() -> bool:
    """??????????? Windows DPAPI?"""

    return bool(DPAPI_AVAILABLE and _crypt32 is not None and _kernel32 is not None)


def _ensure_available() -> None:
    if is_available():
        return
    raise DpapiUnavailableError("??????? Windows DPAPI???????????????")


def _make_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    return blob, buf


def protect_bytes(data: bytes) -> bytes:
    """?? Windows DPAPI ??????"""

    if data is None:
        raise ValueError("data ?????")
    _ensure_available()

    in_blob, _in_buf = _make_blob(bytes(data))
    entropy_blob, _entropy_buf = _make_blob(_AIO_ENTROPY)
    out_blob = _DataBlob()

    ok = bool(
        _crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            0,
            ctypes.byref(out_blob),
        )
    )
    if not ok:
        raise ctypes.WinError()

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            _kernel32.LocalFree(out_blob.pbData)


def unprotect_bytes(cipher: bytes) -> bytes:
    """?? Windows DPAPI ??????"""

    if cipher is None:
        raise ValueError("cipher ?????")
    _ensure_available()

    in_blob, _in_buf = _make_blob(bytes(cipher))
    entropy_blob, _entropy_buf = _make_blob(_AIO_ENTROPY)
    out_blob = _DataBlob()

    ok = bool(
        _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            0,
            ctypes.byref(out_blob),
        )
    )
    if not ok:
        raise ctypes.WinError()

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            _kernel32.LocalFree(out_blob.pbData)


def encrypt_text(text: str) -> str:
    """?????????? JSON ? base64 ????"""

    raw = str(text or "")
    if not raw:
        return ""
    cipher = protect_bytes(raw.encode("utf-8"))
    return base64.b64encode(cipher).decode("ascii")


def decrypt_text(cipher_b64: str) -> str:
    """? base64 ????? UTF-8 ???"""

    raw = str(cipher_b64 or "").strip()
    if not raw:
        return ""
    cipher = base64.b64decode(raw.encode("ascii"))
    plain = unprotect_bytes(cipher)
    return plain.decode("utf-8", errors="strict")
