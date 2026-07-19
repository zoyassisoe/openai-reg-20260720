from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import random
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional


_CURRENT_CONTEXT: contextvars.ContextVar["HttpStageFeatureContext | None"] = contextvars.ContextVar(
    "http_stage_feature_context",
    default=None,
)


_GPU_POOL: tuple[tuple[str, str], ...] = (
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
)
_SCREEN_POOL: tuple[tuple[int, int, int, int, int], ...] = (
    (1920, 1080, 1920, 1040, 24),
    (1920, 1200, 1920, 1160, 24),
    (1536, 864, 1536, 824, 24),
    (1366, 768, 1366, 728, 24),
    (2560, 1440, 2560, 1400, 24),
)
_CHROME_MAJORS: tuple[str, ...] = ("142", "136", "137", "144", "146")
_LSUBID_PREFIXES: tuple[str, ...] = ("X10", "X19", "X42", "X55", "X73", "X81", "X96")

# 名字/生日随机生成（与 _toolcore 版同源）。凭证侧 auth 不走注册，这里主要为
# random_full_name/random_birth_date 兜底接口与 _toolcore 对齐，保证两份 register_http 逻辑一致。
_FIRST_NAMES: tuple[str, ...] = (
    "James", "Robert", "Michael", "David", "William", "Richard", "Joseph", "Thomas",
    "Daniel", "Matthew", "Andrew", "Joshua", "Christopher", "Anthony", "Kevin",
    "Emily", "Sarah", "Jessica", "Ashley", "Amanda", "Stephanie", "Jennifer", "Elizabeth",
    "Lauren", "Rachel", "Hannah", "Megan", "Samantha", "Katherine", "Nicole",
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Quinn", "Avery",
)
_LAST_NAMES: tuple[str, ...] = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Anderson", "Taylor", "Thomas", "Moore", "Jackson",
    "Martin", "Lee", "Thompson", "White", "Harris", "Clark", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Hill", "Green", "Adams",
    "Baker", "Nelson", "Carter", "Mitchell", "Roberts", "Turner", "Phillips", "Campbell",
)
_NICKNAMES: dict[str, tuple[str, ...]] = {
    "Michael": ("Mike", "Mikey"), "William": ("Will", "Bill"),
    "Robert": ("Rob", "Bob"), "Richard": ("Rick", "Rich"),
    "Joseph": ("Joe", "Joey"), "Thomas": ("Tom", "Tommy"),
    "Christopher": ("Chris",), "Daniel": ("Dan", "Danny"),
    "Matthew": ("Matt",), "Anthony": ("Tony",),
    "Jennifer": ("Jen", "Jenny"), "Elizabeth": ("Liz", "Beth"),
    "Katherine": ("Kate", "Katie"), "Jessica": ("Jess",),
    "Samantha": ("Sam",), "Stephanie": ("Steph",),
}


def _generate_name(rng: random.Random) -> str:
    first = rng.choice(_FIRST_NAMES)
    last = rng.choice(_LAST_NAMES)
    if rng.random() < 0.15 and first in _NICKNAMES:
        first = rng.choice(_NICKNAMES[first])
    if rng.random() < 0.18:
        middle = rng.choice(_FIRST_NAMES)
        while middle == first:
            middle = rng.choice(_FIRST_NAMES)
        return f"{first} {middle} {last}"
    return f"{first} {last}"


def _generate_birthday(rng: random.Random) -> str:
    years = list(range(1975, 2005))
    weights = [3 if 1985 <= y <= 1998 else (2 if 1980 <= y <= 2002 else 1) for y in years]
    year = rng.choices(years, weights=weights, k=1)[0]
    month_weights = [87, 80, 87, 85, 88, 90, 95, 97, 100, 95, 88, 87]
    month = rng.choices(range(1, 13), weights=month_weights, k=1)[0]
    max_day = 28 if month == 2 else (30 if month in (4, 6, 9, 11) else 31)
    day_weights = [10] * min(28, max_day) + ([6] * (max_day - 28) if max_day > 28 else [])
    day = rng.choices(range(1, max_day + 1), weights=day_weights, k=1)[0]
    return f"{year:04d}-{month:02d}-{day:02d}"


def random_full_name() -> str:
    """对外兜底：返回一个随机真人姓名，保证绝不返回空名。"""
    return _generate_name(random.Random(secrets.randbits(64)))


def random_birth_date() -> str:
    """对外兜底：返回一个随机生日。"""
    return _generate_birthday(random.Random(secrets.randbits(64)))


def _repo_root() -> Path:
    try:
        here = Path(__file__).resolve()
        toolcore_dir = here.parent
        if toolcore_dir.name != "_toolcore":
            return toolcore_dir
        direct_parent = toolcore_dir.parent
        # X9 结构：X9/_toolcore
        if (direct_parent / "register_cli.py").is_file() and (direct_parent / "credential_cli.py").is_file():
            return direct_parent
        # protocal 结构：protocal/tools/http_auth_tool/_toolcore
        if direct_parent.name == "http_auth_tool" and len(direct_parent.parents) >= 2:
            return direct_parent.parents[1]
        return direct_parent
    except Exception:
        return Path.cwd()


def _safe_name(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", str(text or "").strip().lower()) or "unknown"


def _profile_path(email: str, flow: str) -> Path:
    root = _repo_root() / "tmp" / "http_stage_features"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{_safe_name(flow)}_{_safe_name(email)}.json"


def _seeded_rng(email: str, flow: str, salt: str = "") -> random.Random:
    seed_bytes = hashlib.sha256(f"{flow}|{email}|{salt}".encode("utf-8", errors="ignore")).digest()
    return random.Random(int.from_bytes(seed_bytes[:8], "big"))


def _new_lsubid(prefix: str) -> str:
    return f"{prefix}-{secrets.randbelow(10_000_000):07d}-{secrets.randbelow(10_000_000):07d}:{int(time.time())}"


def _new_profile(email: str, flow: str) -> dict[str, Any]:
    rng = _seeded_rng(email, flow, secrets.token_hex(8))
    chrome_major = rng.choice(_CHROME_MAJORS)
    gpu_vendor, gpu_model = rng.choice(_GPU_POOL)
    screen = rng.choice(_SCREEN_POOL)
    prefix_signin = rng.choice(_LSUBID_PREFIXES)
    prefix_profile = rng.choice(_LSUBID_PREFIXES)
    return {
        "emailKey": str(email or "").strip().lower(),
        "flow": str(flow or "http").strip().lower() or "http",
        "createdAt": time.time(),
        "deviceId": str(uuid.uuid4()),
        "chromeMajor": chrome_major,
        "userAgent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{chrome_major}.0.0.0 Safari/537.36"
        ),
        "secChUa": f'"Chromium";v="{chrome_major}", "Not-A.Brand";v="24", "Google Chrome";v="{chrome_major}"',
        "secChUaMobile": "?0",
        "secChUaPlatform": '"Windows"',
        "gpuVendor": gpu_vendor,
        "gpuModel": gpu_model,
        "screen": {
            "width": screen[0],
            "height": screen[1],
            "availWidth": screen[2],
            "availHeight": screen[3],
            "colorDepth": screen[4],
        },
        "canvasHash": rng.randint(-2_147_000_000, 2_147_000_000),
        "math": {
            "tan": "-1.4214488238747245",
            "sin": "0.8178819121159085",
            "cos": rng.choice(("-0.5753861119575491", "-0.5765775004286854")),
        },
        "lsubidSignin": _new_lsubid(prefix_signin),
        "lsubidProfile": _new_lsubid(prefix_profile),
    }


def _load_or_create_profile(email: str, flow: str) -> dict[str, Any]:
    path = _profile_path(email, flow)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    if isinstance(payload, dict) and payload.get("deviceId") and payload.get("userAgent"):
        return payload
    payload = _new_profile(email, flow)
    try:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass
    return payload


@dataclass
class HttpStageFeatureContext:
    email: str
    flow: str
    profile: dict[str, Any]
    stage: str = "init"
    stage_started_at: float = field(default_factory=time.monotonic)

    @property
    def device_id(self) -> str:
        return str(self.profile.get("deviceId") or "").strip()

    def set_stage(self, stage: str) -> None:
        normalized = str(stage or "").strip() or "request"
        if normalized != self.stage:
            self.stage = normalized
            self.stage_started_at = time.monotonic()

    def browser_headers(self, *, impersonate: str = "") -> dict[str, str]:
        major = str(self.profile.get("chromeMajor") or "").strip()
        matched = re.search(r"chrome(\d+)", str(impersonate or "").strip().lower())
        if matched:
            major = str(matched.group(1) or major).strip()
        ua = str(self.profile.get("userAgent") or "").strip()
        sec_ch_ua = str(self.profile.get("secChUa") or "").strip()
        if major and matched:
            ua = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{major}.0.0.0 Safari/537.36"
            )
            sec_ch_ua = f'"Chromium";v="{major}", "Not-A.Brand";v="24", "Google Chrome";v="{major}"'
        return {
            "user-agent": ua,
            "sec-ch-ua": sec_ch_ua,
            "sec-ch-ua-mobile": str(self.profile.get("secChUaMobile") or "?0"),
            "sec-ch-ua-platform": str(self.profile.get("secChUaPlatform") or '"Windows"'),
        }

    def stage_summary(self) -> dict[str, Any]:
        return {
            "flow": self.flow,
            "stage": self.stage,
            "deviceIdPresent": bool(self.device_id),
            "chromeMajor": str(self.profile.get("chromeMajor") or ""),
            "canvasHash": self.profile.get("canvasHash"),
            "gpuVendor": self.profile.get("gpuVendor"),
            "screen": self.profile.get("screen") if isinstance(self.profile.get("screen"), dict) else {},
            "stageElapsedMs": int(max(0.0, time.monotonic() - self.stage_started_at) * 1000.0),
        }


@contextlib.contextmanager
def http_stage_feature_session(email: str, flow: str) -> Iterator[HttpStageFeatureContext]:
    ctx = HttpStageFeatureContext(
        email=str(email or "").strip().lower(),
        flow=str(flow or "http").strip().lower() or "http",
        profile=_load_or_create_profile(email, flow),
    )
    token = _CURRENT_CONTEXT.set(ctx)
    try:
        yield ctx
    finally:
        _CURRENT_CONTEXT.reset(token)


def current_http_stage_feature_context() -> Optional[HttpStageFeatureContext]:
    return _CURRENT_CONTEXT.get()


def activate_http_stage_feature_session(email: str, flow: str) -> HttpStageFeatureContext:
    ctx = HttpStageFeatureContext(
        email=str(email or "").strip().lower(),
        flow=str(flow or "http").strip().lower() or "http",
        profile=_load_or_create_profile(email, flow),
    )
    _CURRENT_CONTEXT.set(ctx)
    return ctx


def set_http_stage_feature_stage(stage: str) -> None:
    ctx = current_http_stage_feature_context()
    if ctx is not None:
        ctx.set_stage(stage)


def get_http_stage_browser_headers(*, impersonate: str = "") -> dict[str, str]:
    ctx = current_http_stage_feature_context()
    return ctx.browser_headers(impersonate=impersonate) if ctx is not None else {}


def get_http_stage_device_id() -> str:
    ctx = current_http_stage_feature_context()
    return ctx.device_id if ctx is not None else ""


def get_http_stage_feature_summary() -> dict[str, Any]:
    ctx = current_http_stage_feature_context()
    return ctx.stage_summary() if ctx is not None else {}
