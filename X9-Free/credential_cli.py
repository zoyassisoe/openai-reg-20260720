"""
获取凭证 CLI ── 完整凭证获取链路

本目录抽自原项目 `协议plus/X2.2-Windows/tools/http_auth_tool/`，
包含从 OpenAI / ChatGPT 账号"取凭证"的全部链路：

    + auth        ：HTTP 登录 + Codex OAuth 授权 → access_token / refresh_token / id_token
                    最终落到 成功凭证/<email>.json（含 token_exchange、DPAPI 加密的 refresh_token_enc 等）
    + login       ：仅做纯 HTTP 登录，写出 storage_state 和 AT 文本
    + extract-at  ：从已有的 storage_state 中提取 access_token，写到 AT文本/<email>.txt

主要入口函数：
    desktop_auth_common.run_auth_flow       —— 总入口（登录 + OAuth + 写凭证）
    desktop_auth_common.run_login_flow      —— 纯登录
    desktop_auth_common.run_extract_at_flow —— 纯 AT 提取
    codex_oauth.run_codex_oauth_flow        —— Codex OAuth 主流程
    chatgpt_login_http.run_chatgpt_http_login —— 纯 HTTP 登录

用法示例：

    # 完整凭证获取：登录 + OAuth → 成功凭证/<email>.json
    python credential_cli.py auth \\
        --email you@example.com \\
        --password "yourPwd" \\
        --use-imap-otp \\
        --imap-host imap.2925.com --imap-port 993 \\
        --imap-user you@example.com --imap-pass yourImap \\
        --trace

    # 已有 storage_state，仅做凭证升级（登录 → 凭证）
    python credential_cli.py auth \\
        --storage-state ./登录态/you@example.com.json \\
        --trace

    # 仅 HTTP 登录（产物：storage_state + AT 文本）
    python credential_cli.py login \\
        --email you@example.com --password "yourPwd" \\
        --use-imap-otp --imap-user you@example.com --imap-pass yourImap

    # 从已有 storage_state 提取 access_token
    python credential_cli.py extract-at \\
        --storage-state ./登录态/you@example.com.json \\
        --email you@example.com

产物（落到本目录，即 获取凭证/ 下，与 _toolcore/ 同级）：
    登录态/<email>.json   ── Playwright 格式 storage state（cookies + origins）
    AT文本/<email>.txt    ── 纯文本 access_token
    成功凭证/<email>.json ── 完整凭证 JSON：
        { type, email, account_id, id_token, access_token, refresh_token,
          refresh_token_enc, expired, last_refresh, chatgpt_plan_type,
          token_exchange{...}, oauth_email, status, signup_route,
          storage_state_path, at_txt_path, trace_path, ... }
    失败记录/<email>.json ── 失败时落库
    trace/<mode>_<email>_<时间戳>.jsonl ── 每一步请求/响应（--trace 开启时）
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys


def _force_utf8_console() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


_force_utf8_console()


def _bootstrap_import_path() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    toolcore = os.path.join(here, "_credential_toolcore")
    if toolcore not in sys.path:
        sys.path.insert(0, toolcore)


_bootstrap_import_path()


# 必须在 sys.path 调整之后再 import
from desktop_auth_common import (  # noqa: E402
    add_domain_mail_args,
    add_headless_arg,
    add_imap_args,
    add_login_identity_args,
    add_managed_mail_args,
    add_mfa_arg,
    add_register_identity_args,
    add_shared_network_args,
    fail_path_for,
    run_auth_flow,
    run_extract_at_flow,
    run_login_flow,
    run_register_flow,
    summarize_failure,
    summarize_success,
)


def _add_storage_state_arg(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    parser.add_argument(
        "--storage-state",
        required=required,
        default="",
        help="Playwright 格式的 storage_state JSON 路径（包含登录态 cookies）",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenAI / ChatGPT 完整凭证获取链路（auth / login / extract-at）",
    )
    sub = parser.add_subparsers(dest="mode", required=True, metavar="<mode>")

    # auth ── 总入口（登录 + OAuth + 写完整凭证 JSON）
    p_auth = sub.add_parser(
        "auth",
        help="HTTP 登录 + Codex OAuth → 完整凭证（access_token / refresh_token / id_token）",
        description="完整凭证获取链路：如果给了 --storage-state 就复用，否则先做 HTTP 登录，然后跑 Codex OAuth。",
    )
    # 邮箱在 auth 流程里不强制：可以用 storage_state 推导。所以 require_password=False
    p_auth.add_argument("--email", default="", help="账号邮箱（如复用 storage_state 可省略）")
    p_auth.add_argument("--password", default="", help="账号密码（不复用 storage_state 时必填）")
    _add_storage_state_arg(p_auth)
    add_shared_network_args(p_auth)
    add_domain_mail_args(p_auth)
    add_managed_mail_args(p_auth)
    add_imap_args(p_auth)
    add_mfa_arg(p_auth)
    add_headless_arg(p_auth)
    p_auth.add_argument(
        "--expected-workspace-id",
        default="",
        help="（可选）期望命中的 ChatGPT workspace id，多 workspace 账号下用来锁定目标",
    )

    # login ── 仅 HTTP 登录
    p_login = sub.add_parser(
        "login",
        help="仅做纯 HTTP 登录，落 storage_state + AT 文本",
        description="只做 HTTP 登录，不进 OAuth。产物：登录态/<email>.json 和 AT文本/<email>.txt。",
    )
    add_login_identity_args(p_login, require_password=True)
    add_shared_network_args(p_login)
    add_domain_mail_args(p_login)
    add_managed_mail_args(p_login)
    add_imap_args(p_login)
    add_mfa_arg(p_login)

    # register ── HTTP 注册（支持 IMAP 取码，用于 iCloud 别名共用主邮箱场景）
    p_reg = sub.add_parser(
        "register",
        help="HTTP 协议注册账号，落 storage_state（支持 IMAP / managed mail 取码）",
        description="直接走 HTTP 协议注册 ChatGPT / OpenAI 账号，产物：登录态/<email>.json。"
        "邮箱验证码取码优先级 managed_mail → imap（互斥）；只开 --use-imap-otp 即只走 IMAP。",
    )
    add_register_identity_args(p_reg)
    add_shared_network_args(p_reg)
    add_managed_mail_args(p_reg)
    add_imap_args(p_reg)
    add_mfa_arg(p_reg)

    # extract-at ── 从已有 storage_state 提取 AT
    p_ext = sub.add_parser(
        "extract-at",
        help="从已有 storage_state 提取 access_token，写到 AT文本/<email>.txt",
        description="仅从 storage_state 抽 access_token，不做任何网络登录/OAuth。",
    )
    _add_storage_state_arg(p_ext, required=True)
    p_ext.add_argument("--email", default="", help="邮箱（可省略，会从 storage_state 自动推导）")
    p_ext.add_argument(
        "--at-file",
        default="",
        help="（可选）AT 文本输出路径；缺省自动放到 AT文本/<email>.txt",
    )

    return parser


def main() -> int:
    args = _build_parser().parse_args()
    mode = str(getattr(args, "mode", "") or "").strip()
    if mode == "auth":
        result = asyncio.run(run_auth_flow(args))
    elif mode == "register":
        result = asyncio.run(run_register_flow(args))
    elif mode == "login":
        result = asyncio.run(run_login_flow(args))
    elif mode == "extract-at":
        result = asyncio.run(run_extract_at_flow(args))
    else:
        print(f"未知模式：{mode}", file=sys.stderr)
        return 2

    if result.success:
        summarize_success(result)
        return 0
    summarize_failure(result, failure_record_path=fail_path_for(result.email))
    return 1


if __name__ == "__main__":
    sys.exit(main())
