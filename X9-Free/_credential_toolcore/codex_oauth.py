"""
Codex OAuth（PKCE）自动化登录与认证文件保存（Drission only）。

设计目标：
    - 保留现有 OAuth2 + PKCE + 本地/共享回调监听 + token 换取 + 认证文件落盘链路；
    - 浏览器层全面切到 DrissionPage，不再依赖 Playwright；
    - 遇到 Cloudflare / MFA / 验证码时允许人工介入，不实现任何绕过逻辑。
"""

from __future__ import annotations

import ast
import asyncio
import base64
import copy
import datetime
import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

import requests

from codex_auth_mirror import write_codex_auth_json

try:
    from DrissionPage import Chromium, ChromiumOptions
except Exception:
    Chromium = None  # type: ignore[assignment]
    ChromiumOptions = None  # type: ignore[assignment]
try:
    from DrissionPage.common import Keys
except Exception:
    Keys = None  # type: ignore[assignment]

try:
    from windows_dpapi import encrypt_text
except Exception:
    encrypt_text = None  # type: ignore[assignment]

try:
    from playwright.async_api import async_playwright
except Exception:
    async_playwright = None  # type: ignore[assignment]
try:
    from curl_cffi import requests as curl_cffi_requests
except Exception:
    curl_cffi_requests = None  # type: ignore[assignment]

from imap_2925 import Imap2925Config, poll_imap_for_verification_code
from managed_mail_otp import poll_managed_mail_verification_code_sync
from domain_mail_otp import poll_domain_mail_verification_code_sync
from code_utils import defaultCodeKeywords, extractVerificationCode, extractVerificationTimestamp
from totp_utils import generate_totp_code, normalize_totp_secret, totp_seconds_remaining
from http_phone_verification import (
    ManualPhoneControlTimeoutError,
    ManualPhoneReplacedError,
    acquire_http_phone_candidate,
    acquire_pending_http_phone_candidate,
    blacklist_http_phone,
    dispose_http_phone_after_failure,
    cooldown_http_phone,
    is_manual_http_phone,
    is_phone_provider_unusable,
    mark_http_phone_completed,
    mark_http_phone_completed_for_owner,
    report_http_phone_failure,
    wait_for_http_phone_code,
)
from http_stage_features import (
    activate_http_stage_feature_session,
    get_http_stage_browser_headers,
    get_http_stage_device_id,
    get_http_stage_feature_summary,
    set_http_stage_feature_stage,
)


AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_PUBLIC_CALLBACK_PORT = 1455
DEFAULT_CALLBACK_PORT = 2455
DEFAULT_CALLBACK_SCHEME = 'http'
DEFAULT_CALLBACK_HOST = 'localhost'
CALLBACK_PATH = '/auth/callback'
DEFAULT_REDIRECT_URI = f"{DEFAULT_CALLBACK_SCHEME}://{DEFAULT_CALLBACK_HOST}:{DEFAULT_PUBLIC_CALLBACK_PORT}{CALLBACK_PATH}"
DEFAULT_CALLBACK_BIND_HOST = "0.0.0.0"
CLIENT_ID = DEFAULT_CLIENT_ID
REDIRECT_URI = DEFAULT_REDIRECT_URI

_HTTP_BROWSER_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/146.0.7680.80 Safari/537.36'
)
_HTTP_BROWSER_SEC_CH_UA = '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"'
_HTTP_BROWSER_SEC_CH_UA_MOBILE = '?0'
_HTTP_BROWSER_SEC_CH_UA_PLATFORM = '"Windows"'
_HTTP_BROWSER_ACCEPT_LANGUAGE = 'en-US,en;q=0.9'
_HTTP_BROWSER_ACCEPT_ENCODING = 'gzip, deflate, br, zstd'
_HTTP_BROWSER_FETCH_PRIORITY = 'u=1, i'
_HTTP_WORKSPACE_SELECT_CURL_IMPERSONATES: tuple[str, ...] = ('chrome142', 'chrome136', 'chrome133a', 'chrome131')
_HTTP_WORKSPACE_SELECT_CURL_PERSONAL_IMPERSONATES: tuple[str, ...] = ('chrome142', 'chrome136', 'chrome133a', 'chrome131')
_HTTP_SENTINEL_INIT_FLOW = 'login_web_init'
_HTTP_SENTINEL_FRAME_URL_PREFIX = 'https://sentinel.openai.com/backend-api/sentinel/frame.html'
_HTTP_SENTINEL_SDK_FALLBACK_URL = 'https://sentinel.openai.com/backend-api/sentinel/sdk.js'
_HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW = 'authorize_continue'
_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW = 'password_verify'
_HTTP_REGISTER_PASSWORD_SENTINEL_FLOW = 'username_password_create'
_HTTP_REGISTER_PROFILE_SENTINEL_FLOW = 'oauth_create_account'
_HTTP_REGISTER_SENTINEL_FLOWS: frozenset[str] = frozenset(
    {
        _HTTP_REGISTER_PASSWORD_SENTINEL_FLOW,
        _HTTP_REGISTER_PROFILE_SENTINEL_FLOW,
    }
)
_HTTP_SENTINEL_HELPER_TARGET_URLS: tuple[str, ...] = (
    'https://auth.openai.com/log-in',
    'https://auth.openai.com/log-in/password',
)
_HTTP_SENTINEL_REGISTER_HELPER_TARGET_URLS: tuple[str, ...] = (
    'https://auth.openai.com/create-account',
    'https://auth.openai.com/create-account/password',
    'https://auth.openai.com/create-account/about-you',
)
_HTTP_TRANSIENT_ERROR_MARKERS: tuple[str, ...] = (
    'tls connect',
    'ssl',
    'timeout',
    'timed out',
    'connection reset',
    'connection aborted',
    'remote end closed',
    'temporarily unavailable',
    'could not resolve',
    "couldn't connect",
    'failed to connect',
    'name resolution',
    'network is unreachable',
    'connection refused',
    'recv failure',
    'http/2 stream',
    'curl: (28)',
    'curl: (35)',
    'curl: (52)',
    'curl: (56)',
    '(28)',
    '(35)',
    '(52)',
    '(56)',
)


def _http_retry_attempts() -> int:
    raw = os.environ.get('CODEX_OAUTH_HTTP_RETRIES') or os.environ.get('CHATGPT_API_HTTP_RETRIES') or '3'
    try:
        return max(1, min(10, int(float(str(raw).strip()))))
    except Exception:
        return 3


def _http_retry_delay_seconds(attempt: int) -> float:
    raw = os.environ.get('CODEX_OAUTH_HTTP_RETRY_BACKOFF_SECONDS') or os.environ.get(
        'CHATGPT_API_HTTP_RETRY_BACKOFF_SECONDS',
        '0.5',
    )
    try:
        base = max(0.05, min(10.0, float(str(raw).strip())))
    except Exception:
        base = 0.5
    return min(8.0, base * (2 ** max(0, int(attempt) - 1)))


def _is_transient_http_exception(error: BaseException) -> bool:
    text = f'{type(error).__name__}: {error}'.lower()
    return any(marker in text for marker in _HTTP_TRANSIENT_ERROR_MARKERS)

_EMAIL_SELECTORS: tuple[str, ...] = (
    'input#email',
    'input[type="email"]',
    'input[name="email"]',
    'input[name="username"]',
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[inputmode="email"]',
    'input[type="text"][name*="email" i]',
    'input[type="text"][id*="email" i]',
)
_PASSWORD_SELECTORS: tuple[str, ...] = (
    'input[type="password"]',
    'input[name="password"]',
    'input[autocomplete="current-password"]',
    'input[autocomplete="new-password"]',
    'input[id*="password" i]',
    'input[name*="password" i]',
)
_OTP_SELECTORS: tuple[str, ...] = (
    'input[autocomplete="one-time-code"]',
    'input[inputmode="numeric"]',
    'input[name*="code" i]',
    'input[id*="code" i]',
    'input[name*="otp" i]',
    'input[id*="otp" i]',
)

_EMAIL_ENTRY_TEXTS: tuple[str, ...] = (
    'continue with email',
    'use email',
    'email',
    '邮箱',
    '使用邮箱',
)
_SIGNUP_LINK_TEXTS: tuple[str, ...] = (
    'sign up',
    'create account',
    'create your account',
    'get started',
    '注册',
    '创建账号',
    '创建账户',
)
_PROFILE_NAME_SELECTORS: tuple[str, ...] = (
    'input[name="name"]',
    'input[autocomplete="name"]',
    'input[placeholder*="name" i]',
    'input[id*="name" i]',
)
_PROFILE_BIRTH_SELECTORS: tuple[str, ...] = (
    'input[type="date"]',
    'input[name*="birth" i]',
    'input[id*="birth" i]',
    'input[autocomplete="bday"]',
)
_GENERIC_CONTINUE_TEXTS: tuple[str, ...] = (
    'continue',
    'next',
    'submit',
    'log in',
    'sign in',
    '继续',
    '下一步',
    '提交',
    '登录',
)
_PASSWORD_SUBMIT_TEXTS: tuple[str, ...] = (
    'continue',
    'sign in',
    'log in',
    '继续',
    '登录',
)
_OTP_SUBMIT_TEXTS: tuple[str, ...] = (
    'verify',
    'continue',
    'submit',
    '验证',
    '继续',
    '提交',
)
_OTP_RESEND_TEXTS: tuple[str, ...] = (
    'resend verification code',
    'resend code',
    'resend email',
    'send again',
    'get a new code',
    "didn't receive a code",
    '重新获取验证码',
    '重新发送验证码',
    '重新发送',
    '再次发送',
    '获取新验证码',
)
_MAX_AUTO_OTP_RESENDS = 2
_OTP_IMAP_NOT_BEFORE_GRACE_SEC = 120.0
_OTP_AUTO_POLL_ACTION_INTERVAL_SEC = 6.0
# 说明：HTTP passwordless OTP 邮件经常在发送后数秒才进入 IMAP，窗口太短会导致误判超时。
_OTP_IMAP_SINGLE_POLL_TIMEOUT_CAP_SEC = 15.0
_OTP_IMAP_POST_SEND_GRACE_SEC = 8.0
_WORKSPACE_STAGE_ACTION_INTERVAL_SEC = 1.0
_AUTHORIZE_STAGE_ACTION_INTERVAL_SEC = 1.0
_WORKSPACE_STAGE_CLICK_SCROLL_PASSES = 10
_AUTHORIZE_STAGE_CLICK_SCROLL_PASSES = 10
_FAST_STAGE_BUTTON_RETRY_DELAYS_SEC: tuple[float, ...] = (0.0, 0.2, 0.5, 0.8)
_WORKSPACE_POST_SELECT_SCROLL_RETRY_DELAYS_SEC: tuple[float, ...] = (0.0, 0.1, 0.22, 0.45)
_WORKSPACE_POST_SELECT_SCROLL_PASSES_PER_ROUND = 2
_WORKSPACE_SELECTION_RETRY_DELAYS_SEC: tuple[float, ...] = (0.0, 0.08, 0.18)
_WORKSPACE_REAL_CLICK_SETTLE_TIMEOUT_SEC = 2.8
_WORKSPACE_REAL_CLICK_POLL_INTERVAL_SEC = 0.35
_FAST_STAGE_LOOP_SLEEP_SEC = 0.35
_AUTHORIZE_BUTTON_TEXTS: tuple[str, ...] = (
    'allow',
    'authorize',
    'accept',
    'continue',
    '允许',
    '授权',
    '同意',
    '继续',
)
_WORKSPACE_BUTTON_TEXTS: tuple[str, ...] = (
    'continue',
    'open',
    'use workspace',
    'continue to chatgpt',
    '继续',
    '打开',
    '进入',
)
_CHATGPT_ROLE_PROMPT_TEXT_MARKERS: tuple[str, ...] = (
    '你从事哪种工作',
    'what type of work do you do',
    '选择最符合的选项',
)
_CHATGPT_ROLE_OPTION_TEXTS: tuple[str, ...] = (
    '工程',
    'engineering',
    '其他',
    'other',
)
_CHATGPT_WORK_APPS_TEXT_MARKERS: tuple[str, ...] = (
    '选择你的工作应用',
    'choose your work apps',
    '已为你的工作空间启用这些应用',
    'enabled these apps for your workspace',
    '继续前往工作空间',
    'continue to workspace',
)
_CHATGPT_WORK_APPS_SKIP_TEXTS: tuple[str, ...] = (
    '跳过',
    'skip',
)
_CHATGPT_HOME_WORKSPACE_TEXT_MARKERS: tuple[str, ...] = (
    '你的 chatgpt business 工作空间已就绪',
    'your chatgpt business workspace is ready',
    '要将你的历史聊天记录和 gpt 转移到 business 工作空间吗',
    'do you want to move your chats and gpts to the business workspace',
    '转移历史聊天记录和 gpt',
    'transfer your chats and gpts',
    '从空工作空间开始',
    'start with an empty workspace',
)
_CHATGPT_HOME_MIGRATION_OPTION_TEXTS: tuple[str, ...] = (
    '从空工作空间开始',
    'start with an empty workspace',
    '转移历史聊天记录和 gpt',
    'transfer your chats and gpts',
)
_CHATGPT_HOME_WORKSPACE_PERSONAL_KEYWORDS: tuple[str, ...] = (
    'personal',
    '个人',
    'account',
    '帐户',
    '账户',
)
_CHATGPT_HOME_WORKSPACE_MENU_BLOCKED_KEYWORDS: tuple[str, ...] = (
    'upgrade',
    'upgrade plan',
    'pricing',
    'billing',
    'my plan',
    'manage plan',
    'settings',
    'help',
    'logout',
    'log out',
    '升级',
    '定价',
    '账单',
    '设置',
    '帮助',
    '退出登录',
)
_CHATGPT_HOME_STAGE_ACTION_INTERVAL_SEC = 1.0
_OPENAI_HOME_STAGE_ACTION_INTERVAL_SEC = 2.0
_OPENAI_HOME_REOPEN_AFTER_SEC = 2.5
_OPENAI_HOME_REOPEN_MAX = 2

_OPENAI_MARKETING_HOME_TEXT_MARKERS: tuple[str, ...] = (
    'openai 主页',
    'openai home',
    '试用 chatgpt',
    'try chatgpt',
    '研究',
    'research',
    '产品',
    'products',
    '开发人员',
    'developers',
    '公司',
    'foundation',
    '基金会',
)

_BLOCK_PAGE_MARKERS: tuple[str, ...] = (
    'just a moment',
    'performing security verification',
    'cloudflare',
    'verify you are human',
    'attention required',
    'enable javascript and cookies to continue',
    'cf_chl',
    'challenge-error-text',
)
_LOADING_PAGE_MARKERS: tuple[str, ...] = (
    'please wait',
    '请稍候',
    '/api/oauth/oauth2/auth',
)
_ERROR_TEXT_MARKERS: tuple[str, ...] = (
    'unsupported_country_region_territory',
    'country, region, or territory not supported',
    'request_forbidden',
    'authapifailure',
    'unknown_error',
)
_RETRYABLE_ERROR_TEXT_MARKERS: tuple[str, ...] = (
    'oops, an error occurred',
    'oops an error occurred',
    'something went wrong',
    'operation timed out',
    'request timed out',
    'network error',
)
_RETRYABLE_ERROR_BUTTON_TEXTS: tuple[str, ...] = (
    'try again',
    'retry',
    '重试',
    '再试一次',
    '重新尝试',
)
_RETRYABLE_ERROR_STAGE_ACTION_INTERVAL_SEC = 2.0
_RETRYABLE_ERROR_REOPEN_AFTER_SEC = 8.0
_RETRYABLE_ERROR_FAIL_AFTER_SEC = 30.0
_RETRYABLE_ERROR_MAX_RELOADS = 1
_CHALLENGE_AUTO_TAB_PRESS_MAX = 10
_CHALLENGE_AUTO_TAB_ENTER_MAX_ATTEMPTS = 3
_CHALLENGE_AUTO_TAB_ENTER_RETRY_INTERVAL_SEC = 8.0
_OTP_TEXT_MARKERS: tuple[str, ...] = (
    'verification code',
    'one-time code',
    'check your inbox',
    'enter code',
    'email code',
    '验证码',
    '输入验证码',
    '检查您的收件箱',
)
_WORKSPACE_TEXT_MARKERS: tuple[str, ...] = (
    'workspace',
    'select workspace',
    'choose a workspace',
    'pick a workspace',
    'organization',
    '工作区',
    '团队',
)
_AUTHORIZE_TEXT_MARKERS: tuple[str, ...] = (
    'authorize',
    'allow',
    'grant access',
    'consent',
    '授权',
    '允许',
    '同意',
)
_DEFAULT_OTP_KEYWORDS: tuple[str, ...] = (
    'ChatGPT',
    'OpenAI',
    '验证码',
    'verification',
    'verify',
    'code',
    '安全代码',
)
_OTP_INVALID_MARKERS: tuple[str, ...] = (
    'code is incorrect',
    'code is invalid',
    'wrong_email_otp_code',
    'incorrect code',
    '验证码错误',
    '验证码无效',
)
_HTTP_SENTINEL_TOKEN_SDK_MISSING = '{"e":"q2n8w7x5z1"}'
_HTTP_SENTINEL_TOKEN_TOKEN_FAILED = '{"e":"k9d4s6v3b2"}'

_PAGE_SNAPSHOT_JS = r'''
const payload = arguments[0] || {};
const emailSelectors = Array.isArray(payload.emailSelectors) ? payload.emailSelectors : [];
const passwordSelectors = Array.isArray(payload.passwordSelectors) ? payload.passwordSelectors : [];
const otpSelectors = Array.isArray(payload.otpSelectors) ? payload.otpSelectors : [];
function visible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.visibility === 'hidden' || style.display === 'none') return false;
  if (el.disabled) return false;
  return !!(el.offsetParent || el.getClientRects().length);
}
function firstVisible(selectors) {
  for (const sel of selectors || []) {
    try {
      const nodes = Array.from(document.querySelectorAll(sel));
      for (const node of nodes) {
        if (visible(node)) return true;
      }
    } catch (_) {}
  }
  return false;
}
function textOf(el) {
  return String(el.innerText || el.value || el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim();
}
const bodyText = String(document.body ? (document.body.innerText || document.body.textContent || '') : '');
const buttonTexts = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"], input[type="button"]'))
  .filter(visible)
  .slice(0, 20)
  .map(textOf)
  .filter(Boolean);
const frameUrls = Array.from(document.querySelectorAll('iframe'))
  .slice(0, 10)
  .map((el) => String(el.src || el.getAttribute('src') || '').trim())
  .filter(Boolean);
return {
  url: String(location.href || ''),
  title: String(document.title || ''),
  bodyText: bodyText.replace(/\s+/g, ' ').trim().slice(0, 5000),
  emailVisible: firstVisible(emailSelectors),
  passwordVisible: firstVisible(passwordSelectors),
  otpVisible: firstVisible(otpSelectors),
  buttonTexts,
  frameUrls,
};
'''

_SET_INPUT_JS = r'''
const payload = arguments[0] || {};
const selectors = Array.isArray(payload.selectors) ? payload.selectors : [];
const nextValue = String(payload.value ?? '');
function visible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.visibility === 'hidden' || style.display === 'none') return false;
  if (el.disabled) return false;
  return !!(el.offsetParent || el.getClientRects().length);
}
function setValue(el, value) {
  const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
  if (descriptor && descriptor.set) {
    descriptor.set.call(el, value);
  } else {
    el.value = value;
  }
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}
for (const sel of selectors || []) {
  try {
    const nodes = Array.from(document.querySelectorAll(sel));
    for (const node of nodes) {
      if (!visible(node)) continue;
      try { node.focus(); } catch (_) {}
      setValue(node, nextValue);
      try { node.blur(); } catch (_) {}
      return { ok: true, selector: sel };
    }
  } catch (_) {}
}
return { ok: false };
'''

_CLICK_TEXT_JS = r'''
const payload = arguments[0] || {};
const patterns = Array.isArray(payload.patterns) ? payload.patterns : [];
const lowers = Array.isArray(patterns) ? patterns.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean) : [];
const maxScrollPasses = Math.max(0, Number(payload.maxScrollPasses || 0) || 0);
const fallbackToPrimaryAction = !!payload.fallbackToPrimaryAction;
const blockedLowers = Array.isArray(payload.blockedPatterns)
  ? payload.blockedPatterns.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : ['cancel', 'back', 'previous', 'logout', 'sign out', 'personal', 'privacy', 'terms', 'learn more', 'close', '取消', '返回', '上一步', '退出', '个人', '隐私', '条款', '了解更多', '关闭'];
function visible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.visibility === 'hidden' || style.display === 'none' || style.pointerEvents === 'none') return false;
  if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
  return !!(el.offsetParent || el.getClientRects().length);
}
function textOf(el) {
  return String(el.innerText || el.value || el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim();
}
function lowerTextOf(el) {
  return textOf(el).toLowerCase();
}
function canScroll(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.display === 'none' || style.visibility === 'hidden') return false;
  return (el.scrollHeight - el.clientHeight) > 24;
}
function interactableAtCenter(el) {
  if (!el) return false;
  try {
    const rect = el.getBoundingClientRect();
    if (!rect || rect.width <= 0 || rect.height <= 0) return false;
    const x = Math.min(window.innerWidth - 2, Math.max(2, rect.left + (rect.width / 2)));
    const y = Math.min(window.innerHeight - 2, Math.max(2, rect.top + (rect.height / 2)));
    const topNode = document.elementFromPoint(x, y);
    if (!topNode) return false;
    return topNode === el || el.contains(topNode) || topNode.contains(el);
  } catch (_) {
    return true;
  }
}
function tryClick(node, mode) {
  const text = lowerTextOf(node);
  try { node.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch (_) {}
  try { node.focus(); } catch (_) {}
  try {
    node.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, cancelable: true, pointerType: 'mouse', isPrimary: true, button: 0 }));
    node.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, button: 0 }));
    node.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, cancelable: true, pointerType: 'mouse', isPrimary: true, button: 0 }));
    node.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, button: 0 }));
  } catch (_) {}
  try { node.click(); } catch (_) {}
  try {
    const form = node.form || node.closest('form');
    if (form) {
      if (typeof form.requestSubmit === 'function') {
        form.requestSubmit(node.tagName === 'BUTTON' || String(node.type || '').toLowerCase() === 'submit' ? node : undefined);
      } else if (typeof form.submit === 'function') {
        form.submit();
      }
    }
  } catch (_) {}
  return { ok: true, text, mode };
}
function collectNodes() {
  return Array.from(document.querySelectorAll('button, a, [role="button"], [role="link"], input[type="submit"], input[type="button"], input[type="reset"], div[tabindex], [tabindex="0"]'));
}
function isBlocked(text) {
  if (!text) return false;
  return blockedLowers.some((pattern) => text.includes(pattern));
}
function scorePrimary(node) {
  if (!visible(node)) return -10000;
  const text = lowerTextOf(node);
  if (!text || isBlocked(text)) return -10000;
  const rect = node.getBoundingClientRect();
  const type = String(node.getAttribute('type') || '').toLowerCase();
  const role = String(node.getAttribute('role') || '').toLowerCase();
  const cls = String(node.className || '').toLowerCase();
  let score = 0;
  if (lowers.some((pattern) => text.includes(pattern))) score += 200;
  if (text.includes('continue') || text.includes('authorize') || text.includes('allow') || text.includes('open') || text.includes('next')) score += 90;
  if (text.includes('继续') || text.includes('授权') || text.includes('允许') || text.includes('打开') || text.includes('进入') || text.includes('下一步')) score += 90;
  if (node.tagName === 'BUTTON') score += 50;
  if (type === 'submit') score += 70;
  if (role === 'button') score += 35;
  if (cls.includes('primary')) score += 40;
  if (cls.includes('submit')) score += 20;
  if (rect.top >= window.innerHeight * 0.35) score += 35;
  if (rect.top >= window.innerHeight * 0.6) score += 15;
  if (rect.width >= 120) score += 10;
  const form = node.form || node.closest('form');
  if (form) score += 25;
  return score;
}
function scoreExactMatch(node) {
  if (!visible(node)) return -10000;
  const text = lowerTextOf(node);
  if (!text || isBlocked(text)) return -10000;
  if (!lowers.some((pattern) => text.includes(pattern))) return -10000;
  const rect = node.getBoundingClientRect();
  if (!rect || rect.width <= 0 || rect.height <= 0) return -10000;
  let score = scorePrimary(node) + 140;
  if (rect.top > window.innerHeight) score += 90;
  else if (rect.top >= window.innerHeight * 0.55) score += 35;
  if (interactableAtCenter(node)) score += 25;
  return score;
}
function findExactMatch() {
  const nodes = collectNodes();
  let best = null;
  for (const node of nodes) {
    const score = scoreExactMatch(node);
    if (score < 0) continue;
    if (!best || score > best.score) {
      best = { node, text: lowerTextOf(node), score };
    }
  }
  return best;
}
function findPrimaryFallback() {
  const nodes = collectNodes();
  let best = null;
  for (const node of nodes) {
    const score = scorePrimary(node);
    if (score < 60) continue;
    if (!best || score > best.score) {
      best = { node, text: lowerTextOf(node), score };
    }
  }
  return best;
}
function scrollOnce() {
  const candidates = [];
  const root = document.scrollingElement || document.documentElement || document.body;
  if (root) candidates.push(root);
  for (const node of Array.from(document.querySelectorAll('main, [role="main"], form, section, article, div'))) {
    if (!canScroll(node)) continue;
    candidates.push(node);
  }
  const seen = new Set();
  let moved = false;
  for (const node of candidates) {
    if (!node || seen.has(node)) continue;
    seen.add(node);
    const before = node === root ? window.scrollY : node.scrollTop;
    const step = Math.max(260, Math.floor((node.clientHeight || window.innerHeight || 800) * 0.92));
    try {
      if (node === root) {
        window.scrollBy(0, step);
        if (Math.abs(window.scrollY - before) > 2) moved = true;
      } else {
        node.scrollTop = Math.min(node.scrollTop + step, node.scrollHeight);
        if (Math.abs(node.scrollTop - before) > 2) moved = true;
      }
    } catch (_) {}
  }
  return moved;
}
for (let pass = 0; pass <= maxScrollPasses; pass += 1) {
  const match = findExactMatch();
  if (match && match.node) {
    return { ...tryClick(match.node, 'text_match'), pass };
  }
  if (fallbackToPrimaryAction) {
    const primary = findPrimaryFallback();
    if (primary && primary.node) {
      return { ...tryClick(primary.node, 'primary_fallback'), pass, score: primary.score };
    }
  }
  if (pass >= maxScrollPasses) break;
  if (!scrollOnce()) break;
}
return { ok: false, reason: fallbackToPrimaryAction ? 'match_and_primary_not_found' : 'match_not_found', pass: maxScrollPasses };
'''

_SCROLL_PAGE_FOR_CONTINUE_JS = r'''
const payload = arguments[0] || {};
const passes = Math.max(1, Number(payload.passes || 1) || 1);
const minStep = Math.max(180, Number(payload.minStep || 240) || 240);
const stepRatio = Math.min(0.98, Math.max(0.5, Number(payload.stepRatio || 0.9) || 0.9));
const patterns = Array.isArray(payload.patterns)
  ? payload.patterns.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : [];
const blockedLowers = Array.isArray(payload.blockedPatterns)
  ? payload.blockedPatterns.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : ['cancel', 'back', 'previous', 'logout', 'sign out', 'personal', 'privacy', 'terms', 'learn more', 'close', '取消', '返回', '上一步', '退出', '个人', '隐私', '条款', '了解更多', '关闭'];
function canScroll(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.display === 'none' || style.visibility === 'hidden') return false;
  return (el.scrollHeight - el.clientHeight) > 24;
}
function visible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.visibility === 'hidden' || style.display === 'none' || style.pointerEvents === 'none') return false;
  if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
  return !!(el.offsetParent || el.getClientRects().length);
}
function textOf(el) {
  return String(el.innerText || el.value || el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim();
}
function lowerTextOf(el) {
  return textOf(el).toLowerCase();
}
function collectActionNodes() {
  return Array.from(document.querySelectorAll('button, a, [role="button"], [role="link"], input[type="submit"], input[type="button"], input[type="reset"], div[tabindex], [tabindex="0"]'));
}
function isBlocked(text) {
  if (!text) return false;
  return blockedLowers.some((pattern) => text.includes(pattern));
}
const root = document.scrollingElement || document.documentElement || document.body;
let matchedNode = null;
function scoreMatch(node) {
  if (!visible(node)) return -10000;
  const text = lowerTextOf(node);
  if (!text || isBlocked(text)) return -10000;
  if (!patterns.some((pattern) => text.includes(pattern))) return -10000;
  const rect = node.getBoundingClientRect();
  if (!rect || rect.width <= 0 || rect.height <= 0) return -10000;
  let score = 0;
  if (rect.top > window.innerHeight) score += 240;
  else if (rect.top > window.innerHeight * 0.72) score += 160;
  else if (rect.top > window.innerHeight * 0.45) score += 80;
  if (node.tagName === 'BUTTON') score += 40;
  if (String(node.getAttribute('type') || '').toLowerCase() === 'submit') score += 60;
  if (String(node.getAttribute('role') || '').toLowerCase() === 'button') score += 30;
  if (text.includes('continue') || text.includes('继续') || text.includes('authorize') || text.includes('allow')) score += 50;
  return score;
}
function pushScrollable(nodes, seen, node) {
  if (!node || seen.has(node) || !canScroll(node)) return;
  seen.add(node);
  nodes.push(node);
}
function collectScrollTargets(targetNode) {
  const nodes = [];
  const seen = new Set();
  let current = targetNode ? targetNode.parentElement : null;
  while (current && current !== document.body && current !== document.documentElement) {
    pushScrollable(nodes, seen, current);
    current = current.parentElement;
  }
  pushScrollable(nodes, seen, root);
  if (!nodes.length) {
    for (const node of Array.from(document.querySelectorAll('main, [role="main"], form, section, article, div'))) {
      pushScrollable(nodes, seen, node);
    }
  }
  return nodes;
}
function alignTargetWithinNode(node, targetNode) {
  if (!node || !targetNode) return false;
  const before = node === root ? window.scrollY : node.scrollTop;
  const targetRect = targetNode.getBoundingClientRect();
  const containerRect = node === root
    ? { top: 0, height: window.innerHeight || node.clientHeight || 800 }
    : node.getBoundingClientRect();
  if (!targetRect || !containerRect) return false;
  const delta = Math.round(
    (targetRect.top + (targetRect.height / 2)) - (containerRect.top + (containerRect.height / 2))
  );
  if (Math.abs(delta) < 12) return false;
  try {
    if (node === root) {
      window.scrollBy(0, delta);
    } else {
      const nextTop = Math.max(0, Math.min(node.scrollTop + delta, Math.max(0, node.scrollHeight - node.clientHeight)));
      node.scrollTop = nextTop;
    }
  } catch (_) {}
  const after = node === root ? window.scrollY : node.scrollTop;
  return Math.abs(after - before) > 2;
}
function findBestMatchedAction() {
  if (!patterns.length) return null;
  let best = null;
  for (const node of collectActionNodes()) {
    const score = scoreMatch(node);
    if (score < 0) continue;
    if (!best || score > best.score) {
      best = { node, score, text: textOf(node) };
    }
  }
  return best;
}
function scrollMatchedActionIntoView() {
  const best = findBestMatchedAction();
  if (!best || !best.node) {
    return { moved: false, targeted: false, text: '' };
  }
  matchedNode = best.node;
  let moved = false;
  let movedCount = 0;
  const targetedNodes = collectScrollTargets(best.node);
  for (const node of targetedNodes) {
    if (alignTargetWithinNode(node, best.node)) {
      moved = true;
      movedCount += 1;
    }
  }
  const beforeRect = best.node.getBoundingClientRect();
  try { best.node.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch (_) {}
  try { best.node.focus(); } catch (_) {}
  const afterRect = best.node.getBoundingClientRect();
  if (Math.abs((afterRect.top || 0) - (beforeRect.top || 0)) > 2) {
    moved = true;
    movedCount += 1;
  }
  return {
    moved,
    movedCount,
    targeted: true,
    text: String(best.text || '').trim(),
    targetedContainerCount: targetedNodes.length,
  };
}
function scrollOnePass() {
  const nodes = collectScrollTargets(matchedNode);
  const seen = new Set();
  let moved = false;
  let movedCount = 0;
  for (const node of nodes) {
    if (!node || seen.has(node)) continue;
    seen.add(node);
    if (matchedNode && alignTargetWithinNode(node, matchedNode)) {
      moved = true;
      movedCount += 1;
      continue;
    }
    const before = node === root ? window.scrollY : node.scrollTop;
    const height = node === root ? (window.innerHeight || node.clientHeight || 800) : (node.clientHeight || window.innerHeight || 800);
    const step = Math.max(minStep, Math.floor(height * stepRatio));
    try {
      if (node === root) {
        window.scrollBy(0, step);
        if (Math.abs(window.scrollY - before) > 2) {
          moved = true;
          movedCount += 1;
        }
      } else {
        node.scrollTop = Math.min(node.scrollTop + step, node.scrollHeight);
        if (Math.abs(node.scrollTop - before) > 2) {
          moved = true;
          movedCount += 1;
        }
      }
    } catch (_) {}
  }
  return { moved, movedCount };
}
let anyMoved = false;
let totalMovedCount = 0;
let targetedText = '';
let targetedContainerCount = 0;
const targeted = scrollMatchedActionIntoView();
if (targeted.targeted) {
  anyMoved = !!targeted.moved;
  totalMovedCount += Number(targeted.movedCount || 0) || 0;
  targetedText = String(targeted.text || '').trim();
  targetedContainerCount = Number(targeted.targetedContainerCount || 0) || 0;
}
for (let index = 0; index < passes; index += 1) {
  const current = scrollOnePass();
  if (!current.moved) break;
  anyMoved = true;
  totalMovedCount += Number(current.movedCount || 0) || 0;
}
return { ok: true, moved: anyMoved, movedCount: totalMovedCount, passes, targetedText, targetedContainerCount };
'''

_SELECT_NON_PERSONAL_WORKSPACE_JS = r'''
const payload = arguments[0] || {};
const personalKeywords = Array.isArray(payload.personalKeywords)
  ? payload.personalKeywords.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : ['个人账户', 'personal account', 'personal'];
const continueKeywords = Array.isArray(payload.continueKeywords)
  ? payload.continueKeywords.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : ['继续', 'continue', 'open', '打开', '进入'];
const prepareRealClick = !!payload.prepareRealClick;
function visible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.visibility === 'hidden' || style.display === 'none') return false;
  if (el.disabled) return false;
  return !!(el.offsetParent || el.getClientRects().length);
}
function textOf(el) {
  return String(el.innerText || el.value || el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim();
}
function contextTextOf(node) {
  let current = node;
  for (let depth = 0; current && depth < 5; depth += 1, current = current.parentElement) {
    const text = textOf(current);
    if (!text) continue;
    if (text.length <= 180) return text;
  }
  return textOf(node);
}
function containsAny(text, patterns) {
  const low = String(text || '').trim().toLowerCase();
  return patterns.some((item) => low.includes(item));
}
function hasCheckedState(node) {
  if (!node) return false;
  if (
    String(node.getAttribute('aria-checked') || '').toLowerCase() === 'true'
    || String(node.getAttribute('aria-selected') || '').toLowerCase() === 'true'
    || String(node.getAttribute('data-state') || '').toLowerCase() === 'checked'
    || String(node.getAttribute('data-selected') || '').toLowerCase() === 'true'
  ) {
    return true;
  }
  try {
    if (node.matches('input[type="radio"], input[type="checkbox"]')) {
      return !!node.checked;
    }
  } catch (_) {}
  try {
    return !!node.querySelector(
      '[aria-checked="true"], [aria-selected="true"], [data-state="checked"], [data-selected="true"], input[type="radio"]:checked, input[type="checkbox"]:checked'
    );
  } catch (_) {
    return false;
  }
}
function isProbablyInteractive(node) {
  if (!node) return false;
  const tag = String(node.tagName || '').toLowerCase();
  const role = String(node.getAttribute('role') || '').toLowerCase();
  if (tag === 'button' || tag === 'label' || tag === 'input') return true;
  if (role === 'radio' || role === 'option' || role === 'button' || role === 'menuitemradio') return true;
  if (typeof node.onclick === 'function') return true;
  const tabIndex = Number(node.getAttribute('tabindex'));
  return !Number.isNaN(tabIndex) && tabIndex >= 0;
}
function scoreInteractiveNode(node) {
  if (!node || !visible(node)) return -10000;
  const rect = node.getBoundingClientRect();
  if (!rect || rect.width <= 0 || rect.height <= 0) return -10000;
  const tag = String(node.tagName || '').toLowerCase();
  const role = String(node.getAttribute('role') || '').toLowerCase();
  const type = String(node.getAttribute('type') || '').toLowerCase();
  let score = 0;
  if (tag === 'input' && (type === 'radio' || type === 'checkbox')) score += 170;
  if (role === 'radio' || role === 'option' || role === 'menuitemradio') score += 150;
  if (tag === 'label') score += 140;
  if (tag === 'button') score += 100;
  if (hasCheckedState(node)) score += 90;
  if (isProbablyInteractive(node)) score += 40;
  try {
    if (node.querySelector('input[type="radio"], input[type="checkbox"]')) score += 35;
  } catch (_) {}
  if (rect.height <= 180) score += 15;
  if (rect.width <= window.innerWidth * 0.95) score += 8;
  return score;
}
function resolveClickableAnchor(node) {
  let current = node;
  let best = null;
  for (let depth = 0; current && depth < 5; depth += 1, current = current.parentElement) {
    if (!visible(current)) continue;
    const text = contextTextOf(current);
    if (!text || text.length > 220) continue;
    if (containsAny(text, continueKeywords)) continue;
    const score = scoreInteractiveNode(current);
    if (score < 0) continue;
    if (!best || score > best.score) {
      best = { node: current, score };
    }
  }
  return best ? best.node : node;
}
function clickNode(node) {
  if (!node || !visible(node)) return false;
  try { node.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch (_) {}
  try { node.focus(); } catch (_) {}
  try {
    node.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, cancelable: true, pointerType: 'mouse', isPrimary: true, button: 0 }));
    node.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, button: 0 }));
    node.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, cancelable: true, pointerType: 'mouse', isPrimary: true, button: 0 }));
    node.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, button: 0 }));
  } catch (_) {}
  try {
    node.click();
    return true;
  } catch (_) {
    return false;
  }
}
function findContinueReady() {
  const selectors = 'button, a, [role="button"], [role="link"], input[type="submit"], input[type="button"], input[type="reset"]';
  for (const node of Array.from(document.querySelectorAll(selectors))) {
    if (!visible(node)) continue;
    const text = `${textOf(node)} ${contextTextOf(node)}`.replace(/\s+/g, ' ').trim();
    if (!text || !containsAny(text, continueKeywords)) continue;
    return true;
  }
  return false;
}
function collectCandidates() {
  const selectors = [
    '[role="radio"]',
    '[role="option"]',
    '[aria-checked]',
    'input[type="radio"]',
    'label',
    'button',
    '[tabindex]'
  ];
  const seen = new Set();
  const out = [];
  for (const selector of selectors) {
    for (const rawNode of Array.from(document.querySelectorAll(selector))) {
      if (!visible(rawNode)) continue;
      const node = resolveClickableAnchor(rawNode);
      if (!node || seen.has(node) || !visible(node)) continue;
      seen.add(node);
      const text = contextTextOf(node) || contextTextOf(rawNode) || textOf(node) || textOf(rawNode);
      if (!text || text.length > 180) continue;
      if (containsAny(text, continueKeywords)) continue;
      const rect = node.getBoundingClientRect();
      if (!rect || rect.height <= 0 || rect.width <= 0) continue;
      if (rect.top > window.innerHeight * 0.92) continue;
      const role = String(node.getAttribute('role') || rawNode.getAttribute('role') || '').toLowerCase();
      const checked = hasCheckedState(node) || hasCheckedState(rawNode);
      let score = 0;
      if (role === 'radio' || role === 'option') score += 80;
      if (role === 'button') score += 25;
      if (String(node.tagName || '').toLowerCase() === 'label') score += 30;
      if (checked) score += 140;
      try {
        if (node.querySelector('input[type="radio"], input[type="checkbox"]')) score += 35;
      } catch (_) {}
      if (rect.top <= window.innerHeight * 0.55) score += 20;
      out.push({
        node,
        rawNode,
        text,
        lower: String(text || '').trim().toLowerCase(),
        top: rect.top,
        left: rect.left,
        role,
        checked,
        score,
      });
    }
  }
  return out;
}
function resolveSelection(candidates) {
  const personal = candidates.filter((item) => containsAny(item.text, personalKeywords));
  const nonPersonal = candidates.filter((item) => !containsAny(item.text, personalKeywords));
  if (!personal.length) {
    return {
      target: null,
      personalCount: personal.length,
      nonPersonalCount: nonPersonal.length,
      reason: 'personal_missing',
    };
  }
  const checkedTarget = personal.find((item) => item.checked) || null;
  personal.sort((a, b) => {
    if (a.checked !== b.checked) return a.checked ? -1 : 1;
    if (a.score !== b.score) return b.score - a.score;
    return (a.top - b.top) || (a.left - b.left);
  });
  return {
    target: checkedTarget || personal[0],
    personalCount: personal.length,
    nonPersonalCount: nonPersonal.length,
    reason: '',
    checkedTarget,
  };
}
function buildResult(candidates, resolved, target, extra) {
  const payload = extra || {};
  return {
    ok: !!payload.ok,
    text: target ? target.text : '',
    alreadyChecked: !!(target && target.checked),
    selectionConfirmed: !!payload.selectionConfirmed,
    continueReady: !!payload.continueReady,
    clicked: !!payload.clicked,
    clickTargetKind: String(payload.clickTargetKind || ''),
    clickTargetText: String(payload.clickTargetText || ''),
    reason: String(payload.reason || ''),
    personalCount: Number(resolved.personalCount || 0),
    nonPersonalCount: Number(resolved.nonPersonalCount || 0),
    candidateCount: candidates.length,
    selectionKind: target && (target.role === 'radio' || target.role === 'option') ? 'radio_like' : 'card_like',
    selectionMethod: String(payload.selectionMethod || ''),
    realClickReady: !!payload.realClickReady,
    clickPointX: Number(payload.clickPointX || 0),
    clickPointY: Number(payload.clickPointY || 0),
    candidates: candidates.slice(0, 8).map((item) => item.text),
  };
}
const initialCandidates = collectCandidates();
const initialResolved = resolveSelection(initialCandidates);
const initialTarget = initialResolved.target;
if (!initialTarget) {
  return {
    ok: false,
    reason: String(initialResolved.reason || 'personal_missing'),
    personalCount: Number(initialResolved.personalCount || 0),
    nonPersonalCount: Number(initialResolved.nonPersonalCount || 0),
    candidateCount: initialCandidates.length,
    candidates: initialCandidates.slice(0, 8).map((item) => item.text),
  };
}
if (initialTarget.checked) {
  return buildResult(initialCandidates, initialResolved, initialTarget, {
    ok: true,
    selectionConfirmed: true,
    continueReady: true,
    reason: 'already_checked',
  });
}
const clickTargets = [];
function pushClickTarget(node, kind) {
  if (!node || !visible(node) || clickTargets.some((item) => item.node === node)) return;
  clickTargets.push({ node, kind: String(kind || 'unknown') });
}
pushClickTarget(initialTarget.node, 'anchor');
try {
  if (initialTarget.node.matches('input[type="radio"], input[type="checkbox"]')) {
    pushClickTarget(initialTarget.node, 'input');
  }
} catch (_) {}
try {
  pushClickTarget(initialTarget.node.querySelector('input[type="radio"], input[type="checkbox"]'), 'descendant_input');
} catch (_) {}
let current = initialTarget.node.parentElement;
for (let depth = 0; current && depth < 4; depth += 1, current = current.parentElement) {
  if (isProbablyInteractive(current)) {
    pushClickTarget(current, `ancestor_${depth + 1}`);
  }
}
if (prepareRealClick) {
  const preparedTarget = clickTargets.find((item) => item && item.node && visible(item.node)) || null;
  if (!preparedTarget) {
    return buildResult(initialCandidates, initialResolved, initialTarget, {
      ok: false,
      clicked: false,
      realClickReady: false,
      reason: 'real_click_target_missing',
      continueReady: findContinueReady(),
    });
  }
  const rect = preparedTarget.node.getBoundingClientRect();
  return buildResult(initialCandidates, initialResolved, initialTarget, {
    ok: rect && rect.width > 0 && rect.height > 0,
    clicked: false,
    realClickReady: !!(rect && rect.width > 0 && rect.height > 0),
    selectionMethod: 'drission_real_click_prepare',
    clickTargetKind: preparedTarget.kind,
    clickTargetText: textOf(preparedTarget.node) || initialTarget.text,
    clickPointX: rect ? rect.left + rect.width / 2 : 0,
    clickPointY: rect ? rect.top + rect.height / 2 : 0,
    continueReady: findContinueReady(),
    reason: rect && rect.width > 0 && rect.height > 0 ? 'prepared_real_click' : 'real_click_target_invalid_rect',
  });
}
let clicked = false;
let clickTargetKind = '';
let clickTargetText = '';
for (const candidate of clickTargets.slice(0, 5)) {
  if (!clickNode(candidate.node)) continue;
  clicked = true;
  clickTargetKind = candidate.kind;
  clickTargetText = textOf(candidate.node) || initialTarget.text;
  const refreshedCandidates = collectCandidates();
  const refreshedResolved = resolveSelection(refreshedCandidates);
  const confirmedTarget = refreshedResolved.checkedTarget || refreshedResolved.target;
  const continueReady = findContinueReady();
  if (
    (confirmedTarget && confirmedTarget.checked && !containsAny(confirmedTarget.text, personalKeywords))
    || continueReady
  ) {
    return buildResult(refreshedCandidates, refreshedResolved, confirmedTarget, {
      ok: true,
      clicked,
      clickTargetKind,
      clickTargetText,
      selectionConfirmed: true,
      continueReady,
      reason: 'confirmed_after_click',
    });
  }
}
return buildResult(initialCandidates, initialResolved, initialTarget, {
  ok: clicked,
  clicked,
  clickTargetKind,
  clickTargetText,
  selectionConfirmed: false,
  continueReady: findContinueReady(),
  reason: clicked ? 'selection_click_unconfirmed' : 'selection_click_failed',
});
'''

_SELECT_CHATGPT_HOME_NON_PERSONAL_WORKSPACE_JS = r'''
const payload = arguments[0] || {};
const personalKeywords = Array.isArray(payload.personalKeywords)
  ? payload.personalKeywords.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : ['personal', '个人', 'account', '帐户', '账户'];
const menuBlockedKeywords = Array.isArray(payload.menuBlockedKeywords)
  ? payload.menuBlockedKeywords.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : ['upgrade', 'upgrade plan', 'pricing', 'billing', 'my plan', 'manage plan', 'settings', 'help', 'logout', '升级', '定价', '账单', '设置', '帮助', '退出登录'];
const anchorBlockedKeywords = Array.isArray(payload.anchorBlockedKeywords)
  ? payload.anchorBlockedKeywords.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean)
  : ['invite', '邀请团队成员', 'new chat', 'search', '搜索聊天'];
function visible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.visibility === 'hidden' || style.display === 'none') return false;
  if (el.disabled) return false;
  return !!(el.offsetParent || el.getClientRects().length);
}
function textOf(el) {
  return String(el.innerText || el.value || el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g, ' ').trim();
}
function containsAny(text, patterns) {
  const low = String(text || '').trim().toLowerCase();
  return patterns.some((item) => low.includes(item));
}
function attrText(el, name) {
  if (!el || !name) return '';
  return String(el.getAttribute(name) || '').replace(/\s+/g, ' ').trim();
}
function hintOf(el) {
  if (!el) return '';
  const parts = [
    textOf(el),
    attrText(el, 'aria-label'),
    attrText(el, 'title'),
    attrText(el, 'id'),
    attrText(el, 'data-testid'),
    attrText(el, 'data-test-id'),
    attrText(el, 'data-state'),
    typeof el.className === 'string' ? el.className : '',
  ].filter(Boolean);
  return parts.join(' ').replace(/\s+/g, ' ').trim();
}
function hasAvatarLikeDescendant(el) {
  if (!el || typeof el.querySelectorAll !== 'function') return false;
  try {
    if (el.querySelector('img, picture, canvas')) return true;
  } catch (_) {}
  try {
    return Array.from(el.querySelectorAll('*')).some((node) => {
      const hint = hintOf(node).toLowerCase();
      return /avatar|profile|account|workspace|user|sidebar|menu/.test(hint);
    });
  } catch (_) {
    return false;
  }
}
function isLikelyProfileMenuAnchor(el) {
  if (!el) return false;
  const hint = hintOf(el).toLowerCase();
  const ariaHasPopup = String(el.getAttribute('aria-haspopup') || '').toLowerCase();
  const ariaExpanded = String(el.getAttribute('aria-expanded') || '').toLowerCase();
  if (containsAny(hint, ['profile', 'account', 'workspace', '切换工作空间', 'switch workspace', 'open menu', 'settings'])) {
    return true;
  }
  if (ariaHasPopup === 'menu' || ariaExpanded === 'true' || ariaExpanded === 'false') {
    return true;
  }
  if (hasAvatarLikeDescendant(el)) {
    return true;
  }
  return false;
}
function clickNode(node) {
  if (!node) return false;
  try { node.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch (_) {}
  try { node.focus(); } catch (_) {}
  try {
    node.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, cancelable: true, pointerType: 'mouse', isPrimary: true, button: 0 }));
    node.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, button: 0 }));
    node.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, cancelable: true, pointerType: 'mouse', isPrimary: true, button: 0 }));
    node.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, button: 0 }));
  } catch (_) {}
  try { node.click(); return true; } catch (_) { return false; }
}
function collectMenuItems() {
  const selectors = ['[role="menuitemradio"]', '[role="menuitemcheckbox"]', '[role="menuitem"]', '[aria-checked]'];
  const out = [];
  const seen = new Set();
  for (const selector of selectors) {
    for (const node of Array.from(document.querySelectorAll(selector))) {
      if (!visible(node)) continue;
      if (seen.has(node)) continue;
      seen.add(node);
      const rect = node.getBoundingClientRect();
      if (!rect || rect.width <= 0 || rect.height <= 0) continue;
      if (rect.left > Math.max(420, window.innerWidth * 0.4)) continue;
      const text = textOf(node);
      if (!text || text.length > 120) continue;
      const hint = hintOf(node);
      if (containsAny(text, menuBlockedKeywords) || containsAny(hint, menuBlockedKeywords)) continue;
      out.push({
        node,
        text,
        hint,
        role: String(node.getAttribute('role') || '').toLowerCase(),
        top: rect.top,
        left: rect.left,
        checked: String(node.getAttribute('aria-checked') || '').toLowerCase() === 'true'
          || String(node.getAttribute('aria-selected') || '').toLowerCase() === 'true'
          || String(node.getAttribute('data-state') || '').toLowerCase() === 'checked'
      });
    }
  }
  return out;
}
function resolveTarget(menuItems) {
  const radioItems = menuItems.filter((item) => item.role === 'menuitemradio' || item.role === 'menuitemcheckbox' || item.checked);
  const pool = radioItems.length ? radioItems : menuItems;
  const personalItems = pool.filter((item) => containsAny(item.text, personalKeywords));
  const nonPersonal = pool.filter((item) => !containsAny(item.text, personalKeywords));
  if (!personalItems.length) {
    return { target: null, reason: 'personal_menuitem_missing', hasPersonalOption: false, candidateCount: pool.length };
  }
  const checked = personalItems.find((item) => item.checked);
  personalItems.sort((a, b) => {
    if (a.checked !== b.checked) return a.checked ? -1 : 1;
    return (a.top - b.top) || (a.left - b.left);
  });
  return {
    target: checked || personalItems[0],
    reason: '',
    hasPersonalOption: true,
    candidateCount: pool.length,
    nonPersonalCount: nonPersonal.length,
    selectionKind: radioItems.length >= 2 ? 'radio_group_personal' : 'personal_workspace',
    signalConfidence: checked ? 'high' : 'medium',
  };
}
let menuItems = collectMenuItems();
let resolved = resolveTarget(menuItems);
let target = resolved.target;
if (target) {
  let selectionConfirmed = !!target.checked;
  if (!target.checked) {
    clickNode(target.node);
    menuItems = collectMenuItems();
    resolved = resolveTarget(menuItems);
    target = resolved.target || target;
    selectionConfirmed = !!(target && target.checked);
  }
  return {
    ok: true,
    text: target.text,
    alreadyChecked: !!target.checked,
    selectionConfirmed,
    source: 'menu_visible',
    selectionKind: String(resolved.selectionKind || ''),
    signalConfidence: String(resolved.signalConfidence || ''),
    hasPersonalOption: !!resolved.hasPersonalOption,
    candidateCount: Number(resolved.candidateCount || 0),
    nonPersonalCount: Number(resolved.nonPersonalCount || 0),
    menuTexts: menuItems.map((item) => item.text),
  };
}
const anchorSelectors = ['[role="button"]', 'button', 'a', '[tabindex]'];
const anchorCandidates = [];
const seenAnchors = new Set();
for (const selector of anchorSelectors) {
  for (const node of Array.from(document.querySelectorAll(selector))) {
    if (!visible(node)) continue;
    if (seenAnchors.has(node)) continue;
    seenAnchors.add(node);
    const rect = node.getBoundingClientRect();
    if (!rect || rect.width <= 0 || rect.height <= 0) continue;
    if (rect.left > 420 || rect.top < window.innerHeight * 0.68) continue;
    const text = textOf(node);
    const hint = hintOf(node);
    const label = text || hint;
    const avatarLike = isLikelyProfileMenuAnchor(node);
    if ((!label || label.length > 180) && !avatarLike) continue;
    if (containsAny(label, anchorBlockedKeywords)) continue;
    let score = 0;
    if (rect.top >= window.innerHeight * 0.8) score += 4;
    if (rect.left <= 240) score += 3;
    if (avatarLike) score += 6;
    if (String(node.getAttribute('aria-haspopup') || '').toLowerCase() === 'menu') score += 3;
    anchorCandidates.push({
      node,
      text: label,
      hint,
      top: rect.top,
      left: rect.left,
      score,
      avatarLike,
    });
  }
}
anchorCandidates.sort((a, b) => (b.score - a.score) || (b.top - a.top) || (a.left - b.left));
if (!anchorCandidates.length) {
  return { ok: false, reason: 'workspace_anchor_missing', menuTexts: menuItems.map((item) => item.text) };
}
const triedAnchors = [];
for (const anchor of anchorCandidates.slice(0, 3)) {
  triedAnchors.push(anchor.text || anchor.hint || 'unknown');
  clickNode(anchor.node);
  menuItems = collectMenuItems();
  resolved = resolveTarget(menuItems);
  target = resolved.target;
  if (!target) continue;
  let selectionConfirmed = !!target.checked;
  if (!target.checked) {
    clickNode(target.node);
    menuItems = collectMenuItems();
    resolved = resolveTarget(menuItems);
    target = resolved.target || target;
    selectionConfirmed = !!(target && target.checked);
  }
  return {
    ok: true,
    text: target.text,
    alreadyChecked: !!target.checked,
    selectionConfirmed,
    source: 'anchor_menu',
    anchorText: anchor.text,
    anchorHint: anchor.hint,
    selectionKind: String(resolved.selectionKind || ''),
    signalConfidence: String(resolved.signalConfidence || ''),
    hasPersonalOption: !!resolved.hasPersonalOption,
    candidateCount: Number(resolved.candidateCount || 0),
    nonPersonalCount: Number(resolved.nonPersonalCount || 0),
    menuTexts: menuItems.map((item) => item.text),
  };
}
return {
  ok: false,
  reason: String(resolved.reason || 'personal_menuitem_missing'),
  anchorTexts: triedAnchors,
  hasPersonalOption: !!resolved.hasPersonalOption,
  candidateCount: Number(resolved.candidateCount || 0),
  nonPersonalCount: Number(resolved.nonPersonalCount || 0),
  menuTexts: menuItems.map((item) => item.text),
};
'''

_FILL_OTP_JS = r'''
const payload = arguments[0] || {};
const code = String(payload.code || '').trim();
const selectors = Array.isArray(payload.selectors) ? payload.selectors : [];
if (!code) return { ok: false, reason: 'empty_code' };
function visible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (!style) return false;
  if (style.visibility === 'hidden' || style.display === 'none') return false;
  if (el.disabled) return false;
  return !!(el.offsetParent || el.getClientRects().length);
}
function setValue(el, value) {
  const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
  if (descriptor && descriptor.set) {
    descriptor.set.call(el, value);
  } else {
    el.value = value;
  }
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}
const visibleInputs = Array.from(document.querySelectorAll('input')).filter(visible);
const segmented = visibleInputs.filter((el) => {
  const hint = `${el.name || ''} ${el.id || ''} ${el.autocomplete || ''} ${el.inputMode || ''} ${el.getAttribute('aria-label') || ''}`.toLowerCase();
  const maxLen = Number(el.maxLength || 0);
  return (maxLen === 1) || /code|otp|digit|verification|one-time|security/.test(hint);
});
if (segmented.length >= code.length && code.length > 1) {
  for (let i = 0; i < code.length; i += 1) {
    const el = segmented[i];
    if (!el) break;
    try { el.focus(); } catch (_) {}
    setValue(el, code[i]);
  }
  return { ok: true, mode: 'segmented' };
}
for (const sel of selectors || []) {
  try {
    const nodes = Array.from(document.querySelectorAll(sel));
    for (const node of nodes) {
      if (!visible(node)) continue;
      try { node.focus(); } catch (_) {}
      setValue(node, code);
      try { node.blur(); } catch (_) {}
      return { ok: true, mode: 'single', selector: sel };
    }
  } catch (_) {}
}
return { ok: false, reason: 'input_missing' };
'''

_SET_LOCAL_STORAGE_JS = r'''
const payload = arguments[0] || {};
const rows = Array.isArray(payload.items) ? payload.items : [];
let applied = 0;
for (const item of rows) {
  if (!item || typeof item.name !== 'string') continue;
  try {
    localStorage.setItem(String(item.name), String(item.value ?? ''));
    applied += 1;
  } catch (_) {}
}
return { ok: true, count: applied };
'''


@dataclass(frozen=True, slots=True)
class OAuthRuntimeConfig:
    client_id: str
    redirect_uri: str
    callback_bind_host: str
    callback_port: int
    callback_url_hints: tuple[str, ...]
    bridge_enabled: bool = False
    bridge_bind_host: str = ''
    bridge_port: int = 0
    bridge_target_host: str = ''
    bridge_target_port: int = 0
    notices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PKCECodes:
    code_verifier: str
    code_challenge: str


@dataclass(frozen=True, slots=True)
class OAuthCallback:
    code: str
    state: str
    error: str = ''
    error_description: str = ''


@dataclass(frozen=True, slots=True)
class _BrowserConfig:
    browser_path: str
    headless: bool = False
    incognito: bool = True
    auto_port: bool = True
    auto_port_scope_start: int = 9600
    auto_port_scope_end: int = 59600
    local_port: int = 0
    window_width: int = 1365
    window_height: int = 768
    load_mode: str = 'normal'
    proxy_url: str = ''


class _BrowserFactory:
    def __init__(self, cfg: _BrowserConfig) -> None:
        self._cfg = cfg

    def _normalize_load_mode(self) -> str:
        mode = str(self._cfg.load_mode or 'normal').strip().lower()
        if mode not in {'normal', 'eager', 'none'}:
            return 'normal'
        return mode

    def ensure_browser_path(self) -> str:
        p = Path(str(self._cfg.browser_path or '')).expanduser()
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f'浏览器路径不存在：{p}')
        return str(p)

    def make_profile_dir(self, root_dir: str, email: str) -> str:
        root = Path(str(root_dir or '')).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        safe_email = _safe_filename_slug(str(email or '').strip().lower() or 'unknown')
        profile_dir = root / safe_email
        profile_dir.mkdir(parents=True, exist_ok=True)
        return str(profile_dir.resolve())

    def build_options(self, profile_dir: str):
        if ChromiumOptions is None:
            raise RuntimeError('DrissionPage 未安装，无法启动 Codex OAuth 浏览器。')
        opt = ChromiumOptions()
        opt.set_browser_path(self.ensure_browser_path())
        opt.set_user_data_path(str(Path(profile_dir).expanduser().resolve()))
        if bool(self._cfg.auto_port):
            start = int(self._cfg.auto_port_scope_start or 9600)
            end = int(self._cfg.auto_port_scope_end or 59600)
            if end > start > 0:
                opt.auto_port(scope=(start, end))
            else:
                opt.auto_port()
        elif int(self._cfg.local_port or 0) > 0:
            opt.set_local_port(int(self._cfg.local_port))
        else:
            opt.auto_port()
        opt.headless(bool(self._cfg.headless))
        try:
            opt.incognito(bool(self._cfg.incognito))
        except Exception:
            if bool(self._cfg.incognito):
                opt.set_argument('--incognito')
        opt.set_argument('--no-first-run')
        opt.set_argument('--no-default-browser-check')
        opt.set_argument('--disable-sync')
        opt.set_argument('--disable-extensions')
        if os.name != 'nt':
            opt.set_argument('--no-sandbox')
            opt.set_argument('--disable-dev-shm-usage')
        opt.set_argument(f'--window-size={int(self._cfg.window_width)},{int(self._cfg.window_height)}')
        proxy_server = _normalize_proxy_server(str(self._cfg.proxy_url or ''))
        if proxy_server:
            opt.set_proxy(proxy_server)
        try:
            opt.set_load_mode(self._normalize_load_mode())
        except Exception:
            pass
        return opt

    def open_browser(self, profile_dir: str):
        if Chromium is None:
            raise RuntimeError('DrissionPage 未安装，无法启动 Codex OAuth 浏览器。')
        browser = Chromium(self.build_options(profile_dir))
        try:
            browser.set.load_mode(self._normalize_load_mode())
        except Exception:
            pass
        return browser


class _TraceWriter:
    def __init__(self, *, email: str) -> None:
        debug_dir = (_repo_root() / 'trace').resolve()
        debug_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        suffix = _safe_filename_slug(email or 'unknown')[:80] or 'unknown'
        self.path = str((debug_dir / f'codex_trace_{ts}_{suffix}_{uuid.uuid4().hex[:8]}.jsonl').resolve())
        self._lock = threading.Lock()

    def write(self, payload: dict[str, Any]) -> None:
        try:
            raw = json.dumps(dict(payload or {}), ensure_ascii=False, default=str)
        except Exception:
            return
        with self._lock:
            with Path(self.path).open('a', encoding='utf-8') as handle:
                handle.write(raw + '\n')


def _open_drission_browser_with_retry(
    browser_factory: Any,
    profile_dir: str,
    *,
    trace: _TraceWriter,
    log: Any,
    loop: asyncio.AbstractEventLoop,
    max_attempts: int = 2,
    retry_wait_seconds: float = 1.5,
) -> tuple[Any, Any]:
    def _cleanup_stale_drission_auto_port_dirs() -> list[str]:
        raw_auto_port_root = str(os.getenv('AIO_DRISSION_AUTO_PORT_ROOT') or '').strip()
        auto_port_root = (
            Path(raw_auto_port_root).expanduser()
            if raw_auto_port_root
            else (Path(tempfile.gettempdir()) / 'DrissionPage' / 'autoPortData')
        )
        if not auto_port_root.exists() or (not auto_port_root.is_dir()):
            return []

        running_cmdlines: list[str] = []
        proc_root = Path('/proc')
        if os.name != 'nt' and proc_root.exists() and proc_root.is_dir():
            for proc_dir in proc_root.iterdir():
                if not proc_dir.is_dir() or (not proc_dir.name.isdigit()):
                    continue
                try:
                    raw = (proc_dir / 'cmdline').read_bytes()
                except Exception:
                    continue
                text = raw.replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                if text:
                    running_cmdlines.append(text)

        cleaned_paths: list[str] = []
        now_ts = time.time()
        for child in sorted(auto_port_root.iterdir(), key=lambda item: item.name):
            if (not child.is_dir()) or (not child.name.isdigit()):
                continue
            child_text = str(child)
            if running_cmdlines and any(child_text in cmdline for cmdline in running_cmdlines):
                continue
            if not any((child / name).exists() for name in ('SingletonLock', 'SingletonSocket', 'SingletonCookie')):
                continue
            try:
                port = int(child.name)
            except Exception:
                port = 0
            if port > 0:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        continue
                except Exception:
                    pass
            try:
                age_sec = max(0.0, now_ts - float(child.stat().st_mtime))
            except Exception:
                age_sec = 999999.0
            if age_sec < 30.0:
                continue
            try:
                shutil.rmtree(child)
            except Exception as error:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'drission_cleanup_auto_port_dir',
                        'path': child_text,
                        'result': 'error',
                        'error': str(error),
                    }
                )
                continue
            cleaned_paths.append(child_text)
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'drission_cleanup_auto_port_dir',
                    'path': child_text,
                    'result': 'removed',
                    'port': int(port),
                }
            )
        return cleaned_paths

    last_error: Exception | None = None
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        cleaned_paths = _cleanup_stale_drission_auto_port_dirs()
        if cleaned_paths:
            _emit_log_sync(
                loop,
                log,
                'info',
                f'【Codex OAuth】已清理 {len(cleaned_paths)} 个残留的 Drission autoPort 临时目录。',
            )
        browser = None
        try:
            browser = browser_factory.open_browser(profile_dir)
            tab = browser.latest_tab
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'drission_open_browser',
                    'attempt': int(attempt),
                    'result': 'success',
                }
            )
            if attempt > 1:
                _emit_log_sync(loop, log, 'info', f'【Codex OAuth】Drission 浏览器第 {int(attempt)} 次连接成功。')
            return browser, tab
        except Exception as error:
            last_error = error
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'drission_open_browser',
                    'attempt': int(attempt),
                    'result': 'error',
                    'error': str(error),
                }
            )
            _emit_log_sync(
                loop,
                log,
                'warn',
                f'【Codex OAuth】Drission 浏览器连接失败，第 {int(attempt)}/{int(max_attempts)} 次：{error}',
            )
            if browser is not None:
                try:
                    browser.quit()
                except Exception:
                    pass
            if attempt < int(max_attempts):
                time.sleep(max(0.0, float(retry_wait_seconds)))

    if last_error is not None:
        raise last_error
    raise RuntimeError('Drission 浏览器连接失败。')


class _OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'AIOCodexOAuth/1.0'

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != CALLBACK_PATH:
                self.send_response(404)
                self.end_headers()
                return

            q = urllib.parse.parse_qs(parsed.query or '')
            code = (q.get('code') or [''])[0]
            state = (q.get('state') or [''])[0]
            err = (q.get('error') or [''])[0]
            err_desc = (q.get('error_description') or [''])[0]

            cb = OAuthCallback(
                code=str(code or '').strip(),
                state=str(state or '').strip(),
                error=str(err or '').strip(),
                error_description=str(err_desc or '').strip(),
            )
            self.server._set_callback(cb)  # type: ignore[attr-defined]

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(
                (
                    '<!doctype html><html><head><meta charset="utf-8"></head>'
                    '<body style="font-family:system-ui">'
                    '<h3>认证回调已收到</h3><p>你可以关闭此页面，回到控制台等待保存完成。</p>'
                    '</body></html>'
                ).encode('utf-8')
            )
        except Exception:
            try:
                self.send_response(500)
                self.end_headers()
            except Exception:
                pass

    def log_message(self, _format: str, *args: Any) -> None:  # noqa: A003
        return


class OAuthCallbackServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int) -> None:
        super().__init__((host, port), _OAuthCallbackHandler)
        self._evt = threading.Event()
        self._cb: Optional[OAuthCallback] = None

    def _set_callback(self, cb: OAuthCallback) -> None:
        self._cb = cb
        self._evt.set()

    def wait(self, timeout_sec: float) -> Optional[OAuthCallback]:
        ok = self._evt.wait(timeout_sec)
        return self._cb if ok else None


class OAuthCallbackWaiter:
    def __init__(self, *, host: str, port: int, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._future: asyncio.Future[OAuthCallback] = loop.create_future()
        self._server = OAuthCallbackServer(host, port)
        original_setter = self._server._set_callback

        def _set(cb: OAuthCallback) -> None:
            original_setter(cb)
            if self._future.done():
                return
            self._loop.call_soon_threadsafe(self._future.set_result, cb)

        self._server._set_callback = _set  # type: ignore[method-assign]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    async def wait(self, timeout_sec: float) -> OAuthCallback:
        return await asyncio.wait_for(self._future, timeout=float(timeout_sec))

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass


class SharedOAuthCallbackHub:
    def __init__(self, *, host: str, port: int, loop: asyncio.AbstractEventLoop) -> None:
        self._host = str(host or '').strip() or '127.0.0.1'
        self._port = int(port)
        self._loop = loop
        self._lock = threading.Lock()
        self._waiters: dict[str, asyncio.Future[OAuthCallback]] = {}
        self._pending_callbacks: dict[str, OAuthCallback] = {}
        self._started = False
        self._server = OAuthCallbackServer(self._host, self._port)
        original_setter = self._server._set_callback

        def _set(cb: OAuthCallback) -> None:
            original_setter(cb)
            self._dispatch(cb)

        self._server._set_callback = _set  # type: ignore[method-assign]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> None:
        if self._started:
            return
        self._thread.start()
        self._started = True

    @staticmethod
    def _safe_set_result(fut: asyncio.Future[OAuthCallback], cb: OAuthCallback) -> None:
        if not fut.done():
            fut.set_result(cb)

    @staticmethod
    def _safe_set_exception(fut: asyncio.Future[OAuthCallback], error: Exception) -> None:
        if not fut.done():
            fut.set_exception(error)

    def _register_waiter(self, state: str) -> asyncio.Future[OAuthCallback]:
        state_key = str(state or '').strip()
        if not state_key:
            raise RuntimeError('OAuth state 为空，无法注册回调等待。')
        fut: asyncio.Future[OAuthCallback] = self._loop.create_future()
        pending_cb: Optional[OAuthCallback] = None
        with self._lock:
            old = self._waiters.get(state_key)
            if old is not None and (not old.done()):
                raise RuntimeError(f'OAuth state 已存在等待者：{state_key}')
            pending_cb = self._pending_callbacks.pop(state_key, None)
            self._waiters[state_key] = fut
        if pending_cb is not None:
            self._loop.call_soon_threadsafe(self._safe_set_result, fut, pending_cb)
        return fut

    def _unregister_waiter(self, state: str, fut: asyncio.Future[OAuthCallback]) -> None:
        state_key = str(state or '').strip()
        if not state_key:
            return
        with self._lock:
            current = self._waiters.get(state_key)
            if current is fut:
                self._waiters.pop(state_key, None)

    def _dispatch(self, cb: OAuthCallback) -> None:
        state_key = str(getattr(cb, 'state', '') or '').strip()
        if not state_key:
            return
        with self._lock:
            fut = self._waiters.get(state_key)
            if fut is None:
                if state_key not in self._pending_callbacks:
                    self._pending_callbacks[state_key] = cb
                return
        self._loop.call_soon_threadsafe(self._safe_set_result, fut, cb)

    async def wait_for_state(self, *, state: str, timeout_sec: float) -> OAuthCallback:
        fut = self._register_waiter(state)
        try:
            return await asyncio.wait_for(fut, timeout=float(timeout_sec))
        finally:
            self._unregister_waiter(state, fut)

    def stop(self) -> None:
        with self._lock:
            pending = list(self._waiters.values())
            self._waiters.clear()
            self._pending_callbacks.clear()
        for fut in pending:
            self._loop.call_soon_threadsafe(
                self._safe_set_exception,
                fut,
                RuntimeError('共享 OAuth 回调监听已停止。'),
            )
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass


class _OAuthCallbackBridgeHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'AIOCodexOAuthBridge/1.0'

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != CALLBACK_PATH:
                self.send_response(404)
                self.end_headers()
                return

            req = urllib.request.Request(self.server._build_target_url(parsed.query or ''), method='GET')  # type: ignore[attr-defined]
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                    status = int(getattr(resp, 'status', 200) or 200)
                    raw = resp.read()
                    content_type = str(resp.headers.get('Content-Type') or 'text/html; charset=utf-8').strip()
                    cache_control = str(resp.headers.get('Cache-Control') or 'no-store').strip()
            except urllib.error.HTTPError as error:
                status = int(getattr(error, 'code', 502) or 502)
                raw = error.read()
                content_type = str(error.headers.get('Content-Type') or 'text/plain; charset=utf-8').strip()
                cache_control = str(error.headers.get('Cache-Control') or 'no-store').strip()

            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Cache-Control', cache_control or 'no-store')
            self.end_headers()
            if raw:
                self.wfile.write(raw)
        except Exception as error:
            try:
                self.send_response(502)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(f'Codex OAuth 回调桥接失败：{error}'.encode('utf-8', errors='replace'))
            except Exception:
                pass

    def log_message(self, _format: str, *args: Any) -> None:  # noqa: A003
        return


class OAuthCallbackBridgeServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, *, target_host: str, target_port: int) -> None:
        super().__init__((host, port), _OAuthCallbackBridgeHandler)
        self._target_host = str(target_host or '').strip()
        self._target_port = int(target_port)

    def _build_target_url(self, query: str) -> str:
        netloc = _format_netloc(self._target_host, self._target_port)
        return urllib.parse.urlunparse(('http', netloc, CALLBACK_PATH, '', str(query or ''), ''))


class _SharedOAuthCallbackBridge:
    def __init__(self, *, bind_host: str, bind_port: int, target_host: str, target_port: int) -> None:
        self._bind_host = str(bind_host or '').strip()
        self._bind_port = int(bind_port)
        self._target_host = str(target_host or '').strip()
        self._target_port = int(target_port)
        self._started = False
        self._server = OAuthCallbackBridgeServer(
            self._bind_host,
            self._bind_port,
            target_host=self._target_host,
            target_port=self._target_port,
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        if self._started:
            return
        self._thread.start()
        self._started = True

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass


class _SharedOAuthCallbackBridgeLease:
    def __init__(self, bind_key: tuple[str, int]) -> None:
        self._bind_key = bind_key
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _release_shared_oauth_callback_bridge(self._bind_key)


_SHARED_OAUTH_CALLBACK_BRIDGES_LOCK = threading.Lock()
_SHARED_OAUTH_CALLBACK_BRIDGES: dict[tuple[str, int], dict[str, Any]] = {}


def _acquire_shared_oauth_callback_bridge(
    *,
    bind_host: str,
    bind_port: int,
    target_host: str,
    target_port: int,
) -> _SharedOAuthCallbackBridgeLease:
    bind_key = (str(bind_host or '').strip(), int(bind_port))
    target_key = (str(target_host or '').strip(), int(target_port))
    with _SHARED_OAUTH_CALLBACK_BRIDGES_LOCK:
        record = _SHARED_OAUTH_CALLBACK_BRIDGES.get(bind_key)
        if record is not None:
            current_target = tuple(record.get('target') or ())
            if current_target != target_key:
                raise RuntimeError(
                    'Codex OAuth 回调桥接冲突：'
                    f'{bind_key[0]}:{bind_key[1]} 已被用于转发到 {current_target}，'
                    f'不能再转发到 {target_key}。'
                )
            record['refcount'] = int(record.get('refcount') or 0) + 1
            return _SharedOAuthCallbackBridgeLease(bind_key)

        bridge = _SharedOAuthCallbackBridge(
            bind_host=bind_key[0],
            bind_port=bind_key[1],
            target_host=target_key[0],
            target_port=target_key[1],
        )
        bridge.start()
        _SHARED_OAUTH_CALLBACK_BRIDGES[bind_key] = {
            'bridge': bridge,
            'target': target_key,
            'refcount': 1,
        }
        return _SharedOAuthCallbackBridgeLease(bind_key)


def _release_shared_oauth_callback_bridge(bind_key: tuple[str, int]) -> None:
    bridge: Optional[_SharedOAuthCallbackBridge] = None
    with _SHARED_OAUTH_CALLBACK_BRIDGES_LOCK:
        record = _SHARED_OAUTH_CALLBACK_BRIDGES.get(bind_key)
        if record is None:
            return
        next_refcount = int(record.get('refcount') or 0) - 1
        if next_refcount > 0:
            record['refcount'] = next_refcount
            return
        bridge = record.get('bridge')
        _SHARED_OAUTH_CALLBACK_BRIDGES.pop(bind_key, None)
    if bridge is not None:
        bridge.stop()


def _repo_root() -> Path:
    isolated = str(os.getenv('X9_ISOLATED_ROOT') or '').strip()
    if isolated:
        return Path(isolated).expanduser().resolve()
    here = Path(__file__).resolve()
    if here.name.endswith('_draft.py') or here.parent.name in {'_toolcore', '_credential_toolcore'}:
        return here.parent.parent
    return here.parent


def _resolve_any_path(path_str: str) -> Path:
    raw = str(path_str or '').strip()
    p = Path(raw).expanduser()
    if p.is_absolute():
        return p
    return (_repo_root() / p).resolve()


def _load_codex_oauth_config_file() -> dict[str, Any]:
    env_override = str(os.getenv('OAI_PROJECT_CONFIG_PATH') or '').strip()
    candidates: list[Path] = []
    if env_override:
        candidates.append(Path(env_override).expanduser().resolve())
    base = _repo_root().resolve()
    candidates.append((base / 'config.json').resolve())
    candidates.append((base.parent / 'config.json').resolve())
    seen: set[Path] = set()
    for config_path in candidates:
        if config_path in seen:
            continue
        seen.add(config_path)
        if not config_path.exists() or (not config_path.is_file()):
            continue
        try:
            payload = json.loads(config_path.read_text(encoding='utf-8'))
        except Exception:
            continue
        if isinstance(payload, dict):
            return payload
    return {}


def _read_codex_oauth_config_value(config: dict[str, Any], *keys: str) -> Any:
    sources: list[dict[str, Any]] = []
    if isinstance(config, dict):
        sources.append(config)
        for root_key in ('codex_oauth', 'codexOAuth'):
            nested = config.get(root_key)
            if isinstance(nested, dict):
                sources.append(nested)
    for source in sources:
        for key in keys:
            if key in source:
                return source.get(key)
    return None


def _load_bridge_config_imap_defaults() -> dict[str, Any]:
    backend_path = (_repo_root() / 'python_bridge' / 'backend.py').resolve()
    if not backend_path.exists() or (not backend_path.is_file()):
        return {}
    try:
        # backend.py 目前带有 UTF-8 BOM，直接用 utf-8 读取会把 BOM 留在源码首字符里，
        # 导致 ast.parse 误判语法错误，进而读不到 BridgeConfig 里的默认 IMAP 配置。
        tree = ast.parse(backend_path.read_text(encoding='utf-8-sig'))
    except Exception:
        return {}

    target_names = {'imapHost', 'imapPort', 'imapUser', 'imapPass', 'imapFolder', 'imapLatestN'}
    result: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != 'BridgeConfig':
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
                continue
            name = str(stmt.target.id or '').strip()
            if name not in target_names or stmt.value is None:
                continue
            try:
                result[name] = ast.literal_eval(stmt.value)
            except Exception:
                continue
        break
    return result


def _resolve_codex_oauth_imap_runtime_values(
    *,
    imap_host: str,
    imap_port: int,
    imap_user: str,
    imap_pass: str,
    imap_folder: str,
    imap_latest_n: int,
    imap_auth_type: str = "password",
    imap_oauth_client_id: str = "",
    imap_oauth_refresh_token: str = "",
    imap_password_fallback: bool = False,
    imap_pop3_fallback: bool = False,
) -> dict[str, Any]:
    config = _load_codex_oauth_config_file()
    bridge_defaults = _load_bridge_config_imap_defaults()

    resolved_host, host_source = _pick_first_non_empty(
        (str(imap_host or '').strip(), '显式参数 imap_host'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_HOST', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_HOST'),
        (os.getenv('AIO_IMAP_HOST', ''), '环境变量 AIO_IMAP_HOST'),
        (_read_codex_oauth_config_value(config, 'imap_host', 'imapHost'), '配置文件 imap_host'),
        (bridge_defaults.get('imapHost'), 'BridgeConfig.imapHost'),
    )
    resolved_user, user_source = _pick_first_non_empty(
        (str(imap_user or '').strip(), '显式参数 imap_user'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_USER', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_USER'),
        (os.getenv('AIO_IMAP_USER', ''), '环境变量 AIO_IMAP_USER'),
        (_read_codex_oauth_config_value(config, 'imap_user', 'imapUser'), '配置文件 imap_user'),
        (bridge_defaults.get('imapUser'), 'BridgeConfig.imapUser'),
    )
    resolved_pass, pass_source = _pick_first_non_empty(
        (str(imap_pass or ''), '显式参数 imap_pass'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_PASS', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_PASS'),
        (os.getenv('AIO_IMAP_PASS', ''), '环境变量 AIO_IMAP_PASS'),
        (_read_codex_oauth_config_value(config, 'imap_pass', 'imapPass'), '配置文件 imap_pass'),
        (bridge_defaults.get('imapPass'), 'BridgeConfig.imapPass'),
    )
    resolved_auth_type, auth_type_source = _pick_first_non_empty(
        (str(imap_auth_type or '').strip(), '显式参数 imap_auth_type'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_AUTH_TYPE', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_AUTH_TYPE'),
        (_read_codex_oauth_config_value(config, 'imap_auth_type', 'imapAuthType'), '配置文件 imap_auth_type'),
    )
    resolved_oauth_client_id, oauth_client_id_source = _pick_first_non_empty(
        (str(imap_oauth_client_id or '').strip(), '显式参数 imap_oauth_client_id'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_OAUTH_CLIENT_ID', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_OAUTH_CLIENT_ID'),
        (_read_codex_oauth_config_value(config, 'imap_oauth_client_id', 'imapOauthClientId'), '配置文件 imap_oauth_client_id'),
    )
    resolved_oauth_refresh_token, oauth_refresh_token_source = _pick_first_non_empty(
        (str(imap_oauth_refresh_token or '').strip(), '显式参数 imap_oauth_refresh_token'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_OAUTH_REFRESH_TOKEN', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_OAUTH_REFRESH_TOKEN'),
        (_read_codex_oauth_config_value(config, 'imap_oauth_refresh_token', 'imapOauthRefreshToken'), '配置文件 imap_oauth_refresh_token'),
    )
    resolved_folder, folder_source = _pick_first_non_empty(
        (str(imap_folder or '').strip(), '显式参数 imap_folder'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_FOLDER', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_FOLDER'),
        (os.getenv('AIO_IMAP_FOLDER', ''), '环境变量 AIO_IMAP_FOLDER'),
        (_read_codex_oauth_config_value(config, 'imap_folder', 'imapFolder'), '配置文件 imap_folder'),
        (bridge_defaults.get('imapFolder'), 'BridgeConfig.imapFolder'),
    )
    raw_port, port_source = _pick_first_non_empty(
        (str(imap_port or '').strip(), '显式参数 imap_port'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_PORT', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_PORT'),
        (os.getenv('AIO_IMAP_PORT', ''), '环境变量 AIO_IMAP_PORT'),
        (_read_codex_oauth_config_value(config, 'imap_port', 'imapPort'), '配置文件 imap_port'),
        (bridge_defaults.get('imapPort'), 'BridgeConfig.imapPort'),
    )
    raw_latest_n, latest_n_source = _pick_first_non_empty(
        (str(imap_latest_n or '').strip(), '显式参数 imap_latest_n'),
        (os.getenv('AIO_CODEX_OAUTH_IMAP_LATEST_N', ''), '环境变量 AIO_CODEX_OAUTH_IMAP_LATEST_N'),
        (os.getenv('AIO_IMAP_LATEST_N', ''), '环境变量 AIO_IMAP_LATEST_N'),
        (_read_codex_oauth_config_value(config, 'imap_latest_n', 'imapLatestN'), '配置文件 imap_latest_n'),
        (bridge_defaults.get('imapLatestN'), 'BridgeConfig.imapLatestN'),
    )

    try:
        resolved_port_value = int(str(raw_port or '').strip() or '993')
    except Exception:
        resolved_port_value = 993
    if resolved_port_value <= 0:
        resolved_port_value = 993

    try:
        resolved_latest_n_value = int(str(raw_latest_n or '').strip() or '10')
    except Exception:
        resolved_latest_n_value = 10
    if resolved_latest_n_value <= 0:
        resolved_latest_n_value = 10

    return {
        'imap_host': str(resolved_host or 'imap.2925.com').strip() or 'imap.2925.com',
        'imap_port': int(resolved_port_value),
        'imap_user': str(resolved_user or '').strip(),
        'imap_pass': str(resolved_pass or ''),
        'imap_folder': str(resolved_folder or 'Inbox').strip() or 'Inbox',
        'imap_latest_n': int(resolved_latest_n_value),
        'imap_auth_type': 'oauth2' if str(resolved_auth_type or 'password').strip().lower() == 'oauth2' else 'password',
        'imap_oauth_client_id': str(resolved_oauth_client_id or '').strip(),
        'imap_oauth_refresh_token': str(resolved_oauth_refresh_token or '').strip(),
        'imap_password_fallback': bool(imap_password_fallback),
        'imap_pop3_fallback': bool(imap_pop3_fallback),
        'sources': {
            'imap_host': str(host_source or '').strip(),
            'imap_port': str(port_source or '').strip(),
            'imap_user': str(user_source or '').strip(),
            'imap_pass': str(pass_source or '').strip(),
            'imap_folder': str(folder_source or '').strip(),
            'imap_latest_n': str(latest_n_source or '').strip(),
            'imap_auth_type': str(auth_type_source or '').strip(),
            'imap_oauth_client_id': str(oauth_client_id_source or '').strip(),
            'imap_oauth_refresh_token': str(oauth_refresh_token_source or '').strip(),
        },
    }


def _resolve_shared_auth_path(path_str: str, *, default_rel: str) -> str:
    raw = str(path_str or '').strip() or str(default_rel or '').strip()
    return str(_resolve_any_path(raw))


def _iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _safe_filename_slug(text: str) -> str:
    safe = re.sub(r'[^0-9A-Za-z._@-]+', '_', str(text or '').strip())
    safe = safe.replace(':', '_').replace('\\', '_').replace('/', '_')
    return safe.strip('._-') or 'unknown'


def _mask_email(email: str) -> str:
    raw = str(email or '').strip()
    if '@' not in raw:
        return raw[:3] + ('***' if raw else '')
    local, domain = raw.split('@', 1)
    if len(local) <= 2:
        left = (local[:1] or '*') + '***'
    else:
        left = local[:2] + '***' + local[-1:]
    return f'{left}@{domain}'


def _read_bool_env(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, '') or '').strip().lower()
    if not raw:
        return bool(default)
    if raw in {'1', 'true', 'yes', 'on'}:
        return True
    if raw in {'0', 'false', 'no', 'off'}:
        return False
    return bool(default)


def _parse_optional_bool(raw_value: Any, *, source: str) -> bool | None:
    text = str(raw_value or '').strip().lower()
    if not text:
        return None
    if text in {'1', 'true', 'yes', 'on'}:
        return True
    if text in {'0', 'false', 'no', 'off'}:
        return False
    raise RuntimeError(f'Codex OAuth 布尔配置非法（来源：{source}）：{raw_value}')


def _is_loopback_host(host: str) -> bool:
    return str(host or '').strip().lower() in {'localhost', '127.0.0.1'}


def _default_port_for_scheme(scheme: str) -> int:
    low = str(scheme or '').strip().lower()
    if low == 'https':
        return 443
    if low == 'http':
        return 80
    return 0


def _format_netloc(host: str, port: int | None = None) -> str:
    h = str(host or '').strip()
    if ':' in h and not h.startswith('['):
        h = f'[{h}]'
    if port is None:
        return h
    return f'{h}:{int(port)}'


def _normalize_callback_target_host(host: str) -> str:
    final_host = str(host or '').strip()
    if final_host in {'', '0.0.0.0', '::', '[::]', '*'}:
        return '127.0.0.1'
    return final_host


def _validate_callback_port(raw_value: Any, *, source: str) -> int:
    text = str(raw_value or '').strip()
    try:
        port = int(text)
    except Exception as error:
        raise RuntimeError(f'Codex OAuth 回调端口非法（来源：{source}）：{text or raw_value}。端口范围必须为 1-65535。') from error
    if port <= 0 or port > 65535:
        raise RuntimeError(f'Codex OAuth 回调端口非法（来源：{source}）：{port}。端口范围必须为 1-65535。')
    return port


def get_codex_callback_base_url(
    *,
    host: str = DEFAULT_CALLBACK_HOST,
    port: int = DEFAULT_PUBLIC_CALLBACK_PORT,
    scheme: str = DEFAULT_CALLBACK_SCHEME,
) -> str:
    final_host = str(host or '').strip() or DEFAULT_CALLBACK_HOST
    final_scheme = str(scheme or DEFAULT_CALLBACK_SCHEME).strip().lower() or DEFAULT_CALLBACK_SCHEME
    final_port = _validate_callback_port(port, source='codex_callback_base_url')
    return urllib.parse.urlunparse((final_scheme, _format_netloc(final_host, final_port), '', '', '', ''))


def get_codex_redirect_uri(
    *,
    host: str = DEFAULT_CALLBACK_HOST,
    port: int = DEFAULT_PUBLIC_CALLBACK_PORT,
    scheme: str = DEFAULT_CALLBACK_SCHEME,
) -> str:
    parsed = urllib.parse.urlparse(get_codex_callback_base_url(host=host, port=port, scheme=scheme))
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, CALLBACK_PATH, '', '', ''))


def get_codex_callback_listener_url(*, host: str, port: int) -> str:
    final_host = str(host or '').strip() or DEFAULT_CALLBACK_BIND_HOST
    final_port = _validate_callback_port(port, source='codex_callback_listener')
    return urllib.parse.urlunparse(('http', _format_netloc(final_host, final_port), CALLBACK_PATH, '', '', ''))


def _pick_first_non_empty(*items: tuple[Any, str]) -> tuple[str, str]:
    for raw_value, source in items:
        text = str(raw_value or '').strip()
        if text:
            return text, source
    return '', ''


def _raise_callback_bind_error(*, host: str, port: int, error: Exception) -> RuntimeError:
    msg = str(error or '').strip() or type(error).__name__
    errno = getattr(error, 'errno', None)
    if errno in {48, 98, 10048} or ('address already in use' in msg.lower()) or ('只允许使用一次' in msg):
        return RuntimeError(
            'Codex OAuth 回调监听启动失败：'
            f'端口 {port} 已被占用（监听地址 {host}:{port}）。'
            '请改用环境变量 `CODEX_CALLBACK_PORT`、兼容旧变量 `AIO_CODEX_OAUTH_CALLBACK_PORT`，'
            '或在配置文件 `config.json` 中设置 `codex_callback_port`。'
        )
    return RuntimeError(f'Codex OAuth 回调监听启动失败（监听地址 {host}:{port}）：{msg}')


def _raise_callback_bridge_bind_error(*, host: str, port: int, error: Exception) -> RuntimeError:
    msg = str(error or '').strip() or type(error).__name__
    errno = getattr(error, 'errno', None)
    if errno in {48, 98, 10048} or ('address already in use' in msg.lower()) or ('只允许使用一次' in msg):
        return RuntimeError(
            'Codex OAuth 回调桥接启动失败：'
            f'端口 {port} 已被占用（监听地址 {host}:{port}）。'
            '如果当前是 VPS/NPM 场景，请关闭内置桥接 `CODEX_CALLBACK_BRIDGE_ENABLED=0`，'
            '让外部 1455 直接转发到 `CODEX_CALLBACK_PORT`。'
        )
    return RuntimeError(f'Codex OAuth 回调桥接启动失败（监听地址 {host}:{port}）：{msg}')


def _parse_redirect_uri(redirect_uri: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(str(redirect_uri or '').strip())
    scheme = str(parsed.scheme or '').strip().lower()
    if scheme not in {'http', 'https'}:
        raise RuntimeError('Codex OAuth redirect_uri 必须使用 http/https 协议。')
    if not parsed.hostname:
        raise RuntimeError('Codex OAuth redirect_uri 缺少主机名。')
    if str(parsed.path or '').strip() != CALLBACK_PATH:
        raise RuntimeError(f'Codex OAuth redirect_uri 路径必须为 {CALLBACK_PATH}。')
    return parsed


def _parsed_explicit_port(parsed: urllib.parse.ParseResult) -> int | None:
    try:
        raw_port = parsed.port
    except ValueError as error:
        raise RuntimeError('Codex OAuth redirect_uri 端口非法。端口范围必须为 1-65535。') from error
    if raw_port is None:
        return None
    return _validate_callback_port(raw_port, source='codex_redirect_uri')


def _parsed_port_or_default(parsed: urllib.parse.ParseResult) -> int:
    explicit_port = _parsed_explicit_port(parsed)
    if explicit_port is not None:
        return explicit_port
    default_port = _default_port_for_scheme(parsed.scheme)
    if default_port <= 0:
        raise RuntimeError('OAuth 回调端口非法。')
    return default_port


def _build_redirect_uri(
    parsed: urllib.parse.ParseResult,
    *,
    host: str | None = None,
    port: int | None = None,
    scheme: str | None = None,
) -> str:
    final_scheme = str(scheme or parsed.scheme or DEFAULT_CALLBACK_SCHEME).strip().lower()
    final_host = str(host or parsed.hostname or '').strip()
    if not final_host:
        raise RuntimeError('OAuth 回调主机名为空。')
    explicit_port = _parsed_explicit_port(parsed)
    if port is not None:
        netloc = _format_netloc(final_host, _validate_callback_port(port, source='codex_redirect_uri'))
    elif explicit_port is not None:
        netloc = _format_netloc(final_host, explicit_port)
    else:
        netloc = _format_netloc(final_host)
    return urllib.parse.urlunparse((final_scheme, netloc, CALLBACK_PATH, '', '', ''))


def _build_callback_url_hints(redirect_uri: str) -> tuple[str, ...]:
    parsed = urllib.parse.urlparse(str(redirect_uri or '').strip())
    host = str(parsed.hostname or '').strip().lower()
    path = str(parsed.path or CALLBACK_PATH).strip().lower() or CALLBACK_PATH
    port = _parsed_port_or_default(parsed)
    default_port = _default_port_for_scheme(parsed.scheme)
    hints: set[str] = set()

    def _add_host_hints(target_host: str) -> None:
        clean_host = str(target_host or '').strip().lower()
        if not clean_host:
            return
        hints.add(f'{clean_host}:{port}{path}')
        if port == default_port and default_port > 0:
            hints.add(f'{clean_host}{path}')

    if host:
        _add_host_hints(host)
        if host == 'localhost':
            _add_host_hints('127.0.0.1')
        elif host == '127.0.0.1':
            _add_host_hints('localhost')
    return tuple(sorted(hints))


def _resolve_oauth_runtime_config() -> OAuthRuntimeConfig:
    notices: list[str] = []
    config = _load_codex_oauth_config_file()

    client_id, _client_id_source = _pick_first_non_empty(
        (os.getenv('CODEX_CLIENT_ID', ''), '环境变量 CODEX_CLIENT_ID'),
        (os.getenv('AIO_CODEX_OAUTH_CLIENT_ID', ''), '环境变量 AIO_CODEX_OAUTH_CLIENT_ID'),
        (
            _read_codex_oauth_config_value(config, 'codex_client_id', 'codexClientId', 'client_id', 'clientId'),
            '配置文件 codex_client_id',
        ),
    )
    client_id = client_id or DEFAULT_CLIENT_ID

    callback_bind_host, _callback_bind_host_source = _pick_first_non_empty(
        (os.getenv('CODEX_CALLBACK_BIND_HOST', ''), '环境变量 CODEX_CALLBACK_BIND_HOST'),
        (os.getenv('AIO_CODEX_OAUTH_CALLBACK_BIND_HOST', ''), '环境变量 AIO_CODEX_OAUTH_CALLBACK_BIND_HOST'),
        (
            _read_codex_oauth_config_value(
                config,
                'codex_callback_bind_host',
                'codexCallbackBindHost',
                'callback_bind_host',
                'callbackBindHost',
            ),
            '配置文件 codex_callback_bind_host',
        ),
    )
    callback_bind_host = callback_bind_host or DEFAULT_CALLBACK_BIND_HOST

    raw_callback_port, callback_port_source = _pick_first_non_empty(
        (os.getenv('CODEX_CALLBACK_PORT', ''), '环境变量 CODEX_CALLBACK_PORT'),
        (os.getenv('AIO_CODEX_OAUTH_CALLBACK_PORT', ''), '环境变量 AIO_CODEX_OAUTH_CALLBACK_PORT'),
        (
            _read_codex_oauth_config_value(config, 'codex_callback_port', 'codexCallbackPort', 'callback_port', 'callbackPort'),
            '配置文件 codex_callback_port',
        ),
    )
    raw_redirect_uri, redirect_uri_source = _pick_first_non_empty(
        (os.getenv('CODEX_REDIRECT_URI', ''), '环境变量 CODEX_REDIRECT_URI'),
        (os.getenv('AIO_CODEX_OAUTH_REDIRECT_URI', ''), '环境变量 AIO_CODEX_OAUTH_REDIRECT_URI'),
        (
            _read_codex_oauth_config_value(config, 'codex_redirect_uri', 'codexRedirectUri', 'redirect_uri', 'redirectUri'),
            '配置文件 codex_redirect_uri',
        ),
    )

    raw_bridge_enabled, bridge_enabled_source = _pick_first_non_empty(
        (os.getenv('CODEX_CALLBACK_BRIDGE_ENABLED', ''), '环境变量 CODEX_CALLBACK_BRIDGE_ENABLED'),
        (os.getenv('AIO_CODEX_OAUTH_CALLBACK_BRIDGE_ENABLED', ''), '环境变量 AIO_CODEX_OAUTH_CALLBACK_BRIDGE_ENABLED'),
        (
            _read_codex_oauth_config_value(
                config,
                'codex_callback_bridge_enabled',
                'codexCallbackBridgeEnabled',
                'callback_bridge_enabled',
                'callbackBridgeEnabled',
            ),
            '配置文件 codex_callback_bridge_enabled',
        ),
    )
    raw_bridge_bind_host, _bridge_bind_host_source = _pick_first_non_empty(
        (os.getenv('CODEX_CALLBACK_BRIDGE_BIND_HOST', ''), '环境变量 CODEX_CALLBACK_BRIDGE_BIND_HOST'),
        (os.getenv('AIO_CODEX_OAUTH_CALLBACK_BRIDGE_BIND_HOST', ''), '环境变量 AIO_CODEX_OAUTH_CALLBACK_BRIDGE_BIND_HOST'),
        (
            _read_codex_oauth_config_value(
                config,
                'codex_callback_bridge_bind_host',
                'codexCallbackBridgeBindHost',
                'callback_bridge_bind_host',
                'callbackBridgeBindHost',
            ),
            '配置文件 codex_callback_bridge_bind_host',
        ),
    )

    callback_port = _validate_callback_port(
        raw_callback_port or DEFAULT_CALLBACK_PORT,
        source=callback_port_source or f'默认值 {DEFAULT_CALLBACK_PORT}',
    )

    if raw_redirect_uri:
        redirect_uri = _build_redirect_uri(_parse_redirect_uri(raw_redirect_uri))
    else:
        redirect_uri = get_codex_redirect_uri(
            host=DEFAULT_CALLBACK_HOST,
            port=DEFAULT_PUBLIC_CALLBACK_PORT,
            scheme=DEFAULT_CALLBACK_SCHEME,
        )
        redirect_uri_source = f'默认值 {DEFAULT_REDIRECT_URI}'

    force_localhost_for_default = _read_bool_env('AIO_CODEX_OAUTH_FORCE_LOCALHOST_FOR_DEFAULT_CLIENT', False)
    if client_id == DEFAULT_CLIENT_ID and redirect_uri != DEFAULT_REDIRECT_URI:
        notices.append(
            '检测到默认 Codex client_id 使用了非默认回调地址：'
            f'{redirect_uri}。请确认 authorize、token exchange 与本地监听使用完全一致的 redirect_uri；'
            '如果授权页仍直接跳转错误页，更可能是上游对 client_id / redirect_uri 组合的限制。'
        )
        if force_localhost_for_default:
            redirect_uri = DEFAULT_REDIRECT_URI
            notices.append(
                '已按 AIO_CODEX_OAUTH_FORCE_LOCALHOST_FOR_DEFAULT_CLIENT=1 '
                f'强制回退到默认对外回调地址 {DEFAULT_REDIRECT_URI}。'
            )

    redirect_parsed = _parse_redirect_uri(redirect_uri)
    redirect_host = str(redirect_parsed.hostname or '').strip()
    redirect_port = _parsed_port_or_default(redirect_parsed)
    redirect_is_loopback = _is_loopback_host(redirect_host)

    bridge_enabled_raw = _parse_optional_bool(raw_bridge_enabled, source=bridge_enabled_source) if raw_bridge_enabled else None
    bridge_bind_host = str(raw_bridge_bind_host or '').strip()
    bridge_enabled = False
    bridge_port = 0
    bridge_target_host = ''
    bridge_target_port = 0

    if redirect_port == callback_port:
        if bridge_enabled_raw is True:
            notices.append('对外回调端口与本地监听端口一致，已忽略内置桥接配置。')
    elif redirect_is_loopback:
        bridge_enabled = True if bridge_enabled_raw is None else bool(bridge_enabled_raw)
        if not bridge_enabled:
            raise RuntimeError(
                'Codex OAuth 回调配置冲突：'
                f'{redirect_uri_source} 当前指向 {redirect_uri}，但本地真实监听端口为 {callback_port}。'
                '在 localhost / 127.0.0.1 场景下，若对外端口与项目监听端口不同，'
                '必须开启 `CODEX_CALLBACK_BRIDGE_ENABLED=1`，或把 `CODEX_CALLBACK_PORT` 改为同端口。'
            )
        bridge_bind_host = bridge_bind_host or redirect_host or DEFAULT_CALLBACK_HOST
    else:
        bridge_enabled = bool(bridge_enabled_raw) if bridge_enabled_raw is not None else False
        if bridge_enabled:
            bridge_bind_host = bridge_bind_host or callback_bind_host or DEFAULT_CALLBACK_BIND_HOST
        else:
            notices.append(
                '当前为公网 OAuth 回调模式：请确保外部 '
                f'{redirect_uri} 能转发到本地监听 {callback_bind_host}:{callback_port}。'
            )

    if bridge_enabled:
        bridge_port = redirect_port
        bridge_target_host = _normalize_callback_target_host(callback_bind_host)
        bridge_target_port = callback_port
        notices.append(
            '已启用本地回调桥接：'
            f'{get_codex_callback_listener_url(host=bridge_bind_host, port=bridge_port)} '
            f'-> {get_codex_callback_listener_url(host=bridge_target_host, port=bridge_target_port)}。'
        )

    return OAuthRuntimeConfig(
        client_id=client_id,
        redirect_uri=redirect_uri,
        callback_bind_host=callback_bind_host,
        callback_port=callback_port,
        callback_url_hints=_build_callback_url_hints(redirect_uri),
        bridge_enabled=bridge_enabled,
        bridge_bind_host=bridge_bind_host,
        bridge_port=bridge_port,
        bridge_target_host=bridge_target_host,
        bridge_target_port=bridge_target_port,
        notices=tuple(notices),
    )


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def generate_state() -> str:
    return _b64url_no_pad(os.urandom(32))


def generate_pkce() -> PKCECodes:
    verifier = _b64url_no_pad(os.urandom(96))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode('utf-8')).digest())
    return PKCECodes(code_verifier=verifier, code_challenge=challenge)


def build_auth_url(*, state: str, pkce: PKCECodes, client_id: str, redirect_uri: str) -> str:
    params = {
        'response_type': 'code',
        'client_id': str(client_id or '').strip(),
        'redirect_uri': str(redirect_uri or '').strip(),
        'scope': 'openid profile email offline_access',
        'code_challenge': pkce.code_challenge,
        'code_challenge_method': 'S256',
        'id_token_add_organizations': 'true',
        'state': str(state or '').strip(),
    }
    simplified_raw = str(os.getenv('OAI_CODEX_OAUTH_SIMPLIFIED_FLOW') or '').strip().lower()
    if simplified_raw not in {'0', 'false', 'no', 'n', 'off'}:
        params['codex_cli_simplified_flow'] = 'true'
    return f'{AUTH_URL}?{urllib.parse.urlencode(params)}'


def _parse_jwt_payload_no_verify(jwt_token: str) -> dict[str, Any]:
    token = str(jwt_token or '').strip()
    parts = token.split('.')
    if len(parts) != 3:
        return {}
    payload = parts[1]
    pad = '=' * ((4 - (len(payload) % 4)) % 4)
    try:
        raw = base64.urlsafe_b64decode((payload + pad).encode('utf-8'))
        obj = json.loads(raw.decode('utf-8'))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _extract_plan_and_account_id(id_token: str, access_token: str = '') -> tuple[str, str]:
    payload = _parse_jwt_payload_no_verify(id_token)
    auth = payload.get('https://api.openai.com/auth')
    if not isinstance(auth, dict):
        auth = {}
    plan = str(auth.get('chatgpt_plan_type') or '').strip()
    account_id = str(auth.get('chatgpt_account_id') or '').strip()
    # 回退：plan_type/account_id 常在 access_token 的 claims 里（id_token 可能不含），
    # 缺失时从 access_token 补齐，保证顶层 chatgpt_plan_type 正确记录（如 team）。
    if (not plan or not account_id) and access_token:
        at_auth = _parse_jwt_payload_no_verify(access_token).get('https://api.openai.com/auth')
        if isinstance(at_auth, dict):
            if not plan:
                plan = str(at_auth.get('chatgpt_plan_type') or '').strip()
            if not account_id:
                account_id = str(at_auth.get('chatgpt_account_id') or '').strip()
    return plan, account_id


def _extract_access_token_workspace_claims(access_token: str) -> dict[str, str]:
    payload = _parse_jwt_payload_no_verify(access_token)
    auth = payload.get('https://api.openai.com/auth')
    if not isinstance(auth, dict):
        return {}
    return {
        'account_id': str(auth.get('chatgpt_account_id') or '').strip(),
        'plan_type': str(auth.get('chatgpt_plan_type') or '').strip(),
        'user_id': str(auth.get('chatgpt_user_id') or '').strip(),
        'jti': str(payload.get('jti') or '').strip(),
    }


def _choose_http_provider_workspace_context(
    *,
    session_payload: Any,
    session_access_token: str,
) -> dict[str, Any]:
    session_claims = _extract_access_token_workspace_claims(session_access_token)
    workspaces = _collect_http_provider_workspaces(session_payload)
    selected_workspace = _pick_http_provider_workspace(workspaces)
    session_workspace_id = str(selected_workspace.get('workspace_id') or '').strip()
    if session_workspace_id:
        return {
            'workspace_id': session_workspace_id,
            'source': 'session',
            'session_claims': session_claims,
            'session_workspace_id': session_workspace_id,
            'workspaces': workspaces,
            'selected_workspace': selected_workspace,
        }
    return {
        'workspace_id': '',
        'source': '',
        'session_claims': session_claims,
        'session_workspace_id': session_workspace_id,
        'workspaces': workspaces,
        'selected_workspace': selected_workspace,
    }


def _exchange_code_for_tokens(
    *,
    code: str,
    pkce: PKCECodes,
    client_id: str,
    redirect_uri: str,
    proxy_url: Optional[str] = None,
) -> dict[str, Any]:
    payload = {
        'grant_type': 'authorization_code',
        'client_id': str(client_id or '').strip(),
        'code': str(code or '').strip(),
        'redirect_uri': str(redirect_uri or '').strip(),
        'code_verifier': pkce.code_verifier,
    }
    resolved_proxy_url = (
        _resolve_codex_proxy_url()
        if proxy_url is None
        else str(proxy_url or '').strip()
    )
    request_kwargs: dict[str, Any] = {}
    if resolved_proxy_url:
        request_kwargs['proxies'] = {
            'http': resolved_proxy_url,
            'https': resolved_proxy_url,
        }
    response = requests.post(
        TOKEN_URL,
        json=payload,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
        timeout=60,
        **request_kwargs,
    )
    try:
        obj = response.json()
    except Exception:
        obj = {}
    if not isinstance(obj, dict):
        raise RuntimeError('token 响应格式异常')
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(f'HTTP {response.status_code} {obj}')
    return obj


def _summarize_oauth_token_response_for_trace(
    *,
    payload: dict[str, Any],
    text: str,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        'payloadKeys': sorted(str(key) for key in payload.keys()),
    }
    for key in ('error', 'error_description', 'errorDescription', 'token_type', 'scope'):
        value = str(payload.get(key) or '').strip()
        if value:
            summary[key] = _compress_debug_text(value, limit=240)
    expires_in = payload.get('expires_in')
    try:
        if expires_in not in (None, ''):
            summary['expiresIn'] = int(expires_in)
    except Exception:
        pass
    if not summary.get('error'):
        return summary
    if text:
        summary['bodySnippet'] = _compress_debug_text(text, limit=400)
    return summary


async def _exchange_code_for_tokens_with_context(
    request_ctx: Any,
    *,
    code: str,
    pkce: PKCECodes,
    client_id: str,
    redirect_uri: str,
    trace: _TraceWriter,
    timeout_ms: int = 60_000,
) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            'grant_type': 'authorization_code',
            'client_id': str(client_id or '').strip(),
            'code': str(code or '').strip(),
            'redirect_uri': str(redirect_uri or '').strip(),
            'code_verifier': pkce.code_verifier,
        }
    )
    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'accept': 'application/json',
        'origin': 'https://auth.openai.com',
        'referer': 'https://auth.openai.com/',
    }
    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'http_token_exchange',
            'method': 'POST',
            'url': TOKEN_URL,
            'requestHeaders': dict(headers),
            'requestFormKeys': ['grant_type', 'client_id', 'code', 'redirect_uri', 'code_verifier'],
        }
    )
    payload, status, text, response_url, response_headers = await _request_with_context(
        request_ctx,
        method='POST',
        url=TOKEN_URL,
        headers=headers,
        body_text=body,
        timeout_ms=int(max(1_000, timeout_ms)),
        max_redirects=0,
    )
    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'http_token_exchange',
            'status': status,
            'responseUrl': _sanitize_url_for_log(response_url),
            'responseHeaders': response_headers,
            'responseSummary': _summarize_oauth_token_response_for_trace(payload=payload, text=text),
        }
    )
    if not isinstance(payload, dict):
        raise RuntimeError('http_auth_token_exchange_failed: token 响应格式异常')
    if status < 200 or status >= 300:
        error_code = str(payload.get('error') or '').strip()
        error_desc = str(payload.get('error_description') or payload.get('errorDescription') or '').strip()
        detail = f'HTTP {int(status)}'
        if error_code:
            detail += f' {error_code}'
        if error_desc:
            detail += f' ({error_desc})'
        raise RuntimeError(f'http_auth_token_exchange_failed: {detail}')
    access_token = str(payload.get('access_token') or '').strip()
    if not access_token:
        error_code = str(payload.get('error') or '').strip()
        error_desc = str(payload.get('error_description') or payload.get('errorDescription') or '').strip()
        detail = '响应缺少 access_token'
        if error_code:
            detail += f'，error={error_code}'
        if error_desc:
            detail += f'，detail={error_desc}'
        raise RuntimeError(f'http_auth_token_exchange_failed: {detail}')
    return payload


def _http_provider_enabled() -> bool:
    return True


def _default_codex_oauth_provider() -> str:
    return 'http'


def _oauth_browser_inline_signup_enabled() -> bool:
    return str(os.environ.get('X9_OAUTH_BROWSER_INLINE_SIGNUP_TEST') or '').strip() == '1'


def _normalize_codex_oauth_provider(raw_provider: Any) -> str:
    provider = str(raw_provider or '').strip().lower()
    if _oauth_browser_inline_signup_enabled():
        return 'browser'
    if not provider:
        return _default_codex_oauth_provider()
    if provider in {'http', 'protocol'}:
        return 'http'
    if provider == 'browser':
        return 'browser'
    raise RuntimeError(
        f'Codex OAuth 失败：不支持的 provider={provider}，当前支持 http / browser（protocol 会兼容映射到 http）。'
    )


def _cloudflare_tab_enter_enabled() -> bool:
    return _read_bool_env('AIO_CODEX_OAUTH_CF_TAB_ENTER_ENABLED', True)


def _codex_browser_profile_reuse_enabled() -> bool:
    return _read_bool_env('AIO_CODEX_OAUTH_REUSE_BROWSER_PROFILE_STATE', True)


_DIRECT_PROXY_MARKERS: frozenset[str] = frozenset({'direct', 'none', 'off', '0', 'false', 'no'})


def _normalize_browser_proxy_url(proxy_url: str) -> str:
    raw = str(proxy_url or '').strip()
    if not raw:
        return ''
    if raw.lower() in _DIRECT_PROXY_MARKERS:
        return ''

    if ('://' not in raw) and (raw.count(':') >= 3):
        parts = raw.split(':')
        host = str(parts[0] or '').strip()
        port_text = str(parts[1] or '').strip()
        username = str(parts[2] or '').strip()
        password = ':'.join(parts[3:]).strip()
        if host and port_text.isdigit() and username and password:
            port_num = int(port_text)
            if 1 <= port_num <= 65535:
                raw = (
                    'http://'
                    f'{urllib.parse.quote(username, safe="")}:'
                    f'{urllib.parse.quote(password, safe="")}@{host}:{port_num}'
                )
    if '://' not in raw:
        raw = 'http://' + raw

    try:
        parsed = urllib.parse.urlparse(raw)
        if str(parsed.path or '').strip().lower().endswith('.pac'):
            raise ValueError('PAC proxy URLs are not supported')
        if str(parsed.path or '').strip() not in {'', '/'} or parsed.params or parsed.query or parsed.fragment:
            raise ValueError('proxy URL must not contain a path, query, or fragment')
        scheme = str(parsed.scheme or '').strip().lower()
        if scheme == 'socks5h':
            # Chromium/Playwright use remote DNS for SOCKS5 and accept the
            # browser-facing spelling `socks5`, not requests' `socks5h` alias.
            scheme = 'socks5'
        if scheme not in {'http', 'https', 'socks5'}:
            raise ValueError('unsupported browser proxy scheme')
        host = str(parsed.hostname or '').strip()
        if (not scheme) or (not host) or any(char.isspace() for char in host):
            raise ValueError('proxy URL is missing a scheme or host')
        port = parsed.port
        host_for_url = f'[{host}]' if ':' in host and not host.startswith('[') else host
        userinfo = ''
        if parsed.username is not None:
            username = urllib.parse.quote(urllib.parse.unquote(str(parsed.username)), safe='')
            userinfo = username
            if parsed.password is not None:
                password = urllib.parse.quote(urllib.parse.unquote(str(parsed.password)), safe='')
                userinfo += f':{password}'
            userinfo += '@'
        netloc = f'{userinfo}{host_for_url}:{int(port)}' if port else f'{userinfo}{host_for_url}'
        return urllib.parse.urlunparse((scheme, netloc, '', '', '', ''))
    except ValueError as error:
        raise ValueError('invalid browser proxy URL') from error
    except Exception as error:
        raise ValueError('invalid browser proxy URL') from error


def _build_playwright_proxy_option(proxy_url: str) -> dict[str, str] | None:
    normalized = _normalize_browser_proxy_url(proxy_url)
    if not normalized:
        return None
    try:
        parsed = urllib.parse.urlparse(normalized)
        host = str(parsed.hostname or '').strip()
        host_for_url = f'[{host}]' if ':' in host and not host.startswith('[') else host
        port = parsed.port
        server = f'{parsed.scheme}://{host_for_url}:{int(port)}' if port else f'{parsed.scheme}://{host_for_url}'
        out: dict[str, str] = {'server': server}
        if parsed.username is not None:
            out['username'] = urllib.parse.unquote(str(parsed.username))
        if parsed.password is not None:
            out['password'] = urllib.parse.unquote(str(parsed.password))
        return out
    except Exception as error:
        raise ValueError('invalid browser proxy URL') from error


def _mask_proxy_url_for_log(proxy_url: str) -> str:
    raw = str(proxy_url or '').strip()
    if not raw:
        return 'none'
    try:
        normalized = _normalize_browser_proxy_url(raw)
        if not normalized:
            return 'none'
        parsed = urllib.parse.urlparse(normalized)
        host = str(parsed.hostname or '').strip()
        host_for_url = f'[{host}]' if ':' in host and not host.startswith('[') else host
        port = f':{int(parsed.port)}' if parsed.port else ''
        auth = '<redacted>@' if parsed.username is not None or parsed.password is not None else ''
        return f'{parsed.scheme}://{auth}{host_for_url}{port}'
    except Exception:
        return '<invalid-proxy>'


def _is_personal_workspace_label(text: Any) -> bool:
    raw = str(text or '').strip()
    if not raw:
        return False
    low = raw.lower()
    return (
        ('personal account' in low)
        or (low == 'personal')
        or ('个人账户' in raw)
        or ('个人账号' in raw)
        or (raw == '个人')
        or raw.endswith('个人')
    )


def _pick_http_provider_workspace_id(session_payload: Any) -> str:
    selected_workspace = _pick_http_provider_workspace(_collect_http_provider_workspaces(session_payload))
    return str(selected_workspace.get('workspace_id') or '').strip()


def _normalize_http_provider_workspace_entry(
    item: Any,
    *,
    source: str,
    preferred: bool = False,
) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    workspace_id = str(
        item.get('id')
        or item.get('workspace_id')
        or item.get('workspaceId')
        or item.get('account_id')
        or item.get('accountId')
        or ''
    ).strip()
    if not workspace_id:
        return {}
    kind = str(item.get('structure') or item.get('type') or item.get('kind') or '').strip().lower()
    label = str(
        item.get('name')
        or item.get('title')
        or item.get('label')
        or item.get('display_name')
        or item.get('displayName')
        or item.get('workspace_name')
        or item.get('workspaceName')
        or item.get('organization_name')
        or item.get('organizationName')
        or item.get('slug')
        or ''
    ).strip()
    profile_picture_alt_text = str(
        item.get('profile_picture_alt_text')
        or item.get('profilePictureAltText')
        or item.get('profile_alt_text')
        or ''
    ).strip()
    is_personal = bool((kind == 'personal') or (label and _is_personal_workspace_label(label)))
    if is_personal and not kind:
        kind = 'personal'
    display_name = label or profile_picture_alt_text or workspace_id
    return {
        'workspace_id': workspace_id,
        'kind': kind,
        'label': label,
        'display_name': display_name,
        'is_personal': is_personal,
        'is_non_personal': not is_personal,
        'source': str(source or '').strip(),
        'preferred': bool(preferred),
    }


def _collect_http_provider_workspaces(session_payload: Any) -> list[dict[str, Any]]:
    if not isinstance(session_payload, dict):
        return []
    out: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}

    def _merge_item(item: Any, *, source: str, preferred: bool = False) -> None:
        entry = _normalize_http_provider_workspace_entry(item, source=source, preferred=preferred)
        workspace_id = str(entry.get('workspace_id') or '').strip()
        if not workspace_id:
            return
        existing = by_id.get(workspace_id)
        if existing is None:
            by_id[workspace_id] = entry
            out.append(entry)
            return
        if entry.get('label') and not existing.get('label'):
            existing['label'] = entry.get('label')
        if entry.get('display_name') and not existing.get('display_name'):
            existing['display_name'] = entry.get('display_name')
        if entry.get('kind') and not existing.get('kind'):
            existing['kind'] = entry.get('kind')
        if entry.get('source') and not existing.get('source'):
            existing['source'] = entry.get('source')
        if bool(entry.get('preferred')):
            existing['preferred'] = True
        if bool(entry.get('is_personal')):
            existing['is_personal'] = True
            existing['is_non_personal'] = False

    selected_keys = (
        'workspace',
        'selectedWorkspace',
        'selected_workspace',
        'currentWorkspace',
        'current_workspace',
    )
    for key in selected_keys:
        _merge_item(session_payload.get(key), source=f'session.{key}', preferred=True)
    account = session_payload.get('account')
    if isinstance(account, dict):
        _merge_item(account, source='session.account', preferred=False)
        for key in ('workspace', 'selectedWorkspace', 'selected_workspace'):
            _merge_item(account.get(key), source=f'session.account.{key}', preferred=True)
    for collection_key in ('workspaces', 'accounts'):
        items = session_payload.get(collection_key)
        if not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            _merge_item(item, source=f'session.{collection_key}[{index}]', preferred=False)
    return out


def _pick_http_provider_workspace(workspaces: Sequence[dict[str, Any]]) -> dict[str, Any]:
    for item in workspaces:
        if isinstance(item, dict) and bool(item.get('is_personal')):
            return dict(item)
    for item in workspaces:
        if isinstance(item, dict):
            return dict(item)
    return {}


def _http_workspace_select_curl_enabled() -> bool:
    return _read_bool_env('AIO_CODEX_OAUTH_WORKSPACE_SELECT_CURL_ENABLED', True)


def _http_codex_consent_request_ctx_fallback_enabled() -> bool:
    return _read_bool_env('AIO_CODEX_OAUTH_CODEX_CONSENT_REQUEST_CTX_FALLBACK', False)


def _resolve_http_provider_curl_impersonate() -> str:
    if curl_cffi_requests is None:
        return ''
    preferred = str(os.getenv('AIO_CODEX_OAUTH_HTTP_PROVIDER_CURL_IMPERSONATE') or '').strip()
    available = _available_curl_cffi_impersonates()
    if preferred:
        if (not available) or preferred in available:
            return preferred
    for candidate in _HTTP_WORKSPACE_SELECT_CURL_IMPERSONATES:
        value = str(candidate or '').strip()
        if not value:
            continue
        if available and value not in available:
            continue
        return value
    return preferred if preferred and (not available or preferred in available) else ''


def _available_curl_cffi_impersonates() -> set[str]:
    browser_type = getattr(curl_cffi_requests, 'BrowserType', None)
    if browser_type is None:
        return set()
    available: set[str] = set()
    for name in dir(browser_type):
        if name.startswith('_'):
            continue
        value = getattr(browser_type, name, None)
        if isinstance(value, str):
            normalized = str(getattr(value, 'value', value) or '').strip()
            if normalized:
                available.add(normalized)
    return available


def _resolve_workspace_select_curl_impersonate_candidates(*, is_personal: bool) -> tuple[str, ...]:
    if curl_cffi_requests is None:
        return ()
    env_key = (
        'AIO_CODEX_OAUTH_WORKSPACE_SELECT_CURL_PERSONAL_IMPERSONATES'
        if is_personal
        else 'AIO_CODEX_OAUTH_WORKSPACE_SELECT_CURL_IMPERSONATES'
    )
    raw = str(os.getenv(env_key) or '').strip()
    candidates = (
        [item.strip() for item in raw.split(',') if item.strip()]
        if raw
        else list(
            _HTTP_WORKSPACE_SELECT_CURL_PERSONAL_IMPERSONATES
            if is_personal
            else _HTTP_WORKSPACE_SELECT_CURL_IMPERSONATES
        )
    )
    available = _available_curl_cffi_impersonates()
    out: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        value = str(item or '').strip()
        if (not value) or (value in seen):
            continue
        if available and value not in available:
            continue
        seen.add(value)
        out.append(value)
    return tuple(out)


def _build_http_codex_consent_attempts(
    *,
    workspace: dict[str, Any],
    preferred_impersonate: str = '',
) -> list[dict[str, str]]:
    is_personal = bool(workspace.get('is_personal'))
    out: list[dict[str, str]] = []
    if _http_workspace_select_curl_enabled():
        preferred = str(preferred_impersonate or '').strip()
        impersonates = (
            (preferred,)
            if preferred
            else _resolve_workspace_select_curl_impersonate_candidates(is_personal=is_personal)
        )
        for impersonate in impersonates:
            out.append(
                {
                    'mode': 'curl_cffi',
                    'label': f'curl_cffi_{impersonate}',
                    'impersonate': impersonate,
                }
            )
    if _http_codex_consent_request_ctx_fallback_enabled():
        out.append({'mode': 'request_ctx', 'label': 'playwright_request_context'})
    return out


def _storage_state_cookie_matches_url(cookie: Any, *, url: str, now_ts: float | None = None) -> bool:
    if not isinstance(cookie, dict):
        return False
    try:
        parsed = urllib.parse.urlsplit(str(url or '').strip())
    except Exception:
        return False
    host = str(parsed.hostname or '').strip().lower()
    if not host:
        return False
    scheme = str(parsed.scheme or '').strip().lower()
    target_path = str(parsed.path or '/').strip() or '/'
    if bool(cookie.get('secure')) and scheme != 'https':
        return False
    domain = str(cookie.get('domain') or '').strip().lower()
    if domain:
        bare_domain = domain.lstrip('.')
        if host != bare_domain and not host.endswith(f'.{bare_domain}'):
            return False
    cookie_path = str(cookie.get('path') or '/').strip() or '/'
    if cookie_path != '/':
        normalized_cookie_path = cookie_path.rstrip('/')
        if target_path != normalized_cookie_path and not target_path.startswith(f'{normalized_cookie_path}/'):
            return False
    expires = cookie.get('expires')
    try:
        expires_num = float(expires)
    except Exception:
        expires_num = 0.0
    if expires_num > 0:
        current_ts = float(now_ts or time.time())
        if current_ts >= expires_num:
            return False
    return bool(str(cookie.get('name') or '').strip())


def _build_storage_state_cookie_header_for_url(storage_state: Any, *, url: str) -> str:
    cookies = storage_state.get('cookies') if isinstance(storage_state, dict) else None
    if not isinstance(cookies, list):
        return ''
    parts: list[str] = []
    now_ts = time.time()
    for cookie in cookies:
        if not _storage_state_cookie_matches_url(cookie, url=url, now_ts=now_ts):
            continue
        name = str(cookie.get('name') or '').strip()
        if not name:
            continue
        parts.append(f'{name}={str(cookie.get("value") or "")}')
    return '; '.join(parts)


def _read_storage_state_cookie_value(storage_state: Any, *, cookie_name: str) -> str:
    cookies = storage_state.get('cookies') if isinstance(storage_state, dict) else None
    if not isinstance(cookies, list):
        return ''
    target_name = str(cookie_name or '').strip().lower()
    if not target_name:
        return ''
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        current_name = str(cookie.get('name') or '').strip().lower()
        if current_name != target_name:
            continue
        return str(cookie.get('value') or '').strip()
    return ''


def _decode_base64_json_cookie_value(cookie_value: str) -> dict[str, Any]:
    raw = str(cookie_value or '').strip()
    if not raw:
        return {}
    try:
        encoded = str(raw.split('.', 1)[0] or '').strip()
        if not encoded:
            return {}
        padding = '=' * ((4 - (len(encoded) % 4)) % 4)
        payload = base64.urlsafe_b64decode((encoded + padding).encode('utf-8')).decode('utf-8', errors='ignore')
        data = json.loads(payload or '{}')
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _choose_http_provider_workspace_context_from_storage_state(storage_state: Any) -> dict[str, Any]:
    auth_session_cookie = _read_storage_state_cookie_value(storage_state, cookie_name='oai-client-auth-session')
    auth_session_payload = _decode_base64_json_cookie_value(auth_session_cookie)
    workspaces = _collect_http_provider_workspaces(auth_session_payload)
    selected_workspace = _pick_http_provider_workspace(workspaces)
    workspace_id = str(selected_workspace.get('workspace_id') or '').strip()
    source = 'storage_state.oai-client-auth-session' if workspace_id else ''
    return {
        'workspace_id': workspace_id,
        'source': source,
        'session_claims': {},
        'session_workspace_id': '',
        'workspaces': workspaces,
        'selected_workspace': selected_workspace,
    }


def _workspace_context_selected_workspace(workspace_ctx: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(workspace_ctx, dict):
        return {}
    selected_workspace = workspace_ctx.get('selected_workspace')
    if isinstance(selected_workspace, dict):
        return dict(selected_workspace)
    workspace_id = str(workspace_ctx.get('workspace_id') or '').strip()
    if not workspace_id:
        return {}
    for item in workspace_ctx.get('workspaces') or []:
        if not isinstance(item, dict):
            continue
        if str(item.get('workspace_id') or '').strip() != workspace_id:
            continue
        return dict(item)
    return {}


def _workspace_context_is_personal(workspace_ctx: dict[str, Any] | None) -> bool:
    selected_workspace = _workspace_context_selected_workspace(workspace_ctx)
    if bool(selected_workspace.get('is_personal')):
        return True
    return str(selected_workspace.get('kind') or '').strip().lower() == 'personal'


def _merge_http_provider_workspace_context(
    base_ctx: dict[str, Any] | None,
    override_ctx: dict[str, Any] | None,
) -> dict[str, Any]:
    base = dict(base_ctx) if isinstance(base_ctx, dict) else {}
    override = dict(override_ctx) if isinstance(override_ctx, dict) else {}
    if not override:
        return base
    merged = dict(base)
    merged.update(override)
    if not override.get('session_claims'):
        merged['session_claims'] = dict(base.get('session_claims') or {})
    if not override.get('session_workspace_id'):
        merged['session_workspace_id'] = str(base.get('session_workspace_id') or '').strip()
    if not override.get('selected_workspace'):
        merged['selected_workspace'] = _workspace_context_selected_workspace(base)
    return merged


def _prefer_expected_workspace_context(
    workspace_ctx: dict[str, Any] | None,
    expected_workspace_id: str = '',
) -> dict[str, Any]:
    normalized_expected_workspace_id = str(expected_workspace_id or '').strip()
    current_ctx = dict(workspace_ctx) if isinstance(workspace_ctx, dict) else {}
    if not normalized_expected_workspace_id:
        return current_ctx
    workspaces = [
        dict(item)
        for item in list(current_ctx.get('workspaces') or [])
        if isinstance(item, dict)
    ]
    selected_workspace = {}
    for item in workspaces:
        if str(item.get('workspace_id') or '').strip() == normalized_expected_workspace_id:
            selected_workspace = dict(item)
            break
    if not selected_workspace:
        current_selected_workspace = _workspace_context_selected_workspace(current_ctx)
        if str(current_selected_workspace.get('workspace_id') or '').strip() == normalized_expected_workspace_id:
            selected_workspace = dict(current_selected_workspace)
    if not selected_workspace:
        selected_workspace = {'workspace_id': normalized_expected_workspace_id}
        workspaces.append(dict(selected_workspace))
    current_ctx['workspace_id'] = normalized_expected_workspace_id
    current_ctx['selected_workspace'] = selected_workspace
    current_ctx['workspaces'] = workspaces
    if not str(current_ctx.get('source') or '').strip():
        current_ctx['source'] = 'expected_workspace'
    return current_ctx


def _response_looks_like_cloudflare_challenge(
    *,
    status: int,
    text: str,
    response_url: str,
    response_headers: dict[str, str] | None = None,
) -> bool:
    headers = {str(key).lower(): str(value) for key, value in dict(response_headers or {}).items()}
    if str(headers.get('cf-mitigated') or '').strip().lower() == 'challenge':
        return True
    header_hints = '\n'.join(
        [
            str(headers.get('server-timing') or ''),
            str(headers.get('content-type') or ''),
            str(headers.get('location') or ''),
        ]
    )
    merged = '\n'.join([str(response_url or ''), str(text or ''), header_hints]).lower()
    return any(marker in merged for marker in _BLOCK_PAGE_MARKERS)


def _curl_cffi_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    json_body: dict[str, Any],
    timeout_sec: float,
    proxy_url: str = '',
    impersonate: str = '',
) -> Any:
    if curl_cffi_requests is None:
        raise RuntimeError('curl_cffi_unavailable')
    request_kwargs: dict[str, Any] = {
        'headers': dict(headers),
        'json': dict(json_body),
        'timeout': max(5.0, float(timeout_sec or 0.0)),
        'allow_redirects': False,
    }
    session_kwargs: dict[str, Any] = {'default_headers': False, 'trust_env': False}
    impersonate_value = str(impersonate or '').strip()
    if impersonate_value:
        session_kwargs['impersonate'] = impersonate_value
    proxy_value = str(proxy_url or '').strip()
    if proxy_value:
        session_kwargs['proxy'] = proxy_value
    method_text = str(method or 'POST').strip().upper() or 'POST'
    target_url = str(url or '').strip()
    max_attempts = _http_retry_attempts()
    last_error: Optional[BaseException] = None
    session = curl_cffi_requests.Session(**session_kwargs)
    try:
        for attempt in range(1, max_attempts + 1):
            try:
                return session.request(method_text, target_url, **request_kwargs)
            except Exception as error:
                last_error = error
                if attempt >= max_attempts or not _is_transient_http_exception(error):
                    raise
                time.sleep(_http_retry_delay_seconds(attempt))
        if last_error is not None:
            raise last_error
        raise RuntimeError('curl_cffi_request_failed')
    finally:
        try:
            session.close()
        except Exception:
            pass


def _create_curl_cffi_session(
    *,
    storage_state: Any,
    proxy_url: str = '',
    impersonate: str = '',
) -> Any:
    if curl_cffi_requests is None:
        raise RuntimeError('curl_cffi_unavailable')
    session_kwargs: dict[str, Any] = {'default_headers': False, 'trust_env': False}
    impersonate_value = str(impersonate or '').strip()
    if impersonate_value:
        session_kwargs['impersonate'] = impersonate_value
    proxy_value = str(proxy_url or '').strip()
    if proxy_value:
        session_kwargs['proxy'] = proxy_value
    session = curl_cffi_requests.Session(**session_kwargs)
    try:
        setattr(session, 'impersonate', impersonate_value)
    except Exception:
        pass
    cookies = storage_state.get('cookies') if isinstance(storage_state, dict) else None
    if not isinstance(cookies, list):
        return session
    now_ts = time.time()
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get('name') or '').strip()
        if not name:
            continue
        expires = cookie.get('expires')
        try:
            expires_num = float(expires)
        except Exception:
            expires_num = 0.0
        if expires_num > 0 and now_ts >= expires_num:
            continue
        set_kwargs: dict[str, Any] = {}
        domain = str(cookie.get('domain') or '').strip()
        if domain:
            set_kwargs['domain'] = domain
        path = str(cookie.get('path') or '/').strip() or '/'
        if path:
            set_kwargs['path'] = path
        secure = cookie.get('secure')
        if isinstance(secure, bool):
            set_kwargs['secure'] = secure
        if expires_num > 0:
            set_kwargs['expires'] = int(expires_num)
        try:
            session.cookies.set(name, str(cookie.get('value') or ''), **set_kwargs)
        except Exception:
            try:
                session.cookies.set(name, str(cookie.get('value') or ''))
            except Exception:
                continue
    return session


def _export_curl_cffi_session_storage_state(session: Any, *, base_storage_state: Any = None) -> dict[str, Any]:
    origins = copy.deepcopy(base_storage_state.get('origins') or []) if isinstance(base_storage_state, dict) else []
    base_cookie_meta: dict[tuple[str, str, str], dict[str, Any]] = {}
    base_cookies = base_storage_state.get('cookies') if isinstance(base_storage_state, dict) else None
    if isinstance(base_cookies, list):
        for cookie in base_cookies:
            if not isinstance(cookie, dict):
                continue
            name = str(cookie.get('name') or '').strip()
            domain = str(cookie.get('domain') or '').strip()
            path = str(cookie.get('path') or '/').strip() or '/'
            if name and domain:
                base_cookie_meta[(name, domain, path)] = dict(cookie)
    cookies_out: list[dict[str, Any]] = []
    for cookie in getattr(getattr(session, 'cookies', None), 'jar', []):
        name = str(getattr(cookie, 'name', '') or '').strip()
        domain = str(getattr(cookie, 'domain', '') or '').strip()
        path = str(getattr(cookie, 'path', '') or '/').strip() or '/'
        if not name or not domain:
            continue
        meta = base_cookie_meta.get((name, domain, path), {})
        item: dict[str, Any] = {
            'name': name,
            'value': str(getattr(cookie, 'value', '') or ''),
            'domain': domain,
            'path': path,
            'secure': bool(getattr(cookie, 'secure', False)),
        }
        expires = getattr(cookie, 'expires', None)
        if expires not in (None, ''):
            try:
                item['expires'] = float(expires)
            except Exception:
                pass
        elif meta.get('expires') not in (None, ''):
            try:
                item['expires'] = float(meta.get('expires'))
            except Exception:
                pass
        if 'httpOnly' in meta:
            item['httpOnly'] = bool(meta.get('httpOnly'))
        same_site = str(meta.get('sameSite') or '').strip()
        if same_site in {'Lax', 'Strict', 'None'}:
            item['sameSite'] = same_site
        cookies_out.append(item)
    return {'cookies': cookies_out, 'origins': origins}


class _CurlCffiResponseAdapter:
    def __init__(self, response: Any, *, fallback_url: str) -> None:
        self._response = response
        self.url = str(getattr(response, 'url', '') or fallback_url).strip()
        self.status = int(getattr(response, 'status_code', 0) or 0)
        self.headers = dict(getattr(response, 'headers', {}) or {})
        try:
            self._text = str(getattr(response, 'text', '') or '')
        except Exception:
            self._text = ''

    async def text(self) -> str:
        return self._text


class _CurlCffiRequestContext:
    def __init__(
        self,
        *,
        storage_state: Any,
        proxy_url: str = '',
        impersonate: str = '',
    ) -> None:
        self._origins = copy.deepcopy(storage_state.get('origins') or []) if isinstance(storage_state, dict) else []
        self._cookie_metadata: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._seed_cookie_metadata(storage_state)
        self.proxy_url = str(proxy_url or '').strip()
        self.impersonate = str(impersonate or '').strip()
        self._session = _create_curl_cffi_session(
            storage_state=storage_state,
            proxy_url=self.proxy_url,
            impersonate=self.impersonate,
        )

    def _seed_cookie_metadata(self, storage_state: Any) -> None:
        cookies = storage_state.get('cookies') if isinstance(storage_state, dict) else None
        if not isinstance(cookies, list):
            return
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            name = str(cookie.get('name') or '').strip()
            if not name:
                continue
            domain = str(cookie.get('domain') or '').strip()
            path = str(cookie.get('path') or '/').strip() or '/'
            self._cookie_metadata[(name, domain, path)] = dict(cookie)

    def _export_storage_state(self) -> dict[str, Any]:
        cookies_out: list[dict[str, Any]] = []
        for cookie in getattr(self._session.cookies, 'jar', []):
            name = str(getattr(cookie, 'name', '') or '').strip()
            domain = str(getattr(cookie, 'domain', '') or '').strip()
            path = str(getattr(cookie, 'path', '') or '/').strip() or '/'
            if not name or not domain:
                continue
            meta = self._cookie_metadata.get((name, domain, path), {})
            item: dict[str, Any] = {
                'name': name,
                'value': str(getattr(cookie, 'value', '') or ''),
                'domain': domain,
                'path': path,
                'secure': bool(getattr(cookie, 'secure', False)),
            }
            expires = getattr(cookie, 'expires', None)
            if expires not in (None, ''):
                try:
                    item['expires'] = float(expires)
                except Exception:
                    pass
            elif meta.get('expires') not in (None, ''):
                try:
                    item['expires'] = float(meta.get('expires'))
                except Exception:
                    pass
            if 'httpOnly' in meta:
                item['httpOnly'] = bool(meta.get('httpOnly'))
            rest = getattr(cookie, '_rest', {}) or {}
            http_only_rest = str(rest.get('http_only') or '').strip().lower()
            if http_only_rest in {'true', 'false'}:
                item['httpOnly'] = http_only_rest == 'true'
            same_site = str(meta.get('sameSite') or '').strip()
            if same_site in {'Lax', 'Strict', 'None'}:
                item['sameSite'] = same_site
            cookies_out.append(item)
        return {
            'cookies': cookies_out,
            'origins': copy.deepcopy(self._origins),
        }

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        data: Any = None,
        timeout: int = 60_000,
        fail_on_status_code: bool = False,
        max_redirects: int = 0,
    ) -> _CurlCffiResponseAdapter:
        request_kwargs: dict[str, Any] = {
            'headers': dict(headers or {}),
            'timeout': max(1.0, float(timeout or 0) / 1000.0),
            'allow_redirects': int(max_redirects or 0) > 0,
            'default_headers': False,
        }
        if data is not None:
            request_kwargs['data'] = data
        if int(max_redirects or 0) > 0:
            request_kwargs['max_redirects'] = int(max_redirects or 0)
        method_text = str(method or 'GET').strip().upper() or 'GET'
        target_url = str(url or '').strip()
        max_attempts = _http_retry_attempts()
        last_error: Optional[BaseException] = None
        for attempt in range(1, max_attempts + 1):
            try:
                response = self._session.request(method_text, target_url, **request_kwargs)
                break
            except Exception as error:
                last_error = error
                if attempt >= max_attempts or not _is_transient_http_exception(error):
                    raise
                time.sleep(_http_retry_delay_seconds(attempt))
        else:
            if last_error is not None:
                raise last_error
            raise RuntimeError('curl_cffi_context_request_failed')
        status = int(getattr(response, 'status_code', 0) or 0)
        if fail_on_status_code and status >= 400:
            raise RuntimeError(f'curl_cffi_request_failed: HTTP {status}')
        return _CurlCffiResponseAdapter(response, fallback_url=str(url or '').strip())

    async def get(self, url: str, **kwargs: Any) -> _CurlCffiResponseAdapter:
        return await asyncio.to_thread(self._request, 'GET', url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> _CurlCffiResponseAdapter:
        return await asyncio.to_thread(self._request, 'POST', url, **kwargs)

    async def storage_state(self, path: str | None = None) -> dict[str, Any]:
        payload = self._export_storage_state()
        target_path = str(path or '').strip()
        if target_path:
            Path(target_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        return payload

    async def dispose(self) -> None:
        await asyncio.to_thread(self._session.close)


def _build_empty_storage_state_payload() -> dict[str, Any]:
    return {
        'cookies': [],
        'origins': [],
    }


def _is_auth_add_phone_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(str(url or '').strip())
    except Exception:
        return False
    return parts.hostname == 'auth.openai.com' and parts.path.rstrip('/') == '/add-phone'


def _is_auth_phone_otp_select_channel_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(str(url or '').strip())
    except Exception:
        return False
    return parts.hostname == 'auth.openai.com' and parts.path.rstrip('/') == '/phone-otp/select-channel'


def _is_auth_phone_verification_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(str(url or '').strip())
    except Exception:
        return False
    if parts.hostname not in {'auth.openai.com', 'auth0.openai.com'}:
        return False
    path = parts.path.rstrip('/').lower()
    if path in {
        '/add-phone',
        '/phone-verification',
        '/phone-otp',
        '/phone-otp/select-channel',
        '/phone-otp/verify',
        '/phone-otp/resend',
    }:
        return True
    return path.startswith('/phone-otp') or path.startswith('/add-phone') or path.startswith('/phone-verification')


def _auth_phone_page_type(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ''
    page = payload.get('page')
    if isinstance(page, dict):
        return str(page.get('type') or '').strip().lower().replace('-', '_')
    return str(payload.get('type') or '').strip().lower().replace('-', '_')


def _auth_phone_step_still_active(payload: Any, *, url: str = '', text: str = '') -> bool:
    if (
        _is_auth_add_phone_url(url)
        or _is_auth_phone_otp_select_channel_url(url)
        or _is_auth_phone_verification_url(url)
    ):
        return True
    page_type = _auth_phone_page_type(payload)
    if page_type in {
        'add_phone',
        'phone_number_verification',
        'phone_otp_verification',
        'phone_otp_select_channel',
        'phone_otp_channel_selection',
    }:
        return True
    try:
        payload_text = json.dumps(payload, ensure_ascii=False, default=str).lower()
    except Exception:
        payload_text = str(payload or '').lower()
    merged = '\n'.join((str(url or '').lower(), str(text or '').lower(), payload_text))
    normalized = merged.replace('-', '_')
    return any(
        marker in normalized
        for marker in (
            '/add_phone',
            '/phone_verification',
            '/phone_otp/select_channel',
            'phone_otp_verification',
            'phone_number_verification',
            'phone_otp_select_channel',
            'phone_otp_channel_selection',
            'enter the code we sent',
            'enter the code sent',
            'verify your phone',
            'confirm your phone',
        )
    )


def _auth_phone_bind_progress_url(url: str) -> bool:
    value = str(url or '').strip()
    if not value:
        return False
    if _auth_phone_step_still_active({}, url=value):
        return False
    try:
        parts = urllib.parse.urlsplit(value)
    except Exception:
        return False
    host = str(parts.hostname or '').strip().lower()
    path = str(parts.path or '').strip().lower()
    query = str(parts.query or '').strip().lower()
    if host in {'chatgpt.com', 'chat.openai.com', 'platform.openai.com'}:
        return True
    if host == 'auth.openai.com':
        if path.rstrip('/') in {
            '',
            '/',
            '/api/accounts/callback',
            '/consent',
            '/sign-in-with-chatgpt/codex/consent',
        }:
            return True
        if path.startswith('/workspace') or path.startswith('/organization'):
            return True
        if 'code=' in query or 'state=' in query:
            return True
    if 'code=' in query and 'state=' in query:
        return True
    return False


def _auth_phone_channel_options(payload: Any) -> list[str]:
    option_keys = {
        'available_channels',
        'availablechannels',
        'channel_options',
        'channeloptions',
        'channels',
    }
    found: list[str] = []

    def add_option(value: Any) -> None:
        if isinstance(value, str):
            normalized = value.strip().lower().replace('-', '_')
            if normalized in {'sms', 'whatsapp', 'whats_app'}:
                canonical = 'whatsapp' if normalized in {'whatsapp', 'whats_app'} else 'sms'
                if canonical not in found:
                    found.append(canonical)
            return
        if isinstance(value, list):
            for item in value:
                add_option(item)
            return
        if isinstance(value, dict):
            for name in ('type', 'name', 'value', 'channel'):
                if name in value:
                    add_option(value.get(name))

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = str(key or '').strip().lower().replace('-', '_')
                if normalized_key in option_keys:
                    add_option(item)
                if isinstance(item, (dict, list)):
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, list)):
                    walk(item)

    walk(payload)
    return found


def _choose_auth_phone_channel(options: Sequence[str], *, allow_whatsapp: bool) -> str:
    normalized = {
        str(option or '').strip().lower().replace('-', '_')
        for option in options
        if str(option or '').strip()
    }
    if 'sms' in normalized or not normalized:
        return 'sms'
    if normalized.intersection({'whatsapp', 'whats_app'}):
        return 'whatsapp' if allow_whatsapp else ''
    return 'sms'


def _auth_phone_channel_selection_required(payload: Any, *, url: str = '', text: str = '') -> bool:
    if _is_auth_phone_otp_select_channel_url(url):
        return True
    try:
        payload_text = json.dumps(payload, ensure_ascii=False, default=str).lower()
    except Exception:
        payload_text = str(payload or '').lower()
    merged = '\n'.join((str(url or '').lower(), str(text or '').lower(), payload_text))
    normalized = merged.replace('-', '_')
    return any(
        marker in normalized
        for marker in (
            '/phone_otp/select_channel',
            'phone_otp_select_channel',
            'phone_otp_channel_selection',
        )
    )


def _auth_phone_forced_whatsapp(payload: Any, *, text: str = '', url: str = '') -> bool:
    channel_keys = {
        'channel',
        'selected_channel',
        'delivery_channel',
        'delivery_method',
        'verification_channel',
    }

    def selected_in(value: Any) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = str(key or '').strip().lower().replace('-', '_')
                if normalized_key in channel_keys:
                    candidates = [item]
                    if isinstance(item, dict):
                        candidates.extend(item.get(name) for name in ('type', 'name', 'value'))
                    if any(
                        str(candidate or '').strip().lower().replace('-', '_') in {'whatsapp', 'whats_app'}
                        for candidate in candidates
                    ):
                        return True
                if isinstance(item, (dict, list)) and selected_in(item):
                    return True
        elif isinstance(value, list):
            return any(selected_in(item) for item in value if isinstance(item, (dict, list)))
        return False

    if selected_in(payload):
        return True
    lowered_url = str(url or '').strip().lower()
    if '/whatsapp' in lowered_url or 'channel=whatsapp' in lowered_url:
        return True
    normalized_text = re.sub(r'\s+', ' ', str(text or '')).strip().lower()
    return any(
        phrase in normalized_text
        for phrase in (
            'sent to whatsapp',
            'sent via whatsapp',
            'delivered to whatsapp',
            'delivered via whatsapp',
            'check your whatsapp',
            'check whatsapp',
            'open whatsapp',
        )
    )


class _PhoneBindCompleted(RuntimeError):
    """Internal control-flow signal emitted only after phone OTP validation succeeds."""

    def __init__(self, phone: str) -> None:
        super().__init__('phone_bind_completed')
        self.phone = str(phone or '').strip()


class _ManualPhoneRetryRequested(RuntimeError):
    """Internal signal that retries add-phone without leaving the HTTP session."""


def _is_retryable_manual_phone_error(error: BaseException) -> bool:
    if isinstance(error, (ManualPhoneReplacedError, ManualPhoneControlTimeoutError)):
        return True
    message = str(error or '').strip().lower()
    if not message.startswith('http_auth_add_phone_failed:'):
        return False
    non_retryable_markers = (
        'invalid authorization step',
        'invalid_authorization_step',
        'invalid state',
        'invalid_state',
        'state mismatch',
        'state_mismatch',
        'cloudflare',
        'challenge blocked',
        'challenge_blocked',
        'too many phone verification',
        'phone_verification_rate_limit',
        'too many requests',
        'rate limit',
        'rate-limit',
        'http 429',
    )
    if any(marker in message for marker in non_retryable_markers):
        return False
    if 'phone-otp/validate failed:' in message:
        return True
    if 'phone verification code is empty' in message:
        return True
    if 'phone verification send failed:' in message:
        retryable_send_markers = (
            'phone number',
            'phone_number',
            'invalid phone',
            'already in use',
            'already_in_use',
            'already used',
            'recently used',
            'suspicious',
            'blocked phone',
            'disallowed phone',
            'unsupported',
            'channel',
            'temporarily',
            'timeout',
            'timed out',
            'service unavailable',
            'internal server error',
            'bad gateway',
            'gateway timeout',
            'http 400',
            'http 409',
            'http 422',
            'http 500',
            'http 502',
            'http 503',
            'http 504',
        )
        return any(marker in message for marker in retryable_send_markers)
    return False


def _build_http_provider_request_context(
    *,
    storage_state_path: str = '',
    storage_state: Any = None,
    proxy_url: str = '',
    impersonate: str = '',
) -> Any:
    payload = storage_state if isinstance(storage_state, dict) else None
    if payload is None:
        state_path_text = str(storage_state_path or '').strip()
        if state_path_text:
            payload = _load_storage_state_payload(state_path_text)
        else:
            payload = _build_empty_storage_state_payload()
    return _CurlCffiRequestContext(
        storage_state=payload,
        proxy_url=proxy_url,
        impersonate=impersonate,
    )


def _curl_cffi_response_to_result(
    response: Any,
    *,
    fallback_url: str,
) -> tuple[dict[str, Any], int, str, str, dict[str, str]]:
    text = ''
    try:
        text = str(response.text or '')
    except Exception:
        text = ''
    payload: dict[str, Any] = {}
    if text:
        try:
            parsed_payload = json.loads(text)
        except Exception:
            parsed_payload = None
        if isinstance(parsed_payload, dict):
            payload = parsed_payload
    try:
        response_url = str(response.url or fallback_url).strip()
    except Exception:
        response_url = str(fallback_url or '').strip()
    response_headers = {
        str(key).lower(): str(value)
        for key, value in dict(getattr(response, 'headers', {}) or {}).items()
    }
    status = int(getattr(response, 'status_code', 0) or 0)
    return payload, status, text, response_url, response_headers


def _request_with_curl_cffi_session(
    session: Any,
    *,
    method: str,
    url: str,
    headers: Optional[dict[str, str]] = None,
    body_text: str = '',
    json_body: Optional[dict[str, Any]] = None,
    timeout_sec: float = 30.0,
) -> tuple[dict[str, Any], int, str, str, dict[str, str]]:
    merged_headers = _build_http_browser_identity_headers(
        impersonate=str(getattr(session, 'impersonate', '') or '').strip(),
    )
    if isinstance(headers, dict):
        for key, value in headers.items():
            if value is None:
                continue
            merged_headers[str(key)] = str(value)
    if not any(str(key).lower() == 'cookie' for key in merged_headers):
        try:
            cookie_header = _build_storage_state_cookie_header_for_url(
                _export_curl_cffi_session_storage_state(session),
                url=str(url or '').strip(),
            )
        except Exception:
            cookie_header = ''
        if cookie_header:
            merged_headers['cookie'] = cookie_header
    method_text = str(method or 'GET').strip().upper() or 'GET'
    request_kwargs: dict[str, Any] = {
        'headers': merged_headers,
        'timeout': max(5.0, float(timeout_sec or 0.0)),
        'allow_redirects': False,
        'default_headers': False,
    }
    if method_text == 'POST':
        if isinstance(json_body, dict):
            request_kwargs['json'] = dict(json_body)
        elif body_text:
            request_kwargs['data'] = body_text
    target_url = str(url or '').strip()
    max_attempts = _http_retry_attempts()
    last_error: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = session.request(method_text, target_url, **request_kwargs)
            break
        except Exception as error:
            last_error = error
            if attempt >= max_attempts or not _is_transient_http_exception(error):
                raise
            time.sleep(_http_retry_delay_seconds(attempt))
    else:
        if last_error is not None:
            raise last_error
        raise RuntimeError('curl_cffi_session_request_failed')
    return _curl_cffi_response_to_result(response, fallback_url=str(url or '').strip())


def _submit_workspace_select_with_curl_cffi(
    *,
    consent_url: str,
    workspace_id: str,
    storage_state: Any,
    timeout_sec: float,
    proxy_url: str = '',
    impersonate: str = '',
    session: Any = None,
) -> dict[str, Any]:
    select_url = 'https://auth.openai.com/api/accounts/workspace/select'
    headers = _build_http_auth_fetch_headers(
        referer_url=consent_url,
        accept='application/json',
        impersonate=impersonate,
    )
    headers['content-type'] = 'application/json'
    headers.update(_build_http_datadog_trace_headers())
    active_session = session
    if active_session is None:
        active_session = _create_curl_cffi_session(
            storage_state=storage_state,
            proxy_url=proxy_url,
            impersonate=impersonate,
        )
    payload, status, text, response_url, response_headers = _request_with_curl_cffi_session(
        active_session,
        method='POST',
        url=select_url,
        headers=headers,
        json_body={'workspace_id': str(workspace_id or '').strip()},
        timeout_sec=max(10.0, min(float(timeout_sec or 0.0), 30.0)),
    )
    return {
        'status': status,
        'text': text,
        'payload': payload,
        'response_url': response_url,
        'response_headers': response_headers,
        'challenge_detected': _response_looks_like_cloudflare_challenge(
            status=status,
            text=text,
            response_url=response_url,
            response_headers=response_headers,
        ),
    }


def _follow_http_authorize_chain_with_curl_cffi_session(
    session: Any,
    *,
    auth_url: str,
    redirect_uri: str,
    expected_state: str,
    timeout_sec: float,
    trace: _TraceWriter,
) -> OAuthCallback:
    current_url = str(auth_url or '').strip()
    if not current_url:
        raise RuntimeError('http_auth_code_missing: authorize URL 为空。')

    headers = _build_http_html_headers(
        impersonate=str(getattr(session, 'impersonate', '') or '').strip(),
    )
    interactive_markers = (
        'sign in',
        'log in',
        '/log-in',
        '/log-in/password',
        '/api/accounts/login',
        'login_password',
        'email-verification',
        'continue with email',
        'continue with google',
        'continue with microsoft',
        'password',
        '验证码',
        'one-time code',
        'mfa',
        '2-step verification',
    )
    for hop in range(1, 17):
        _payload, status, body_text, response_url, response_headers = _request_with_curl_cffi_session(
            session,
            method='GET',
            url=current_url,
            headers=headers,
            timeout_sec=timeout_sec,
        )
        location = str(response_headers.get('location') or '').strip()
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_authorize_hop',
                'hop': hop,
                'status': status,
                'url': _sanitize_url_for_log(current_url),
                'responseUrl': _sanitize_url_for_log(response_url),
                'location': _sanitize_url_for_log(location),
            }
        )
        if _response_looks_like_cloudflare_challenge(
            status=status,
            text=body_text,
            response_url=response_url,
            response_headers=response_headers,
        ):
            raise RuntimeError('http_auth_challenge_blocked: authorize 命中 Cloudflare challenge，纯 HTTP 无法继续。')
        callback = _callback_from_url(
            url=response_url,
            expected_state=expected_state,
            redirect_uri=redirect_uri,
        )
        if callback is not None and (callback.code or callback.error):
            return callback
        if 300 <= status < 400 and location:
            next_url = urllib.parse.urljoin(response_url or current_url, location)
            callback = _callback_from_url(
                url=next_url,
                expected_state=expected_state,
                redirect_uri=redirect_uri,
            )
            if callback is not None and (callback.code or callback.error or callback.state):
                return callback
            current_url = next_url
            continue
        callback = _callback_from_text(
            text=body_text,
            expected_state=expected_state,
            redirect_uri=redirect_uri,
        )
        if callback is not None:
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_authorize_callback_in_body',
                    'hop': hop,
                    'status': status,
                    'url': _sanitize_url_for_log(response_url),
                    'hasCode': bool(callback.code),
                    'hasError': bool(callback.error),
                    'hasState': bool(callback.state),
                }
            )
            return callback
        merged = '\n'.join([response_url, body_text]).lower()
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_authorize_terminal',
                'hop': hop,
                'status': status,
                'url': _sanitize_url_for_log(response_url),
                'bodySnippet': _compress_debug_text(body_text, limit=400),
            }
        )
        if any(marker in merged for marker in _ERROR_TEXT_MARKERS):
            detail = _extract_auth_error_detail(response_url) or _compress_debug_text(body_text, limit=220)
            raise RuntimeError(f'http_auth_authorize_failed: {detail or "authorize 页面返回错误。"}')
        if any(marker in merged for marker in interactive_markers):
            raise RuntimeError('http_auth_login_required: 当前登录态未能直达 authorize，已回落到登录或验证交互页。')
        raise RuntimeError(
            'http_auth_code_missing: authorize 未返回可用 code，'
            f'status={status}，url={_sanitize_url_for_log(response_url) or "unknown"}。'
        )
    raise RuntimeError('http_auth_code_missing: authorize redirect 跳转次数超过上限。')


def _exchange_code_for_tokens_with_curl_cffi_session(
    session: Any,
    *,
    code: str,
    pkce: PKCECodes,
    client_id: str,
    redirect_uri: str,
    timeout_sec: float,
) -> tuple[dict[str, Any], int, str, str, dict[str, str]]:
    body = urllib.parse.urlencode(
        {
            'grant_type': 'authorization_code',
            'client_id': str(client_id or '').strip(),
            'code': str(code or '').strip(),
            'redirect_uri': str(redirect_uri or '').strip(),
            'code_verifier': pkce.code_verifier,
        }
    )
    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'accept': 'application/json',
        'origin': 'https://auth.openai.com',
        'referer': 'https://auth.openai.com/',
    }
    return _request_with_curl_cffi_session(
        session,
        method='POST',
        url=TOKEN_URL,
        headers=headers,
        body_text=body,
        timeout_sec=max(10.0, min(float(timeout_sec or 0.0), 60.0)),
    )


def _complete_http_codex_consent_via_curl_cffi(
    *,
    consent_url: str,
    workspace_id: str,
    storage_state: Any,
    auth_url: str,
    redirect_uri: str,
    expected_state: str,
    pkce: PKCECodes,
    client_id: str,
    timeout_sec: float,
    proxy_url: str = '',
    impersonate: str = '',
    trace: _TraceWriter,
) -> dict[str, Any]:
    session = _create_curl_cffi_session(
        storage_state=storage_state,
        proxy_url=proxy_url,
        impersonate=impersonate,
    )
    try:
        select_result = _submit_workspace_select_with_curl_cffi(
            consent_url=consent_url,
            workspace_id=workspace_id,
            storage_state=storage_state,
            timeout_sec=timeout_sec,
            proxy_url=proxy_url,
            impersonate=impersonate,
            session=session,
        )
        callback: Optional[OAuthCallback] = None
        follow_error = ''
        status = int(select_result.get('status') or 0)
        challenge_detected = bool(select_result.get('challenge_detected'))
        if not challenge_detected and 200 <= status < 400:
            resume_authorize_url = str(_extract_continue_url(select_result.get('payload')) or '').strip() or str(auth_url or '').strip()
            try:
                callback = _follow_http_authorize_chain_with_curl_cffi_session(
                    session,
                    auth_url=resume_authorize_url,
                    redirect_uri=redirect_uri,
                    expected_state=expected_state,
                    timeout_sec=max(10.0, min(float(timeout_sec or 0.0), 30.0)),
                    trace=trace,
                )
            except Exception as error:
                follow_error = str(error or '').strip()
        token_result: dict[str, Any] = {}
        if isinstance(callback, OAuthCallback) and str(callback.code or '').strip():
            try:
                token_payload, token_status, token_text, token_url, token_headers = _exchange_code_for_tokens_with_curl_cffi_session(
                    session,
                    code=str(callback.code or '').strip(),
                    pkce=pkce,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    timeout_sec=timeout_sec,
                )
                token_result = {
                    'payload': token_payload,
                    'status': token_status,
                    'text': token_text,
                    'response_url': token_url,
                    'response_headers': token_headers,
                }
            except Exception as error:
                token_result = {'error': str(error or '').strip()}
        return {
            'select_result': select_result,
            'callback': callback,
            'follow_error': follow_error,
            'token_result': token_result,
            'storage_state': _export_curl_cffi_session_storage_state(session, base_storage_state=storage_state),
        }
    finally:
        try:
            session.close()
        except Exception:
            pass


_SEND_FAILURE_TEMPORARY_MARKERS = (
    "recently used",
    "try again later",
    "too many requests",
    "rate limit",
    "rate-limit",
    "temporarily",
    "try again",
    "service unavailable",
    "internal server error",
    "bad gateway",
    "gateway timeout",
    "timeout",
    "timed out",
    "connection",
    "429",
    "502",
    "503",
    "504",
)


def _is_send_failure_temporary(detail: str) -> bool:
    """发码(add-phone/send)失败是否属于临时性/可恢复 → 应冷却而非永久拉黑。

    OpenAI 对一个号短时间多次发码会临时限频（recently used / Too many requests / 5xx），
    这类号本身没坏，等冷却到期可再用。只有确定性坏号（suspicious 等持久风控）才永久拉黑。
    """
    text = str(detail or "").lower()
    return any(marker in text for marker in _SEND_FAILURE_TEMPORARY_MARKERS)


def _is_validate_recently_used(detail: str) -> bool:
    """验码(phone-otp/validate)失败是否为 'recently used' 冷却（号已收到码，仅冷却期）。"""
    text = str(detail or "").lower()
    return ("recently used" in text) or ("try again later" in text)


def _extract_error(payload: dict[str, Any] | None, text: str = '') -> tuple[str, str]:
    if isinstance(payload, dict):
        error_obj = payload.get('error')
        if isinstance(error_obj, dict):
            code = str(error_obj.get('code') or '').strip()
            msg = str(error_obj.get('message') or '').strip()
            if code or msg:
                return code, msg
        payload_code = str(payload.get('code') or '').strip()
        payload_msg = str(payload.get('message') or '').strip()
        if payload_code or payload_msg:
            return payload_code, payload_msg
    low = str(text or '').lower()
    if 'invalid_state' in low:
        return 'invalid_state', 'Invalid client/session. Please start over.'
    return '', ''


def _is_invalid_authorization_step(*, err_code: str = '', err_msg: str = '', text: str = '') -> bool:
    low = f'{err_code}\n{err_msg}\n{text}'.lower()
    if 'invalid_authorization_step' in low:
        return True
    if 'invalid authorization step' in low:
        return True
    return ('invalid' in low) and ('authorization' in low) and ('step' in low)


def _is_unknown_parameter_error(
    *,
    err_code: str = '',
    err_msg: str = '',
    text: str = '',
    parameter_name: str = '',
) -> bool:
    low = f'{err_code}\n{err_msg}\n{text}'.lower()
    marker = str(parameter_name or '').strip().lower()
    if ('unknown parameter' not in low) and ('unknown field' not in low):
        return False
    if not marker:
        return True
    return marker in low


def _collect_auth_step_hints(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    hints: dict[str, Any] = {}
    for key in (
        'state',
        'step',
        'next_step',
        'next_action',
        'action',
        'screen',
        'screen_hint',
        'authorization_step',
        'challenge_type',
    ):
        value = payload.get(key)
        if value not in (None, '', [], {}):
            hints[key] = value
    error_obj = payload.get('error')
    if isinstance(error_obj, dict):
        for key in ('code', 'message', 'step', 'next_step', 'next_action', 'authorization_step'):
            value = error_obj.get(key)
            if value not in (None, '', [], {}):
                hints[f'error_{key}'] = value
    return hints


def _extract_continue_url(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ''
    for key in ('continue_url', 'continueUrl', 'redirect_url', 'redirectUrl'):
        value = str(payload.get(key) or '').strip()
        if value:
            return value
    page_obj = payload.get('page')
    if isinstance(page_obj, dict):
        for key in ('continue_url', 'continueUrl', 'redirect_url', 'redirectUrl'):
            value = str(page_obj.get(key) or '').strip()
            if value:
                return value
    return ''


def _is_email_verification_url(value: Any) -> bool:
    return 'email-verification' in str(value or '').strip().lower()


def _is_email_otp_verification_step(payload: Any) -> bool:
    continue_url = str(_extract_continue_url(payload) or '').strip().lower()
    page_type = ''
    if isinstance(payload, dict):
        page_obj = payload.get('page')
        if isinstance(page_obj, dict):
            page_type = str(page_obj.get('type') or '').strip().lower()
    if 'email_otp' in page_type:
        return True
    return _is_email_verification_url(continue_url)


def _poll_otp_api_url_verification_code_sync(
    *,
    otp_api_url: str,
    otp_timeout_sec: float,
    otp_interval_sec: float,
    blocked_codes: set[str] | None = None,
    not_before_ts: float = 0.0,
) -> str:
    url = str(otp_api_url or '').strip()
    if not url:
        return ''
    deadline = time.time() + max(3.0, float(otp_timeout_sec or 120.0))
    interval = max(1.0, float(otp_interval_sec or 3.0))
    blocked = blocked_codes or set()
    while time.time() <= deadline:
        try:
            request = urllib.request.Request(
                url,
                headers={
                    'accept': 'text/html,application/json,text/plain,*/*',
                    'user-agent': 'Mozilla/5.0',
                },
            )
            with urllib.request.urlopen(request, timeout=min(20.0, max(5.0, interval + 5.0))) as response:
                raw = response.read(2_000_000)
            text = raw.decode('utf-8', errors='ignore')
            message_ts = extractVerificationTimestamp(text)
            if float(not_before_ts or 0.0) > 0 and message_ts > 0 and message_ts < float(not_before_ts):
                time.sleep(interval)
                continue
            code_value = extractVerificationCode(
                text,
                keywords=defaultCodeKeywords,
                blockedCodes=blocked,
            )
            if code_value:
                return str(code_value)
        except Exception:
            pass
        time.sleep(interval)
    return ''


def _is_login_password_step(payload: Any) -> bool:
    continue_url = str(_extract_continue_url(payload) or '').strip().lower()
    page_type = ''
    if isinstance(payload, dict):
        page_obj = payload.get('page')
        if isinstance(page_obj, dict):
            page_type = str(page_obj.get('type') or '').strip().lower()
    return page_type == 'login_password' or '/log-in/password' in continue_url


def _is_codex_consent_url(url: str) -> bool:
    return '/sign-in-with-chatgpt/codex/consent' in str(url or '').strip().lower()


def _is_codex_consent_step(payload: Any) -> bool:
    continue_url = str(_extract_continue_url(payload) or '').strip().lower()
    page_type = ''
    if isinstance(payload, dict):
        page_obj = payload.get('page')
        if isinstance(page_obj, dict):
            page_type = str(page_obj.get('type') or '').strip().lower()
    return page_type == 'sign_in_with_chatgpt_codex_consent' or _is_codex_consent_url(continue_url)


def _is_http_passwordless_login_allowed(payload: Any) -> bool:
    if not _is_login_password_step(payload):
        return False
    page_payload: Any = None
    if isinstance(payload, dict):
        page_obj = payload.get('page')
        if isinstance(page_obj, dict):
            page_payload = page_obj.get('payload')
    if isinstance(page_payload, dict):
        passwordless_disabled = page_payload.get('passwordless_disabled')
        if isinstance(passwordless_disabled, bool):
            return not passwordless_disabled
    return False


def _http_passwordless_fallback_enabled() -> bool:
    return _read_bool_env('AIO_CODEX_OAUTH_HTTP_PASSWORDLESS_FALLBACK', True)


def _extract_http_email_verification_mode(payload: Any) -> str:
    candidates: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        candidates.append(payload)
        auth_session = payload.get('oai-client-auth-session')
        if isinstance(auth_session, dict):
            candidates.append(auth_session)
        page_obj = payload.get('page')
        if isinstance(page_obj, dict):
            page_payload = page_obj.get('payload')
            if isinstance(page_payload, dict):
                candidates.append(page_payload)
    for item in candidates:
        mode = str(item.get('email_verification_mode') or '').strip().lower()
        if mode:
            return mode
        if bool(item.get('passwordless_otp_from_password_redirect')):
            return 'passwordless_login'
    return ''


def _choose_http_otp_send_request(
    payload: Any,
    *,
    default_path: str = '/email-otp/send',
) -> tuple[str, str]:
    if _is_email_otp_verification_step(payload):
        return '/email-otp/resend', 'POST'
    mode = _extract_http_email_verification_mode(payload)
    if mode == 'passwordless_login':
        return '/passwordless/send-otp', 'POST'
    if mode in {'onboarding', 'email_verification'}:
        return '/email-otp/send', 'GET'
    path = str(default_path or '/email-otp/send').strip() or '/email-otp/send'
    method = 'POST' if path == '/passwordless/send-otp' else 'GET'
    return path, method


def _has_imap_otp_credentials(
    *,
    use_imap_otp: bool,
    imap_user: Any,
    imap_pass: Any,
    imap_auth_type: Any = "password",
    imap_oauth_client_id: Any = None,
    imap_oauth_refresh_token: Any = None,
) -> bool:
    if not bool(use_imap_otp):
        return False
    if not bool(str(imap_user or '').strip()):
        return False
    if str(imap_auth_type or "password").strip().lower() == "oauth2":
        return bool(str(imap_oauth_client_id or "").strip()) and bool(str(imap_oauth_refresh_token or "").strip())
    return bool(str(imap_user or '').strip()) and bool(str(imap_pass or '').strip())


def _should_try_http_passwordless_login_fallback(
    *,
    login_payload: Any,
    err_code: str = '',
    err_msg: str = '',
    email: str = '',
    use_imap_otp: bool = False,
    imap_user: Any = None,
    imap_pass: Any = None,
    imap_auth_type: Any = "password",
    imap_oauth_client_id: Any = None,
    imap_oauth_refresh_token: Any = None,
) -> bool:
    if not _http_passwordless_fallback_enabled():
        return False
    if '@' not in str(email or ''):
        return False
    if not _is_login_password_step(login_payload):
        return False
    low = f'{err_code}\n{err_msg}'.lower()
    return (
        ('invalid_username_or_password' in low)
        or ('invalid_credentials' in low)
        or _is_invalid_authorization_step(err_code=err_code, err_msg=err_msg)
    )


def _resolve_http_browser_identity_for_impersonate(impersonate: str = '') -> dict[str, str]:
    normalized = str(impersonate or '').strip().lower()
    matched = re.search(r'chrome(\d+)', normalized)
    if not matched:
        return {
            'user-agent': _HTTP_BROWSER_USER_AGENT,
            'sec-ch-ua': _HTTP_BROWSER_SEC_CH_UA,
            'sec-ch-ua-mobile': _HTTP_BROWSER_SEC_CH_UA_MOBILE,
            'sec-ch-ua-platform': _HTTP_BROWSER_SEC_CH_UA_PLATFORM,
        }
    major = str(matched.group(1) or '').strip()
    if not major:
        return {
            'user-agent': _HTTP_BROWSER_USER_AGENT,
            'sec-ch-ua': _HTTP_BROWSER_SEC_CH_UA,
            'sec-ch-ua-mobile': _HTTP_BROWSER_SEC_CH_UA_MOBILE,
            'sec-ch-ua-platform': _HTTP_BROWSER_SEC_CH_UA_PLATFORM,
        }
    return {
        'user-agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            f'Chrome/{major}.0.0.0 Safari/537.36'
        ),
        'sec-ch-ua': f'"Chromium";v="{major}", "Not-A.Brand";v="24", "Google Chrome";v="{major}"',
        'sec-ch-ua-mobile': _HTTP_BROWSER_SEC_CH_UA_MOBILE,
        'sec-ch-ua-platform': _HTTP_BROWSER_SEC_CH_UA_PLATFORM,
    }


def _resolve_request_ctx_impersonate(request_ctx: Any) -> str:
    value = getattr(request_ctx, 'impersonate', '')
    return str(value).strip() if isinstance(value, str) else ''


def _build_http_browser_identity_headers(
    *,
    include_accept_language: bool = False,
    impersonate: str = '',
) -> dict[str, str]:
    headers = get_http_stage_browser_headers(impersonate=impersonate) or _resolve_http_browser_identity_for_impersonate(impersonate)
    if include_accept_language and not str(headers.get('accept-language') or '').strip():
        # profile 已带英语 accept-language 时优先保留，避免与英语区指纹矛盾的 zh-CN；缺失才用英语默认兜底。
        headers['accept-language'] = _HTTP_BROWSER_ACCEPT_LANGUAGE
    return headers


def _build_http_html_headers(*, impersonate: str = '') -> dict[str, str]:
    headers = {
        'accept': (
            'text/html,application/xhtml+xml,application/xml;q=0.9,'
            'image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
        ),
        'upgrade-insecure-requests': '1',
    }
    headers.update(_build_http_browser_identity_headers(include_accept_language=True, impersonate=impersonate))
    return headers


def _build_http_auth_fetch_headers(
    *,
    referer_url: str = '',
    accept: str = 'application/json',
    impersonate: str = '',
) -> dict[str, str]:
    referer = str(referer_url or '').strip()
    if referer.startswith('/'):
        referer = f'https://auth.openai.com{referer}'
    if not referer.lower().startswith('https://auth.openai.com/'):
        referer = 'https://auth.openai.com/log-in'
    accept_text = str(accept or 'application/json').strip() or 'application/json'
    headers = {
        'accept': accept_text,
        'accept-encoding': _HTTP_BROWSER_ACCEPT_ENCODING,
        'accept-language': _HTTP_BROWSER_ACCEPT_LANGUAGE,
        'origin': 'https://auth.openai.com',
        'priority': _HTTP_BROWSER_FETCH_PRIORITY,
        'referer': referer,
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
    }
    headers.update(_build_http_browser_identity_headers(impersonate=impersonate))
    return headers


def _build_http_datadog_trace_headers() -> dict[str, str]:
    trace_hex = uuid.uuid4().hex[-16:]
    parent_hex = uuid.uuid4().hex[-16:]
    return {
        'x-datadog-origin': 'rum',
        'x-datadog-trace-id': str(int(trace_hex, 16)),
        'x-datadog-parent-id': str(int(parent_hex, 16)),
        'x-datadog-sampling-priority': '1',
        'traceparent': f'00-{"0" * 16}{trace_hex}-{parent_hex}-01',
        'tracestate': 'dd=s:1;o:rum',
    }


def _build_http_sentinel_headers(*, sentinel_token: str, session_observer_token: str = '') -> dict[str, str]:
    headers: dict[str, str] = {}
    sentinel_value = str(sentinel_token or '').strip()
    if sentinel_value:
        headers['OpenAI-Sentinel-Token'] = sentinel_value
    observer_value = str(session_observer_token or '').strip()
    if observer_value:
        headers['OpenAI-Sentinel-SO-Token'] = observer_value
    return headers


def _is_http_sentinel_frame_url(url: Any) -> bool:
    return str(url or '').strip().lower().startswith(_HTTP_SENTINEL_FRAME_URL_PREFIX.lower())


def _extract_http_sentinel_frame_version(frame_url: Any) -> str:
    text = str(frame_url or '').strip()
    if not text:
        return ''
    try:
        parsed = urllib.parse.urlparse(text)
        values = urllib.parse.parse_qs(parsed.query or '')
    except Exception:
        return ''
    version_values = values.get('sv') or []
    if not version_values:
        return ''
    return str(version_values[0] or '').strip()


def _build_http_sentinel_frame_sdk_urls(frame_url: Any) -> list[str]:
    urls: list[str] = []
    version = _extract_http_sentinel_frame_version(frame_url)
    if version:
        urls.append(
            'https://sentinel.openai.com/sentinel/'
            f'{urllib.parse.quote(version, safe="")}/sdk.js'
        )
    urls.append(_HTTP_SENTINEL_SDK_FALLBACK_URL)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in urls:
        value = str(item or '').strip()
        if (not value) or (value in seen):
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _http_sentinel_browser_helper_enabled() -> bool:
    return _read_bool_env('AIO_CODEX_OAUTH_HTTP_SENTINEL_BROWSER_HELPER', True)


def _http_sentinel_browser_helper_headless() -> bool:
    raw = str(os.getenv('AIO_CODEX_OAUTH_HTTP_SENTINEL_BROWSER_HELPER_HEADLESS', '') or '').strip()
    if raw:
        return _read_bool_env('AIO_CODEX_OAUTH_HTTP_SENTINEL_BROWSER_HELPER_HEADLESS', True)
    if os.name != 'nt' and not str(os.getenv('DISPLAY', '') or '').strip():
        return True
    return False


def _http_sentinel_browser_helper_timeout_ms(default: int = 25_000) -> int:
    raw = str(os.getenv('AIO_CODEX_OAUTH_HTTP_SENTINEL_BROWSER_TIMEOUT_MS', '') or '').strip()
    if raw.isdigit():
        value = int(raw)
        if value >= 5_000:
            return value
    return int(default)


def _pick_free_loopback_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _pick_http_sentinel_debug_port() -> int:
    return _pick_free_loopback_port()


def _wait_http_sentinel_debug_port(*, port: int, timeout_ms: int) -> None:
    deadline = time.monotonic() + max(1, int(timeout_ms)) / 1000.0
    endpoint = f'http://127.0.0.1:{int(port)}/json/version'
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(endpoint, timeout=1.5) as resp:
                if int(getattr(resp, 'status', 0) or 0) == 200:
                    return
        except Exception:
            time.sleep(0.3)
    raise TimeoutError(f'cdp_debug_port_timeout: {port}')


def _resolve_http_sentinel_browser_executable() -> str:
    requested = str(os.getenv('AIO_CODEX_OAUTH_HTTP_SENTINEL_BROWSER_EXECUTABLE', '') or '').strip()
    if requested:
        path = Path(requested).expanduser()
        if path.is_file():
            return str(path)
        return ''
    # Linux 服务器默认走 Playwright 自带 Chromium；系统 Chromium/snap 的 CDP 常超时。
    if os.name != 'nt':
        return ''
    candidates: list[str] = []
    which_keys = (
        'chrome.exe',
        'chrome',
        'msedge.exe',
        'msedge',
        'google-chrome',
        'google-chrome-stable',
        'chromium',
        'chromium-browser',
    )
    for key in which_keys:
        found = shutil.which(key)
        if found:
            candidates.append(found)
    candidates.extend(
        [
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
            str(Path(os.getenv('LOCALAPPDATA', '')) / 'Google' / 'Chrome' / 'Application' / 'chrome.exe'),
            r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            str(Path(os.getenv('LOCALAPPDATA', '')) / 'Microsoft' / 'Edge' / 'Application' / 'msedge.exe'),
            '/usr/bin/google-chrome',
            '/usr/bin/google-chrome-stable',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
            '/snap/bin/chromium',
        ]
    )
    for item in candidates:
        path = Path(str(item or '').strip()).expanduser()
        if path.is_file():
            return str(path)
    return ''


def _resolve_http_sentinel_helper_target_urls(flow_names: Optional[Sequence[str]] = None) -> tuple[str, ...]:
    flows = {
        str(item or '').strip()
        for item in (flow_names or ())
        if str(item or '').strip()
    }
    urls: list[str] = []
    if flows & _HTTP_REGISTER_SENTINEL_FLOWS:
        urls.extend(_HTTP_SENTINEL_REGISTER_HELPER_TARGET_URLS)
    urls.extend(_HTTP_SENTINEL_HELPER_TARGET_URLS)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in urls:
        value = str(item or '').strip()
        if value and value not in seen:
            seen.add(value)
            deduped.append(value)
    return tuple(deduped)


def _iter_http_sentinel_fallback_header_candidates(*, flow_name: str = '') -> list[tuple[str, dict[str, str]]]:
    sentinel_override = str(os.getenv('AIO_CODEX_OAUTH_HTTP_SENTINEL_TOKEN', '') or '').strip()
    session_observer_override = str(os.getenv('AIO_CODEX_OAUTH_HTTP_SENTINEL_SO_TOKEN', '') or '').strip()
    if sentinel_override:
        return [
            (
                str(flow_name or 'override').strip() or 'override',
                _build_http_sentinel_headers(
                    sentinel_token=sentinel_override,
                    session_observer_token=session_observer_override,
                ),
            )
        ]
    return [
        (
            'sdk_missing',
            _build_http_sentinel_headers(
                sentinel_token=_HTTP_SENTINEL_TOKEN_SDK_MISSING,
            ),
        ),
        (
            'token_failed',
            _build_http_sentinel_headers(
                sentinel_token=_HTTP_SENTINEL_TOKEN_TOKEN_FAILED,
            ),
        ),
    ]


def _iter_http_authorize_continue_fallback_header_candidates() -> list[tuple[str, dict[str, str]]]:
    return _iter_http_sentinel_fallback_header_candidates(flow_name=_HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW)


def _iter_http_password_verify_fallback_header_candidates() -> list[tuple[str, dict[str, str]]]:
    return _iter_http_sentinel_fallback_header_candidates(flow_name=_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW)


async def _launch_http_sentinel_browser(
    *,
    playwright: Any,
    proxy_opt: Optional[dict[str, str]] = None,
) -> tuple[Any, str, Optional[subprocess.Popen[Any]], str]:
    launch_kwargs: dict[str, Any] = {
        'headless': _http_sentinel_browser_helper_headless(),
        'args': ['--disable-blink-features=AutomationControlled'],
    }
    if proxy_opt:
        launch_kwargs['proxy'] = proxy_opt
    if not bool(launch_kwargs['headless']):
        launch_kwargs['args'].extend(
            [
                '--window-position=-32000,-32000',
                '--window-size=1280,800',
            ]
        )

    external_executable = _resolve_http_sentinel_browser_executable()
    if external_executable:
        debug_port = _pick_http_sentinel_debug_port()
        profile_dir = tempfile.mkdtemp(prefix='aio_codex_sentinel_')
        args = [
            external_executable,
            f'--remote-debugging-port={debug_port}',
            f'--user-data-dir={profile_dir}',
            '--lang=en-US',
            '--window-size=1280,800',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-blink-features=AutomationControlled',
        ]
        if bool(launch_kwargs['headless']):
            args.append('--headless=new')
        else:
            args.append('--window-position=-32000,-32000')
        if proxy_opt and str(proxy_opt.get('server') or '').strip():
            args.append(f'--proxy-server={str(proxy_opt.get("server") or "").strip()}')
        args.append('about:blank')
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            await asyncio.to_thread(
                _wait_http_sentinel_debug_port,
                port=debug_port,
                timeout_ms=_http_sentinel_browser_helper_timeout_ms(default=15_000),
            )
            browser = await playwright.chromium.connect_over_cdp(f'http://127.0.0.1:{debug_port}')
            return browser, f'cdp:{Path(external_executable).name}', proc, profile_dir
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            shutil.rmtree(profile_dir, ignore_errors=True)

    requested_channel = str(
        os.getenv(
            'AIO_CODEX_OAUTH_HTTP_SENTINEL_BROWSER_CHANNEL',
            'chrome' if os.name == 'nt' else '',
        )
        or ''
    ).strip()
    if requested_channel:
        try:
            browser = await playwright.chromium.launch(channel=requested_channel, **launch_kwargs)
            return browser, f'channel:{requested_channel}', None, ''
        except Exception:
            pass

    executable_path = str(os.getenv('AIO_CODEX_OAUTH_HTTP_SENTINEL_BROWSER_EXECUTABLE', '') or '').strip()
    if executable_path:
        browser = await playwright.chromium.launch(executable_path=executable_path, **launch_kwargs)
        return browser, f'executable:{executable_path}', None, ''

    browser = await playwright.chromium.launch(**launch_kwargs)
    return browser, 'bundled', None, ''


async def _wait_for_http_sentinel_frame(
    *,
    page: Any,
    trace: Optional[Any],
    timeout_ms: int,
) -> tuple[Any, str]:
    deadline = time.monotonic() + max(1, int(timeout_ms)) / 1000.0
    last_title = ''
    last_page_url = ''
    last_frame_urls: list[str] = []
    challenge_detected = False

    while True:
        try:
            last_page_url = str(getattr(page, 'url', '') or '').strip()
        except Exception:
            last_page_url = ''
        try:
            last_title = str(await page.title() or '').strip()
        except Exception:
            pass

        try:
            frames = list(page.frames)
        except Exception:
            frames = []
        last_frame_urls = [str(getattr(frame, 'url', '') or '').strip() for frame in frames]
        for frame in frames:
            frame_url = str(getattr(frame, 'url', '') or '').strip()
            if _is_http_sentinel_frame_url(frame_url):
                if trace is not None:
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_auth_sentinel_browser_helper_frame_ready',
                            'pageUrl': _sanitize_url_for_log(last_page_url),
                            'title': _compress_debug_text(last_title, limit=160),
                            'frameUrl': _sanitize_url_for_log(frame_url),
                        }
                    )
                return frame, frame_url

        lower_title = last_title.lower()
        lower_frames = '\n'.join(last_frame_urls).lower()
        if (
            ('challenge-platform' in lower_frames)
            or ('turnstile' in lower_frames)
            or ('just a moment' in lower_title)
            or ('请稍候' in last_title)
        ):
            challenge_detected = True

        if time.monotonic() >= deadline:
            break
        await page.wait_for_timeout(750)

    if trace is not None:
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_sentinel_browser_helper_frame_missing',
                'pageUrl': _sanitize_url_for_log(last_page_url),
                'title': _compress_debug_text(last_title, limit=160),
                'challengeDetected': challenge_detected,
                'frameUrls': _compress_debug_text(
                    json.dumps(last_frame_urls, ensure_ascii=False),
                    limit=480,
                ),
            }
        )
    return None, ''


async def _seed_http_sentinel_context_from_storage_state(
    *,
    context: Any,
    page: Any,
    storage_state_path: str,
) -> None:
    state_path = Path(str(storage_state_path or '').strip()).expanduser()
    if (not str(state_path)) or (not state_path.is_file()):
        return
    try:
        payload = json.loads(state_path.read_text(encoding='utf-8'))
    except Exception:
        return
    cookies = payload.get('cookies') if isinstance(payload, dict) else None
    if isinstance(cookies, list) and cookies:
        try:
            await context.add_cookies(cookies)
        except Exception:
            pass
    origins = payload.get('origins') if isinstance(payload, dict) else None
    if not isinstance(origins, list):
        return
    for item in origins:
        if not isinstance(item, dict):
            continue
        origin_url = str(item.get('origin') or '').strip()
        local_items = item.get('localStorage')
        if (not origin_url) or (not isinstance(local_items, list)) or (not local_items):
            continue
        try:
            await page.goto(origin_url, wait_until='domcontentloaded', timeout=60_000)
            await page.evaluate(
                """
                (items) => {
                  for (const item of Array.isArray(items) ? items : []) {
                    const key = String((item && item.name) || '');
                    const value = String((item && item.value) || '');
                    if (!key) {
                      continue;
                    }
                    window.localStorage.setItem(key, value);
                  }
                }
                """,
                local_items,
            )
        except Exception:
            continue


async def _evaluate_http_sentinel_token_from_page(
    *,
    page: Any,
    flow_name: str,
    frame_url: str,
) -> dict[str, Any]:
    sdk_urls = _build_http_sentinel_frame_sdk_urls(frame_url)
    return await page.evaluate(
        """
        async ({ flowName, initFlow, sdkUrls }) => {
          const normalize = (value) => {
            if (!value) {
              return '';
            }
            if (typeof value === 'string') {
              return value;
            }
            try {
              return JSON.stringify(value || {});
            } catch (_error) {
              return String(value);
            }
          };

          const attemptedUrls = [];
          const sentinelReqLog = [];
          const originalFetch = (typeof window.fetch === 'function') ? window.fetch.bind(window) : null;
          if (originalFetch) {
            window.fetch = async (...args) => {
              const input = args[0];
              const requestUrl = (typeof input === 'string')
                ? input
                : String((input && input.url) || '');
              const init = args[1] || {};
              const isReqCall = requestUrl.includes('/backend-api/sentinel/req');
              const bodyPreview = isReqCall && (typeof init.body === 'string')
                ? init.body.slice(0, 400)
                : '';
              try {
                const response = await originalFetch(...args);
                if (isReqCall) {
                  sentinelReqLog.push({
                    url: requestUrl,
                    status: Number(response.status || 0),
                    bodyPreview,
                  });
                }
                return response;
              } catch (error) {
                if (isReqCall) {
                  sentinelReqLog.push({
                    url: requestUrl,
                    status: -1,
                    bodyPreview,
                    error: String(error && error.message ? error.message : error),
                  });
                }
                throw error;
              }
            };
          }

          const loadScript = (src) => new Promise((resolve, reject) => {
            if (!src) {
              reject(new Error('empty_src'));
              return;
            }
            attemptedUrls.push(String(src));
            const existing = Array.from(document.scripts || []).find((item) => item.src === src);
            if (existing && window.SentinelSDK && typeof window.SentinelSDK.token === 'function') {
              resolve(src);
              return;
            }
            const script = document.createElement('script');
            script.type = 'text/javascript';
            script.src = src;
            script.async = true;
            script.defer = true;
            script.onload = () => resolve(src);
            script.onerror = () => reject(new Error('load failed: ' + src));
            (document.head || document.body || document.documentElement).appendChild(script);
          });

          try {
            if (!window.SentinelSDK || typeof window.SentinelSDK.token !== 'function') {
              for (const src of Array.isArray(sdkUrls) ? sdkUrls : []) {
                try {
                  await loadScript(src);
                } catch (_loadError) {}
                if (window.SentinelSDK && typeof window.SentinelSDK.token === 'function') {
                  break;
                }
              }
            }

            if (!window.SentinelSDK || typeof window.SentinelSDK.token !== 'function') {
              return {
                ok: false,
                error: 'sentinel_sdk_unavailable',
                tokenSource: attemptedUrls.length ? 'iframe_sdk_load_failed' : 'iframe_sdk_missing',
                attemptedUrls,
                sentinelReqLog,
                frameUrl: location.href,
              };
            }

            if (typeof window.SentinelSDK.init === 'function') {
              try {
                await window.SentinelSDK.init(initFlow);
              } catch (_initError) {}
            }

            const rawToken = await window.SentinelSDK.token(flowName);
            let rawSessionObserverToken = '';
            if (typeof window.SentinelSDK.sessionObserverToken === 'function') {
              try {
                rawSessionObserverToken = await window.SentinelSDK.sessionObserverToken(flowName);
              } catch (_soError) {}
            }
            return {
              ok: !!rawToken,
              token: normalize(rawToken),
              sessionObserverToken: normalize(rawSessionObserverToken),
              tokenSource: attemptedUrls.length ? 'iframe_sdk_loaded' : 'iframe_sdk_existing',
              attemptedUrls,
              sentinelReqLog,
              frameUrl: location.href,
            };
          } catch (error) {
            return {
              ok: false,
              error: String(error && error.message ? error.message : error),
              tokenSource: 'iframe_token_error',
              attemptedUrls,
              sentinelReqLog,
              frameUrl: location.href,
            };
          } finally {
            if (originalFetch) {
              window.fetch = originalFetch;
            }
          }
        }
        """,
        {
            'flowName': str(flow_name or '').strip(),
            'initFlow': _HTTP_SENTINEL_INIT_FLOW,
            'sdkUrls': sdk_urls,
        },
    )


async def _mint_http_sentinel_header_candidates(
    *,
    playwright: Any,
    storage_state_path: str,
    proxy_opt: Optional[dict[str, str]],
    trace: Optional[Any],
    timeout_ms: int,
    flow_names: Optional[Sequence[str]] = None,
) -> list[tuple[str, dict[str, str]]]:
    if (playwright is None) or (not _http_sentinel_browser_helper_enabled()):
        return []

    dynamic_candidates: list[tuple[str, dict[str, str]]] = []
    helper_timeout_ms = _http_sentinel_browser_helper_timeout_ms(default=timeout_ms)
    requested_flow_names = tuple(
        dict.fromkeys(
            str(item or '').strip()
            for item in (flow_names or (_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW,))
            if str(item or '').strip()
        )
    )
    if not requested_flow_names:
        requested_flow_names = (_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW,)

    state_path_text = str(storage_state_path or '').strip()
    context_modes: list[tuple[str, str]] = []
    if state_path_text:
        context_modes.append(('storage_state', state_path_text))
    context_modes.append(('clean', ''))
    resolved_helper_urls = _resolve_http_sentinel_helper_target_urls(requested_flow_names)
    found_flows: set[str] = set()
    for context_mode, context_storage_state in context_modes:
        browser = None
        browser_proc: Optional[subprocess.Popen[Any]] = None
        browser_profile_dir = ''
        context = None
        try:
            browser, launch_mode, browser_proc, browser_profile_dir = await _launch_http_sentinel_browser(
                playwright=playwright,
                proxy_opt=proxy_opt,
            )
            if browser_proc is not None:
                context = browser.contexts[0] if browser.contexts else None
                if context is None:
                    raise RuntimeError('sentinel_helper_cdp_context_missing')
                await context.add_init_script(
                    """
                    Object.defineProperty(navigator, 'webdriver', {
                      configurable: true,
                      get: () => undefined,
                    });
                    """
                )
                page = context.pages[0] if context.pages else await context.new_page()
                if context_storage_state:
                    await _seed_http_sentinel_context_from_storage_state(
                        context=context,
                        page=page,
                        storage_state_path=context_storage_state,
                    )
            else:
                context_kwargs: dict[str, Any] = {
                    'ignore_https_errors': True,
                    'locale': 'en-US',
                    'user_agent': _HTTP_BROWSER_USER_AGENT,
                    'viewport': {'width': 1280, 'height': 800},
                }
                if context_storage_state:
                    context_kwargs['storage_state'] = context_storage_state
                context = await browser.new_context(**context_kwargs)
                await context.add_init_script(
                    """
                    Object.defineProperty(navigator, 'webdriver', {
                      configurable: true,
                      get: () => undefined,
                    });
                    """
                )
                page = await context.new_page()
            page.set_default_timeout(helper_timeout_ms)
            for helper_url in resolved_helper_urls:
                try:
                    await page.goto(helper_url, wait_until='domcontentloaded', timeout=helper_timeout_ms)
                except Exception as error:
                    if trace is not None:
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': 'http_auth_sentinel_browser_helper_page_failed',
                                'launchMode': launch_mode,
                                'contextMode': context_mode,
                                'targetUrl': _sanitize_url_for_log(helper_url),
                                'error': _compress_debug_text(str(error or ''), limit=240),
                            }
                        )
                    continue
                sentinel_frame, sentinel_frame_url = await _wait_for_http_sentinel_frame(
                    page=page,
                    trace=trace,
                    timeout_ms=helper_timeout_ms,
                )
                if sentinel_frame is None:
                    continue

                for flow_name in requested_flow_names:
                    if flow_name in found_flows:
                        continue
                    result = await _evaluate_http_sentinel_token_from_page(
                        page=page,
                        flow_name=flow_name,
                        frame_url=sentinel_frame_url,
                    )
                    token_value = str((result or {}).get('token') or '').strip()
                    session_observer_value = str((result or {}).get('sessionObserverToken') or '').strip()
                    if trace is not None:
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': 'http_auth_sentinel_browser_helper',
                                'flow': flow_name,
                                'launchMode': launch_mode,
                                'contextMode': context_mode,
                                'targetUrl': _sanitize_url_for_log(helper_url),
                                'ok': bool((result or {}).get('ok')),
                                'tokenSource': str((result or {}).get('tokenSource') or '').strip(),
                                'frameUrl': _sanitize_url_for_log(str((result or {}).get('frameUrl') or sentinel_frame_url)),
                                'attemptedSdkUrls': _compress_debug_text(
                                    json.dumps((result or {}).get('attemptedUrls') or [], ensure_ascii=False),
                                    limit=320,
                                ),
                                'sentinelReqLog': _compress_debug_text(
                                    json.dumps((result or {}).get('sentinelReqLog') or [], ensure_ascii=False),
                                    limit=480,
                                ),
                                'tokenPreview': _compress_debug_text(token_value, limit=160),
                                'sessionObserverPreview': _compress_debug_text(session_observer_value, limit=160),
                                'error': _compress_debug_text((result or {}).get('error'), limit=240),
                            }
                        )
                    if token_value:
                        dynamic_candidates.append(
                            (
                                f'browser_{context_mode}_{flow_name}',
                                _build_http_sentinel_headers(
                                    sentinel_token=token_value,
                                    session_observer_token=session_observer_value,
                                ),
                            )
                        )
                        found_flows.add(flow_name)
                if all(flow_name in found_flows for flow_name in requested_flow_names):
                    break
            if (
                all(flow_name in found_flows for flow_name in requested_flow_names)
                and (context_mode == 'storage_state' or not state_path_text)
            ):
                break
        except Exception as error:
            if trace is not None:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_sentinel_browser_helper_failed',
                        'contextMode': context_mode,
                        'error': _compress_debug_text(str(error or ''), limit=320),
                    }
                )
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            if browser is not None:
                try:
                    await browser.close()
                except Exception:
                    pass
            if browser_proc is not None:
                try:
                    browser_proc.terminate()
                    browser_proc.wait(timeout=5)
                except Exception:
                    try:
                        browser_proc.kill()
                    except Exception:
                        pass
            if browser_profile_dir:
                shutil.rmtree(browser_profile_dir, ignore_errors=True)
    storage_state_candidates = [
        item for item in dynamic_candidates if str(item[0] or '').startswith('browser_storage_state_')
    ]
    clean_candidates = [
        item for item in dynamic_candidates if not str(item[0] or '').startswith('browser_storage_state_')
    ]
    return storage_state_candidates + clean_candidates


async def _iter_http_password_verify_header_candidates(
    *,
    playwright: Any = None,
    storage_state_path: str = '',
    proxy_opt: Optional[dict[str, str]] = None,
    trace: Optional[Any] = None,
    timeout_ms: int = 25_000,
) -> list[tuple[str, dict[str, str]]]:
    collected = await _collect_http_sentinel_header_candidates_for_flows(
        flow_names=(_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW,),
        playwright=playwright,
        storage_state_path=storage_state_path,
        proxy_opt=proxy_opt,
        trace=trace,
        timeout_ms=timeout_ms,
    )
    return list(collected.get(_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW) or [])


def _extract_http_sentinel_flow_from_headers(headers: Optional[dict[str, str]]) -> str:
    if not isinstance(headers, dict):
        return ''
    token_value = ''
    for key in ('OpenAI-Sentinel-Token', 'openai-sentinel-token'):
        raw = headers.get(key)
        if raw:
            token_value = str(raw).strip()
            break
    if not token_value:
        return ''
    try:
        parsed = json.loads(token_value)
    except Exception:
        return ''
    if not isinstance(parsed, dict):
        return ''
    return str(parsed.get('flow') or '').strip()


def _http_sentinel_prefers_fallback_first(flow_name: str) -> bool:
    normalized_flow = str(flow_name or '').strip()
    return (
        normalized_flow in _HTTP_REGISTER_SENTINEL_FLOWS
        or normalized_flow == _HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW
    )


def _http_sentinel_skip_browser_for_flows(flow_names: Sequence[str]) -> bool:
    if str(os.getenv('AIO_CODEX_OAUTH_HTTP_SENTINEL_FORCE_BROWSER', '') or '').strip() == '1':
        return False
    requested = [str(item or '').strip() for item in flow_names if str(item or '').strip()]
    if not requested:
        return False
    return all(_http_sentinel_prefers_fallback_first(flow_name) for flow_name in requested)


def _iter_http_sentinel_fallback_candidates_for_flow(flow_name: str) -> list[tuple[str, dict[str, str]]]:
    normalized_flow = str(flow_name or '').strip()
    if normalized_flow == _HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW:
        return _iter_http_authorize_continue_fallback_header_candidates()
    if normalized_flow == _HTTP_PASSWORD_VERIFY_SENTINEL_FLOW:
        return _iter_http_password_verify_fallback_header_candidates()
    if normalized_flow in _HTTP_REGISTER_SENTINEL_FLOWS:
        return _iter_http_sentinel_fallback_header_candidates(flow_name=normalized_flow)
    return _iter_http_sentinel_fallback_header_candidates(flow_name=normalized_flow)


async def _collect_http_sentinel_header_candidates_for_flows(
    *,
    flow_names: Sequence[str],
    playwright: Any = None,
    storage_state_path: str = '',
    proxy_opt: Optional[dict[str, str]] = None,
    trace: Optional[Any] = None,
    timeout_ms: int = 25_000,
) -> dict[str, list[tuple[str, dict[str, str]]]]:
    requested_flows = tuple(
        dict.fromkeys(str(item or '').strip() for item in flow_names if str(item or '').strip())
    )
    collected: dict[str, list[tuple[str, dict[str, str]]]] = {flow_name: [] for flow_name in requested_flows}
    if not requested_flows:
        return collected

    skip_browser_mint = _http_sentinel_skip_browser_for_flows(requested_flows)
    playwright_instance = playwright
    playwright_manager: Any = None
    owns_playwright = False
    if (
        (not skip_browser_mint)
        and playwright_instance is None
        and async_playwright is not None
        and _http_sentinel_browser_helper_enabled()
    ):
        try:
            playwright_manager = await async_playwright().start()
            playwright_instance = playwright_manager
            owns_playwright = True
            if trace is not None:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_sentinel_playwright_autostart',
                        'headless': _http_sentinel_browser_helper_headless(),
                    }
                )
        except Exception as error:
            if trace is not None:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_sentinel_playwright_autostart_failed',
                        'error': _compress_debug_text(str(error or ''), limit=320),
                    }
                )

    try:
        if skip_browser_mint:
            dynamic_candidates: list[tuple[str, dict[str, str]]] = []
            if trace is not None:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_sentinel_browser_helper_skipped',
                        'reason': 'register_fallback_first',
                        'flowNames': list(requested_flows),
                    }
                )
        else:
            dynamic_candidates = await _mint_http_sentinel_header_candidates(
                playwright=playwright_instance,
                storage_state_path=storage_state_path,
                proxy_opt=proxy_opt,
                trace=trace,
                timeout_ms=timeout_ms,
                flow_names=requested_flows,
            )
        for candidate_name, candidate_headers in dynamic_candidates:
            flow_name = _extract_http_sentinel_flow_from_headers(candidate_headers)
            if flow_name in collected:
                collected[flow_name].append((candidate_name, candidate_headers))
        for flow_name in requested_flows:
            fallback_candidates = _iter_http_sentinel_fallback_candidates_for_flow(flow_name)
            dynamic_for_flow = list(collected.get(flow_name) or [])
            if _http_sentinel_prefers_fallback_first(flow_name):
                collected[flow_name] = list(fallback_candidates) + dynamic_for_flow
            elif dynamic_for_flow:
                collected[flow_name] = dynamic_for_flow + list(fallback_candidates)
            else:
                collected[flow_name] = list(fallback_candidates)
    finally:
        if owns_playwright and playwright_manager is not None:
            try:
                await playwright_manager.stop()
            except Exception:
                pass
    return collected


async def _iter_http_authorize_continue_header_candidates(
    *,
    playwright: Any = None,
    storage_state_path: str = '',
    proxy_opt: Optional[dict[str, str]] = None,
    trace: Optional[Any] = None,
    timeout_ms: int = 25_000,
) -> list[tuple[str, dict[str, str]]]:
    collected = await _collect_http_sentinel_header_candidates_for_flows(
        flow_names=(_HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW,),
        playwright=playwright,
        storage_state_path=storage_state_path,
        proxy_opt=proxy_opt,
        trace=trace,
        timeout_ms=timeout_ms,
    )
    return list(collected.get(_HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW) or [])


async def _request_with_context(
    request_ctx: Any,
    *,
    method: str,
    url: str,
    headers: Optional[dict[str, str]] = None,
    body_text: str = '',
    timeout_ms: int = 60_000,
    max_redirects: int = 0,
) -> tuple[dict[str, Any], int, str, str, dict[str, str]]:
    merged_headers = _build_http_browser_identity_headers(
        impersonate=_resolve_request_ctx_impersonate(request_ctx),
    )
    if isinstance(headers, dict):
        for key, value in headers.items():
            if value is None:
                continue
            merged_headers[str(key)] = str(value)
    method_text = str(method or 'GET').strip().upper() or 'GET'
    if method_text == 'POST':
        resp = await request_ctx.post(
            str(url or '').strip(),
            headers=merged_headers,
            data=(body_text if body_text else None),
            timeout=int(max(1000, timeout_ms)),
            fail_on_status_code=False,
            max_redirects=int(max(0, max_redirects)),
        )
    else:
        resp = await request_ctx.get(
            str(url or '').strip(),
            headers=merged_headers,
            timeout=int(max(1000, timeout_ms)),
            fail_on_status_code=False,
            max_redirects=int(max(0, max_redirects)),
        )
    text = ''
    try:
        text = await resp.text()
    except Exception:
        text = ''
    payload: dict[str, Any] = {}
    if text:
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            payload = parsed
    response_headers = {str(key).lower(): str(value) for key, value in dict(resp.headers or {}).items()}
    return payload, int(resp.status or 0), text, str(resp.url or url).strip(), response_headers


async def _request_json_with_context(
    request_ctx: Any,
    *,
    url: str,
    headers: Optional[dict[str, str]] = None,
    timeout_ms: int = 60_000,
) -> tuple[dict[str, Any], int, str]:
    merged_headers = {'accept': 'application/json'}
    if isinstance(headers, dict):
        for key, value in headers.items():
            if value is None:
                continue
            merged_headers[str(key)] = str(value)
    payload, status, text, _response_url, _response_headers = await _request_with_context(
        request_ctx,
        method='GET',
        url=url,
        headers=merged_headers,
        timeout_ms=timeout_ms,
        max_redirects=0,
    )
    return payload, status, text


async def _request_auth_api_with_context(
    request_ctx: Any,
    *,
    stage: str,
    path: str,
    method: str,
    timeout_ms: int,
    trace: _TraceWriter,
    referer_url: str = '',
    accept: str = 'application/json',
    include_json_content_type: bool = True,
    json_body: Optional[dict[str, Any]] = None,
    trace_json_body: Optional[dict[str, Any]] = None,
    extra_headers: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    base = 'https://auth.openai.com/api/accounts'
    url = f'{base}{path}'
    method_text = str(method or 'GET').strip().upper() or 'GET'
    headers = _build_http_auth_fetch_headers(
        referer_url=referer_url,
        accept=accept,
        impersonate=_resolve_request_ctx_impersonate(request_ctx),
    )
    if method_text == 'POST' and bool(include_json_content_type):
        headers['content-type'] = 'application/json'
    device_id = get_http_stage_device_id()
    if device_id:
        headers['oai-device-id'] = device_id
    headers.update(_build_http_datadog_trace_headers())
    set_http_stage_feature_stage(stage)
    body_text = ''
    if json_body is not None:
        body_text = json.dumps(json_body, ensure_ascii=False)
    trace_body_text = body_text
    if trace_json_body is not None:
        trace_body_text = json.dumps(trace_json_body, ensure_ascii=False)
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if value in (None, ''):
                continue
            headers[str(key)] = str(value)
    trace.write(
        {
            'ts': _iso_now(),
            'stage': stage,
            'method': method_text,
            'url': url,
            'requestHeaders': headers,
            'requestBody': _compress_debug_text(trace_body_text, limit=400),
            'stageFeature': get_http_stage_feature_summary(),
        }
    )
    payload, status, text, response_url, response_headers = await _request_with_context(
        request_ctx,
        method=method_text,
        url=url,
        headers=headers,
        body_text=body_text,
        timeout_ms=timeout_ms,
        max_redirects=0,
    )
    trace.write(
        {
            'ts': _iso_now(),
            'stage': stage,
            'status': status,
            'responseUrl': _sanitize_url_for_log(response_url),
            'responseHeaders': response_headers,
            'bodySnippet': _compress_debug_text(text, limit=800),
            'hints': _collect_auth_step_hints(payload),
        }
    )
    return {
        'status': status,
        'url': response_url,
        'text': text,
        'payload': payload,
        'headers': response_headers,
    }


async def _read_request_context_storage_state(request_ctx: Any) -> dict[str, Any]:
    try:
        state = await request_ctx.storage_state()
        return state if isinstance(state, dict) else {}
    except TypeError:
        temp_path = ''
        try:
            with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as fh:
                temp_path = fh.name
            await request_ctx.storage_state(path=temp_path)
            payload = json.loads(Path(temp_path).read_text(encoding='utf-8') or '{}')
            return payload if isinstance(payload, dict) else {}
        finally:
            if temp_path:
                Path(temp_path).unlink(missing_ok=True)


async def _resolve_http_provider_workspace_context_for_consent(
    *,
    request_ctx: Any,
    workspace_ctx: dict[str, Any] | None,
    consent_url: str,
    timeout_sec: float,
    trace: _TraceWriter,
    log: Any,
    expected_workspace_id: str = '',
) -> dict[str, Any]:
    normalized_expected_workspace_id = str(expected_workspace_id or '').strip()
    current_workspace_ctx = _prefer_expected_workspace_context(workspace_ctx, normalized_expected_workspace_id)
    current_workspace_id = str(current_workspace_ctx.get('workspace_id') or '').strip()
    current_selected_workspace = _workspace_context_selected_workspace(current_workspace_ctx)
    current_workspace_kind = str(current_selected_workspace.get('kind') or '').strip().lower()
    current_workspace_name = str(
        current_selected_workspace.get('display_name')
        or current_selected_workspace.get('label')
        or current_workspace_id
    ).strip()
    current_workspace_is_personal = _workspace_context_is_personal(current_workspace_ctx)
    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'http_auth_workspace_ctx_current',
            'workspaceId': current_workspace_id,
            'workspaceSource': str(current_workspace_ctx.get('source') or '').strip(),
            'workspaceKind': current_workspace_kind,
            'workspaceName': _compress_debug_text(current_workspace_name, limit=120),
            'workspaceIsPersonal': current_workspace_is_personal,
        }
    )
    if current_workspace_id and (not current_workspace_is_personal) and (
        (not normalized_expected_workspace_id) or current_workspace_id == normalized_expected_workspace_id
    ):
        return current_workspace_ctx

    storage_state = await _read_request_context_storage_state(request_ctx)
    cookie_workspace_ctx = _prefer_expected_workspace_context(
        _choose_http_provider_workspace_context_from_storage_state(storage_state),
        normalized_expected_workspace_id,
    )
    cookie_workspace_id = str(cookie_workspace_ctx.get('workspace_id') or '').strip()
    selected_workspace = cookie_workspace_ctx.get('selected_workspace')
    if not isinstance(selected_workspace, dict):
        selected_workspace = {}
    refresh_reason = 'workspace_missing'
    if current_workspace_id and current_workspace_is_personal:
        refresh_reason = 'personal_workspace_requires_refresh'
    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'http_auth_workspace_ctx_from_storage_state',
            'workspaceId': cookie_workspace_id,
            'workspaceSource': str(cookie_workspace_ctx.get('source') or '').strip(),
            'workspaceKind': str(selected_workspace.get('kind') or '').strip(),
            'workspaceName': _compress_debug_text(
                selected_workspace.get('display_name') or selected_workspace.get('label') or '',
                limit=120,
            ),
            'workspaceCount': len(cookie_workspace_ctx.get('workspaces') or []),
            'refreshReason': refresh_reason,
        }
    )
    if cookie_workspace_id:
        cookie_workspace_ctx = _merge_http_provider_workspace_context(current_workspace_ctx, cookie_workspace_ctx)
        await _emit_log(
            log,
            'info',
            '【Codex OAuth】已从当前 HTTP 会话 cookie 补齐 workspace 上下文，'
            f'workspace={str(selected_workspace.get("display_name") or selected_workspace.get("label") or cookie_workspace_id).strip() or cookie_workspace_id}',
        )
        return cookie_workspace_ctx

    target_url = str(consent_url or '').strip()
    if not _is_codex_consent_url(target_url):
        return _prefer_expected_workspace_context(cookie_workspace_ctx or current_workspace_ctx, normalized_expected_workspace_id)

    try:
        _payload, status, body_text, response_url, response_headers = await _request_with_context(
            request_ctx,
            method='GET',
            url=target_url,
            headers=_build_http_html_headers(
                impersonate=_resolve_request_ctx_impersonate(request_ctx),
            ),
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            max_redirects=0,
        )
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_workspace_ctx_probe_consent',
                'status': status,
                'url': _sanitize_url_for_log(response_url),
                'location': _sanitize_url_for_log(str(response_headers.get('location') or '').strip()),
                'bodySnippet': _compress_debug_text(body_text, limit=320),
            }
        )
    except Exception as error:
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_workspace_ctx_probe_consent',
                'error': _compress_debug_text(str(error or ''), limit=320),
            }
        )
        return cookie_workspace_ctx or current_workspace_ctx

    storage_state = await _read_request_context_storage_state(request_ctx)
    cookie_workspace_ctx = _prefer_expected_workspace_context(
        _choose_http_provider_workspace_context_from_storage_state(storage_state),
        normalized_expected_workspace_id,
    )
    cookie_workspace_id = str(cookie_workspace_ctx.get('workspace_id') or '').strip()
    selected_workspace = cookie_workspace_ctx.get('selected_workspace')
    if not isinstance(selected_workspace, dict):
        selected_workspace = {}
    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'http_auth_workspace_ctx_after_consent_probe',
            'workspaceId': cookie_workspace_id,
            'workspaceSource': str(cookie_workspace_ctx.get('source') or '').strip(),
            'workspaceKind': str(selected_workspace.get('kind') or '').strip(),
            'workspaceName': _compress_debug_text(
                selected_workspace.get('display_name') or selected_workspace.get('label') or '',
                limit=120,
            ),
            'workspaceCount': len(cookie_workspace_ctx.get('workspaces') or []),
        }
    )
    if cookie_workspace_id:
        cookie_workspace_ctx = _merge_http_provider_workspace_context(current_workspace_ctx, cookie_workspace_ctx)
        await _emit_log(
            log,
            'info',
            '【Codex OAuth】已通过纯 HTTP 再探测 consent 页面补齐 workspace 上下文，'
            f'workspace={str(selected_workspace.get("display_name") or selected_workspace.get("label") or cookie_workspace_id).strip() or cookie_workspace_id}',
        )
    return _prefer_expected_workspace_context(cookie_workspace_ctx or current_workspace_ctx, normalized_expected_workspace_id)


async def _complete_http_codex_consent_via_http(
    *,
    request_ctx: Any,
    auth_url: str,
    consent_url: str,
    redirect_uri: str,
    expected_state: str,
    pkce: PKCECodes,
    client_id: str,
    workspace_ctx: dict[str, Any] | None,
    timeout_sec: float,
    trace: _TraceWriter,
    log: Any,
    proxy_url: str = '',
) -> Optional[OAuthCallback | dict[str, Any]]:
    target_url = str(consent_url or '').strip()
    if not _is_codex_consent_url(target_url):
        return None
    workspace_payload = workspace_ctx if isinstance(workspace_ctx, dict) else {}
    selected_workspace = workspace_payload.get('selected_workspace')
    if not isinstance(selected_workspace, dict):
        selected_workspace = {}
    workspace_id = str(selected_workspace.get('workspace_id') or workspace_payload.get('workspace_id') or '').strip()
    if not workspace_id:
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_workspace_select_skipped',
                'reason': 'workspace_id_missing',
            }
        )
        return None
    workspace_kind = str(selected_workspace.get('kind') or '').strip().lower()
    workspace_name = str(selected_workspace.get('display_name') or selected_workspace.get('label') or workspace_id).strip()
    attempt_plan = _build_http_codex_consent_attempts(
        workspace=selected_workspace or {'workspace_id': workspace_id},
        preferred_impersonate=_resolve_request_ctx_impersonate(request_ctx),
    )
    if not attempt_plan:
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_workspace_select_skipped',
                'reason': 'attempt_plan_empty',
                'workspaceId': workspace_id,
                'workspaceKind': workspace_kind,
            }
        )
        return None
    await _emit_log(
        log,
        'info',
        '【Codex OAuth】HTTP 登录链路进入 Codex consent，'
        f'准备先用纯 HTTP 完成 workspace/select：workspace={workspace_name}，'
        f'kind={workspace_kind or "unknown"}。',
    )
    select_url = 'https://auth.openai.com/api/accounts/workspace/select'
    select_timeout_ms = int(max(15_000, float(timeout_sec) * 1000.0 / 3.0))
    follow_timeout_ms = int(max(15_000, float(timeout_sec) * 1000.0 / 2.0))
    request_body = json.dumps({'workspace_id': workspace_id}, ensure_ascii=False)
    for attempt in attempt_plan:
        mode = str(attempt.get('mode') or '').strip().lower()
        attempt_label = str(attempt.get('label') or mode or 'workspace_select').strip()
        impersonate = str(attempt.get('impersonate') or '').strip()
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_workspace_select_attempt',
                'attempt': attempt_label,
                'mode': mode,
                'impersonate': impersonate,
                'workspaceId': workspace_id,
                'workspaceKind': workspace_kind,
                'workspaceName': workspace_name,
            }
        )
        response_headers: dict[str, str] = {}
        response_url = select_url
        response_text = ''
        select_payload: dict[str, Any] = {}
        status = 0
        challenge_detected = False
        callback: Optional[OAuthCallback] = None
        follow_error = ''
        try:
            if mode == 'curl_cffi':
                storage_state = await _read_request_context_storage_state(request_ctx)
                curl_result = await asyncio.to_thread(
                    _complete_http_codex_consent_via_curl_cffi,
                    consent_url=target_url,
                    workspace_id=workspace_id,
                    storage_state=storage_state,
                    auth_url=str(auth_url or '').strip(),
                    redirect_uri=redirect_uri,
                    expected_state=expected_state,
                    pkce=pkce,
                    client_id=client_id,
                    timeout_sec=max(10.0, min(float(timeout_sec or 0.0), 30.0)),
                    proxy_url=proxy_url,
                    impersonate=impersonate,
                    trace=trace,
                )
                select_result = curl_result.get('select_result') if isinstance(curl_result.get('select_result'), dict) else {}
                status = int(select_result.get('status') or 0)
                response_text = str(select_result.get('text') or '')
                response_url = str(select_result.get('response_url') or select_url).strip()
                select_payload = select_result.get('payload') if isinstance(select_result.get('payload'), dict) else {}
                response_headers = {
                    str(key).lower(): str(value)
                    for key, value in dict(select_result.get('response_headers') or {}).items()
                }
                challenge_detected = bool(select_result.get('challenge_detected'))
                callback = curl_result.get('callback') if isinstance(curl_result.get('callback'), OAuthCallback) else None
                follow_error = str(curl_result.get('follow_error') or '').strip()
            else:
                headers = _build_http_auth_fetch_headers(
                    referer_url=target_url,
                    accept='application/json',
                    impersonate=_resolve_request_ctx_impersonate(request_ctx),
                )
                headers['content-type'] = 'application/json'
                headers.update(_build_http_datadog_trace_headers())
                select_payload, status, response_text, response_url, response_headers = await _request_with_context(
                    request_ctx,
                    method='POST',
                    url=select_url,
                    headers=headers,
                    body_text=request_body,
                    timeout_ms=select_timeout_ms,
                    max_redirects=0,
                )
                challenge_detected = _response_looks_like_cloudflare_challenge(
                    status=status,
                    text=response_text,
                    response_url=response_url,
                    response_headers=response_headers,
                )
        except Exception as error:
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_auth_workspace_select_result',
                    'attempt': attempt_label,
                    'mode': mode,
                    'impersonate': impersonate,
                    'workspaceId': workspace_id,
                    'workspaceKind': workspace_kind,
                    'workspaceName': workspace_name,
                    'error': _compress_debug_text(str(error or ''), limit=300),
                }
            )
            await _emit_log(
                log,
                'warn',
                f'【Codex OAuth】workspace/select 纯 HTTP 尝试失败（{attempt_label}）：{error}',
            )
            continue
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_workspace_select_result',
                'attempt': attempt_label,
                'mode': mode,
                'impersonate': impersonate,
                'workspaceId': workspace_id,
                'workspaceKind': workspace_kind,
                'workspaceName': workspace_name,
                'status': status,
                'responseUrl': _sanitize_url_for_log(response_url),
                'responseHeaders': response_headers,
                'bodySnippet': _compress_debug_text(response_text, limit=800),
                'challengeDetected': challenge_detected,
            }
        )
        if challenge_detected:
            await _emit_log(
                log,
                'warn',
                f'【Codex OAuth】workspace/select 触发 Cloudflare challenge（{attempt_label}），继续尝试下一种纯 HTTP 策略。',
            )
            continue
        if status < 200 or status >= 400:
            await _emit_log(
                log,
                'warn',
                f'【Codex OAuth】workspace/select 返回 HTTP {status or 0}（{attempt_label}），继续尝试下一种纯 HTTP 策略。',
            )
            continue
        if callback is None:
            if mode == 'curl_cffi':
                detail = follow_error or 'curl_cffi_follow_authorize_returned_empty_callback'
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_workspace_select_follow_authorize_result',
                        'attempt': attempt_label,
                        'workspaceId': workspace_id,
                        'workspaceKind': workspace_kind,
                        'workspaceName': workspace_name,
                        'error': _compress_debug_text(detail, limit=300),
                    }
                )
                await _emit_log(
                    log,
                    'warn',
                    f'【Codex OAuth】workspace/select 已提交，但 curl_cffi follow authorize 未直接拿到 callback（{attempt_label}）：{detail}',
                )
                continue
            resume_authorize_url = str(_extract_continue_url(select_payload) or '').strip() or str(auth_url or '').strip()
            try:
                callback = await _follow_http_authorize_chain(
                    request_ctx,
                    auth_url=resume_authorize_url,
                    redirect_uri=redirect_uri,
                    expected_state=expected_state,
                    timeout_ms=follow_timeout_ms,
                    trace=trace,
                )
            except Exception as error:
                detail = str(error or '').strip()
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_workspace_select_follow_authorize_result',
                        'attempt': attempt_label,
                        'workspaceId': workspace_id,
                        'workspaceKind': workspace_kind,
                        'workspaceName': workspace_name,
                        'error': _compress_debug_text(detail, limit=300),
                    }
                )
                await _emit_log(
                    log,
                    'warn',
                    f'【Codex OAuth】workspace/select 已提交，但 follow authorize 未直接拿到 callback（{attempt_label}）：{detail or "unknown"}',
                )
                continue
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_auth_workspace_select_follow_authorize_result',
                'attempt': attempt_label,
                'workspaceId': workspace_id,
                'workspaceKind': workspace_kind,
                'workspaceName': workspace_name,
                'success': isinstance(callback, OAuthCallback),
                'hasCode': bool(getattr(callback, 'code', '')),
            }
        )
        if isinstance(callback, OAuthCallback):
            await _emit_log(
                log,
                'info',
                f'【Codex OAuth】已通过纯 HTTP 完成 workspace/select 并拿到 OAuth callback（{attempt_label}）。',
            )
            result: dict[str, Any] = {'callback': callback}
            if mode == 'curl_cffi':
                storage_state_from_result = curl_result.get('storage_state') if isinstance(curl_result, dict) else None
                if isinstance(storage_state_from_result, dict):
                    result['storage_state'] = storage_state_from_result
                token_result_from_result = curl_result.get('token_result') if isinstance(curl_result, dict) else None
                if isinstance(token_result_from_result, dict):
                    result['token_result'] = token_result_from_result
            return result
    return None


def _callback_from_url(*, url: str, expected_state: str, redirect_uri: str) -> Optional[OAuthCallback]:
    raw = str(url or '').strip()
    target = str(redirect_uri or '').strip()
    if not raw or not target:
        return None
    try:
        parsed = urllib.parse.urlsplit(raw)
        target_parsed = urllib.parse.urlsplit(target)
    except Exception:
        return None
    same_target = (
        str(parsed.scheme or '').strip().lower() == str(target_parsed.scheme or '').strip().lower()
        and str(parsed.hostname or '').strip().lower() == str(target_parsed.hostname or '').strip().lower()
        and int(parsed.port or _default_port_for_scheme(parsed.scheme)) == int(target_parsed.port or _default_port_for_scheme(target_parsed.scheme))
        and str(parsed.path or '').strip() == str(target_parsed.path or '').strip()
    )
    if not same_target:
        return None
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    state = str((query.get('state') or [''])[0] or '').strip()
    if expected_state and state and state != str(expected_state or '').strip():
        raise RuntimeError('http_auth_state_mismatch: OAuth 回调 state 不匹配。')
    return OAuthCallback(
        code=str((query.get('code') or [''])[0] or '').strip(),
        state=state,
        error=str((query.get('error') or [''])[0] or '').strip(),
        error_description=str((query.get('error_description') or [''])[0] or '').strip(),
    )


def _callback_from_text(*, text: str, expected_state: str, redirect_uri: str) -> Optional[OAuthCallback]:
    raw_text = str(text or '').strip()
    if not raw_text:
        return None
    candidate_urls: list[str] = []
    for matched in re.findall(r'https?://[^\s<>"\']+', raw_text, flags=re.IGNORECASE):
        candidate = str(matched or '').strip().rstrip('.,;)')
        if candidate:
            candidate_urls.append(candidate)
        decoded = urllib.parse.unquote(candidate)
        decoded = str(decoded or '').strip().rstrip('.,;)')
        if decoded and decoded != candidate:
            candidate_urls.append(decoded)
    for candidate in candidate_urls:
        callback = _callback_from_url(
            url=candidate,
            expected_state=expected_state,
            redirect_uri=redirect_uri,
        )
        if callback is not None and (callback.code or callback.error or callback.state):
            return callback
    return None


def _callback_from_snapshot(
    *,
    snapshot: dict[str, Any],
    expected_state: str,
    redirect_uri: str,
) -> Optional[OAuthCallback]:
    candidate_urls: list[str] = [str(snapshot.get('url') or '').strip()]
    for item in snapshot.get('frameUrls') or []:
        candidate_urls.append(str(item or '').strip())
    for candidate in candidate_urls:
        callback = _callback_from_url(
            url=candidate,
            expected_state=expected_state,
            redirect_uri=redirect_uri,
        )
        if callback is not None and (callback.code or callback.error or callback.state):
            return callback
    return _callback_from_text(
        text=str(snapshot.get('bodyText') or ''),
        expected_state=expected_state,
        redirect_uri=redirect_uri,
    )


async def _follow_http_authorize_chain(
    request_ctx: Any,
    *,
    auth_url: str,
    redirect_uri: str,
    expected_state: str,
    timeout_ms: int,
    trace: _TraceWriter,
    interactive_handler: Any = None,
    phone_handler: Any = None,
) -> OAuthCallback:
    current_url = str(auth_url or '').strip()
    if not current_url:
        raise RuntimeError('http_auth_code_missing: authorize URL 为空。')

    headers = _build_http_html_headers(
        impersonate=_resolve_request_ctx_impersonate(request_ctx),
    )
    interactive_attempts = 0
    for hop in range(1, 17):
        _payload, status, body_text, response_url, response_headers = await _request_with_context(
            request_ctx,
            method='GET',
            url=current_url,
            headers=headers,
            timeout_ms=timeout_ms,
            max_redirects=0,
        )
        location = str(response_headers.get('location') or '').strip()
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_authorize_hop',
                'hop': hop,
                'status': status,
                'url': _sanitize_url_for_log(current_url),
                'responseUrl': _sanitize_url_for_log(response_url),
                'location': _sanitize_url_for_log(location),
            }
        )
        try:
            callback = _callback_from_url(
                url=response_url,
                expected_state=expected_state,
                redirect_uri=redirect_uri,
            )
        except RuntimeError:
            raise
        if callback is not None and (callback.code or callback.error):
            return callback
        if 300 <= status < 400 and location:
            next_url = urllib.parse.urljoin(response_url or current_url, location)
            callback = _callback_from_url(
                url=next_url,
                expected_state=expected_state,
                redirect_uri=redirect_uri,
            )
            if callback is not None and (callback.code or callback.error or callback.state):
                return callback
            if callable(phone_handler) and (
                _is_auth_add_phone_url(next_url)
                or _is_auth_phone_otp_select_channel_url(next_url)
            ):
                handled = await phone_handler(next_url)
                if isinstance(handled, OAuthCallback):
                    return handled
                if handled:
                    current_url = str(auth_url or '').strip()
                    continue
            current_url = next_url
            continue
        callback = _callback_from_text(
            text=body_text,
            expected_state=expected_state,
            redirect_uri=redirect_uri,
        )
        if callback is not None:
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_authorize_callback_in_body',
                    'hop': hop,
                    'status': status,
                    'url': _sanitize_url_for_log(response_url),
                    'hasCode': bool(callback.code),
                    'hasError': bool(callback.error),
                    'hasState': bool(callback.state),
                }
            )
            return callback

        terminal_url = str(response_url or current_url or '').strip()
        if callable(phone_handler) and (
            _is_auth_add_phone_url(terminal_url)
            or _is_auth_phone_otp_select_channel_url(terminal_url)
        ):
            handled = await phone_handler(terminal_url)
            if isinstance(handled, OAuthCallback):
                return handled
            if handled:
                current_url = str(auth_url or '').strip()
                continue

        merged = '\n'.join([response_url, body_text]).lower()
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'http_authorize_terminal',
                'hop': hop,
                'status': status,
                'url': _sanitize_url_for_log(response_url),
                'bodySnippet': _compress_debug_text(body_text, limit=400),
            }
        )
        if any(marker in merged for marker in _BLOCK_PAGE_MARKERS):
            raise RuntimeError('http_auth_challenge_blocked: authorize 命中 Cloudflare challenge，纯 HTTP 无法继续。')
        if any(marker in merged for marker in _ERROR_TEXT_MARKERS):
            detail = _extract_auth_error_detail(response_url) or _compress_debug_text(body_text, limit=220)
            raise RuntimeError(f'http_auth_authorize_failed: {detail or "authorize 页面返回错误。"}')
        interactive_markers = (
            'sign in',
            'log in',
            '/log-in',
            '/log-in/password',
            '/api/accounts/login',
            'login_password',
            'email-verification',
            'continue with email',
            'continue with google',
            'continue with microsoft',
            'password',
            '验证码',
            'one-time code',
            'mfa',
            '2-step verification',
        )
        if any(marker in merged for marker in interactive_markers):
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_authorize_interactive',
                    'hop': hop,
                    'status': status,
                    'url': _sanitize_url_for_log(response_url),
                    'bodySnippet': _compress_debug_text(body_text, limit=220),
                }
            )
            if callable(interactive_handler):
                interactive_attempts += 1
                if interactive_attempts > 2:
                    raise RuntimeError('http_auth_login_required: 已执行 HTTP 登录继续链路，但 authorize 仍停留在交互页，未能拿到 callback。')
                handled = await interactive_handler(response_url, body_text)
                if isinstance(handled, OAuthCallback):
                    return handled
                if handled:
                    current_url = str(auth_url or '').strip()
                    continue
            raise RuntimeError('http_auth_login_required: 当前登录态未能直达 authorize，已回落到登录/验证交互页。')
        raise RuntimeError(
            'http_auth_code_missing: authorize 未返回可用 code，'
            f'status={status}，url={_sanitize_url_for_log(response_url) or "unknown"}。'
        )

    raise RuntimeError('http_auth_code_missing: authorize redirect 跳转次数超过上限。')


async def _persist_codex_token_payload(
    *,
    log: Any,
    safe_email: str,
    output_path: str,
    token_resp: dict[str, Any],
    trace_path: str = '',
    expected_workspace_id: str = '',
    bound_phone_numbers: list[str] | None = None,
) -> dict[str, Any]:
    access_token = str(token_resp.get('access_token') or '').strip()
    refresh_token = str(token_resp.get('refresh_token') or '').strip()
    id_token = str(token_resp.get('id_token') or '').strip()
    expires_in = int(token_resp.get('expires_in') or 0)

    plan, account_id = _extract_plan_and_account_id(id_token, access_token)
    normalized_expected_workspace_id = str(expected_workspace_id or '').strip()
    normalized_account_id = str(account_id or '').strip()
    if normalized_expected_workspace_id:
        if not normalized_account_id:
            raise RuntimeError(
                f'workspace_mismatch: token account_id 为空，expected_workspace_id={normalized_expected_workspace_id}'
            )
        if normalized_account_id != normalized_expected_workspace_id:
            raise RuntimeError(
                'workspace_mismatch: '
                f'token account_id={normalized_account_id}, expected_workspace_id={normalized_expected_workspace_id}'
            )
    acct_hint = (account_id[:6] + '…' + account_id[-4:]) if account_id else ''
    plan_type = str(plan or '').strip() or 'unknown'
    account_hint = acct_hint or 'unknown'
    await _emit_log(
        log,
        'info',
        '【Codex OAuth】token 交换成功：'
        f'expires_in={expires_in}s, plan_type={plan_type}, account_id={account_hint}',
    )
    expire_at = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=max(expires_in, 0))
    ).isoformat()

    refresh_token_enc = ''
    if refresh_token and encrypt_text is not None:
        try:
            refresh_token_enc = str(encrypt_text(refresh_token) or '').strip()
        except Exception:
            refresh_token_enc = ''
    clear_plain = str(os.getenv('AIO_CODEX_OAUTH_CLEAR_REFRESH_TOKEN_PLAINTEXT', '') or '').strip().lower() in {
        '1',
        'true',
        'yes',
        'on',
    }
    refresh_token_to_write = '' if (clear_plain and refresh_token_enc) else refresh_token

    payload = {
        'type': 'codex',
        'email': safe_email,
        'account_id': str(account_id or '').strip(),
        'id_token': id_token,
        'access_token': access_token,
        'refresh_token': refresh_token_to_write,
        'refresh_token_enc': refresh_token_enc,
        'expired': expire_at,
        'last_refresh': _iso_now(),
        'chatgpt_plan_type': str(plan or '').strip(),
        'token_exchange': {
            'access_token': access_token,
            'refresh_token': refresh_token_to_write,
            'id_token': id_token,
            'token_type': str(token_resp.get('token_type') or '').strip(),
            'expires_in': int(token_resp.get('expires_in') or 0),
            'scope': str(token_resp.get('scope') or '').strip(),
        },
    }
    normalized_bound_phones: list[str] = []
    for phone in bound_phone_numbers or []:
        value = str(phone or '').strip()
        if value and value not in normalized_bound_phones:
            normalized_bound_phones.append(value)
    if normalized_bound_phones:
        payload['bound_phone'] = normalized_bound_phones[0]
        payload['bound_phone_number'] = normalized_bound_phones[0]
        payload['phone'] = normalized_bound_phones[0]
        payload['phone_number'] = normalized_bound_phones[0]
        payload['bound_phone_numbers'] = normalized_bound_phones

    out_path = Path(output_path).expanduser()
    await _emit_log(log, 'info', f'【Codex OAuth】步骤 7/8：保存认证文件到：{out_path}')
    out_path, mirror_path, mirror_error = await asyncio.to_thread(
        write_codex_auth_json,
        path=out_path,
        payload=payload,
    )
    await _emit_log(log, 'success', f'【Codex OAuth】完成：认证文件已保存：{out_path}')
    if mirror_path is not None and mirror_path != out_path:
        await _emit_log(log, 'info', f'【Codex OAuth】镜像认证文件已同步到：{mirror_path}')
    elif mirror_error:
        await _emit_log(log, 'warn', f'【Codex OAuth】镜像目录同步失败：{mirror_error}')
    if trace_path:
        await _emit_log(log, 'info', f'【Codex OAuth】调试追踪文件：{trace_path}')
    return {
        'success': True,
        'path': str(out_path),
        'plan_type': plan,
        'trace_path': trace_path,
        'bound_phone': normalized_bound_phones[0] if normalized_bound_phones else '',
        'phone_number': normalized_bound_phones[0] if normalized_bound_phones else '',
        'bound_phone_numbers': normalized_bound_phones,
    }


async def run_codex_oauth_http_flow(
    *,
    email: str,
    password: str = '',
    storage_state_path: str,
    output_path: str,
    headless: bool = False,
    log: Any,
    oauth_cfg: OAuthRuntimeConfig,
    auth_url: str,
    pkce: PKCECodes,
    state: str,
    timeout_sec: float,
    trace: _TraceWriter,
    mfa_totp_secret: str = '',
    otp_api_url: str = '',
    use_imap_otp: bool = False,
    otp_timeout_sec: float = 120.0,
    otp_interval_sec: float = 3.0,
    imap_host: str = 'imap.2925.com',
    imap_port: int = 993,
    imap_user: str = '',
    imap_pass: str = '',
    imap_folder: str = 'Inbox',
    imap_latest_n: int = 10,
    imap_auth_type: str = 'password',
    imap_oauth_client_id: str = '',
    imap_oauth_refresh_token: str = '',
    imap_password_fallback: bool = False,
    imap_pop3_fallback: bool = False,
    imap_profiles_json: str = '',
    use_managed_mail_otp: bool = True,
    managed_mail_provider: str = '',
    managed_mail_jwt: str = '',
    managed_mail_api_base: str = '',
    managed_mail_frontend_base: str = '',
    managed_mail_latest_n: int = 20,
    use_domain_mail_otp: bool = True,
    domain_mail_api_base: str = '',
    domain_mail_domain: str = '',
    domain_mail_token: str = '',
    domain_mail_latest_n: int = 20,
    expected_workspace_id: str = '',
    phone_verification: Optional[dict[str, Any]] = None,
    require_phone_bind: bool = False,
) -> dict[str, Any]:
    safe_email = str(email or '').strip()
    activate_http_stage_feature_session(safe_email, 'codex_oauth_http')
    normalized_expected_workspace_id = str(expected_workspace_id or '').strip()
    state_path_text = str(storage_state_path or '').strip()
    state_path = Path(state_path_text).expanduser() if state_path_text else Path()
    if not _http_provider_enabled():
        raise RuntimeError('http_provider_disabled: 未开启 AIO_CODEX_OAUTH_ENABLE_HTTP_PROVIDER。')
    if curl_cffi_requests is None:
        raise RuntimeError('http_provider_bootstrap_failed: 当前环境缺少 curl_cffi，无法启动纯 HTTP provider。')
    inline_signup_test = str(os.environ.get('X9_OAUTH_INLINE_SIGNUP_TEST') or '').strip() == '1'
    if inline_signup_test and ((not str(state_path)) or (not state_path.is_file())):
        initial_storage_state = _build_empty_storage_state_payload()
    elif not str(state_path) or (not state_path.is_file()):
        raise RuntimeError('http_auth_session_bootstrap_failed: 缺少可用 storage_state，无法纯 HTTP 复用登录态。')
    else:
        initial_storage_state = None

    await _emit_log(log, 'info', '【Codex OAuth】步骤 2/8：启动纯 HTTP 会话上下文')
    try:
        from chatgpt_api_health import extract_access_token_from_session_payload, extract_session_summary_from_payload, resolve_proxy_for_url
    except Exception as error:
        raise RuntimeError(f'http_provider_bootstrap_failed: 加载 session 依赖失败：{error}') from error

    resolved_proxy_url = str(resolve_proxy_for_url(AUTH_URL) or '').strip()
    proxy_opt = _build_playwright_proxy_option(resolved_proxy_url)
    resolved_impersonate = _resolve_http_provider_curl_impersonate()
    request_ctx = None
    trace_path = trace.path
    normalized_totp_secret = normalize_totp_secret(str(mfa_totp_secret or '').strip())
    blocked_otp_codes: set[str] = set()
    log_loop = asyncio.get_running_loop()
    pending_phone_candidates: list[Any] = []
    phone_usage_committed = False
    token_exchange_storage_state: dict[str, Any] = {}
    token_exchange_payload: dict[str, Any] = {}

    def _make_threadsafe_log(level: str):
        def _log_from_thread(message: str) -> None:
            try:
                asyncio.run_coroutine_threadsafe(
                    _emit_log(log, level, str(message or '')),
                    log_loop,
                ).result()
            except Exception:
                return

        return _log_from_thread

    managed_mail_log_info = _make_threadsafe_log('info')
    managed_mail_log_warn = _make_threadsafe_log('warn')
    try:
        if initial_storage_state is None:
            initial_storage_state = _load_storage_state_payload(str(state_path))
    except Exception as error:
        raise RuntimeError(f'http_auth_session_bootstrap_failed: storage_state 读取失败：{error}') from error
    workspace_ctx: dict[str, Any] = {
        'workspace_id': '',
        'source': '',
        'session_claims': {},
        'session_workspace_id': '',
        'workspaces': [],
        'selected_workspace': {},
    }
    try:
        request_ctx = await asyncio.to_thread(
            _build_http_provider_request_context,
            storage_state=initial_storage_state,
            proxy_url=resolved_proxy_url,
            impersonate=resolved_impersonate,
        )
        await _emit_log(
            log,
            'info',
            '【Codex OAuth】纯 HTTP 上下文已切换为 curl_cffi Session：'
            f'impersonate={resolved_impersonate or "default"}，proxy={_mask_proxy_url_for_log(resolved_proxy_url)}',
        )

        if inline_signup_test and (not str(storage_state_path or '').strip()):
            await _emit_log(log, 'info', '【Codex OAuth】OAuth 内联注册测试：空会话打开 authorize，将在登录页走 signup。')
        else:
            await _emit_log(log, 'info', '【Codex OAuth】已注入现有 storage_state，准备复用当前登录态推进 OAuth。')

        async def _request_json_with_context_with_retry(
            *,
            url: str,
            headers: Optional[dict[str, str]] = None,
            timeout_ms: int,
            trace_stage: str,
            max_attempts: int = 3,
        ) -> tuple[dict[str, Any], int, str]:
            last_error: Optional[Exception] = None
            total_attempts = max(1, int(max_attempts or 1))
            for attempt in range(1, total_attempts + 1):
                try:
                    return await _request_json_with_context(
                        request_ctx,
                        url=url,
                        headers=headers,
                        timeout_ms=timeout_ms,
                    )
                except Exception as error:
                    last_error = error
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': trace_stage,
                            'attempt': attempt,
                            'maxAttempts': total_attempts,
                            'url': _sanitize_url_for_log(url),
                            'error': _compress_debug_text(str(error), limit=320),
                        }
                    )
                    if attempt >= total_attempts:
                        raise
                    wait_seconds = min(4.0, 1.2 * attempt)
                    await _emit_log(
                        log,
                        'warn',
                        f'【Codex OAuth】HTTP 请求异常，准备重试（stage={trace_stage}, '
                        f'attempt={attempt}/{total_attempts}, wait={wait_seconds:.1f}s）：{error}',
                    )
                    await asyncio.sleep(wait_seconds)
            if last_error is not None:
                raise last_error
            raise RuntimeError(f'http_request_failed: {trace_stage}')

        async def _refresh_session_state(
            *,
            stage_name: str,
            exchange_stage_name: str,
            exchange_claims_stage_name: str,
            log_message_prefix: str,
            enforce_expected_workspace: bool = False,
        ) -> dict[str, Any]:
            nonlocal workspace_ctx
            try:
                session_payload, session_status, session_text = await _request_json_with_context_with_retry(
                    url='https://chatgpt.com/api/auth/session',
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace_stage=f'{stage_name}_request_retry',
                )
            except Exception as error:
                session_payload = {}
                session_status = 0
                session_text = ''
                session_summary = extract_session_summary_from_payload(
                    session_payload,
                    status=session_status,
                    error_text=str(error),
                    updated_at=_iso_now(),
                )
                workspace_ctx = {
                    'workspace_id': '',
                    'source': '',
                    'session_claims': {},
                    'session_workspace_id': '',
                    'workspaces': [],
                    'selected_workspace': {},
                }
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': stage_name,
                        'status': session_status,
                        'accessTokenLen': 0,
                        'selectedWorkspaceId': '',
                        'selectedWorkspaceName': '',
                        'planType': '',
                        'tokenAccountId': '',
                        'tokenPlanType': '',
                        'workspaceId': '',
                        'workspaceSource': '',
                        'error': _compress_debug_text(str(error), limit=220),
                        'bodySnippet': '',
                    }
                )
                await _emit_log(
                    log,
                    'warn',
                    f'【Codex OAuth】{log_message_prefix}失败：auth/session 请求异常，'
                    '将继续按当前登录态推进 OAuth 链路。',
                )
                return {
                    'session_payload': session_payload,
                    'session_status': session_status,
                    'session_text': session_text,
                    'access_token': '',
                    'workspace_ctx': workspace_ctx,
                    'session_summary': session_summary,
                }
            session_summary = extract_session_summary_from_payload(
                session_payload,
                status=session_status,
                error_text='',
                updated_at=_iso_now(),
            )
            access_token = extract_access_token_from_session_payload(session_payload)
            workspace_ctx = _prefer_expected_workspace_context(
                (
                    _choose_http_provider_workspace_context(
                        session_payload=session_payload,
                        session_access_token=access_token,
                    )
                    if access_token
                    else {
                        'workspace_id': '',
                        'source': '',
                        'session_claims': {},
                        'session_workspace_id': '',
                        'workspaces': [],
                        'selected_workspace': {},
                    }
                ),
                normalized_expected_workspace_id,
            )
            session_claims = workspace_ctx.get('session_claims') or {}
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': stage_name,
                    'status': session_status,
                    'accessTokenLen': len(access_token),
                    'selectedWorkspaceId': str(session_summary.get('selectedWorkspaceId') or '').strip(),
                    'selectedWorkspaceName': _compress_debug_text(session_summary.get('selectedWorkspaceName'), limit=120),
                    'planType': str(session_summary.get('accountPlanType') or '').strip(),
                    'tokenAccountId': str(session_claims.get('account_id') or '').strip(),
                    'tokenPlanType': str(session_claims.get('plan_type') or '').strip(),
                    'workspaceId': str(workspace_ctx.get('workspace_id') or '').strip(),
                    'workspaceSource': str(workspace_ctx.get('source') or '').strip(),
                    'bodySnippet': _compress_debug_text(session_text, limit=220),
                }
            )
            if session_status != 200:
                await _emit_log(log, 'warn', f'【Codex OAuth】{log_message_prefix}失败：auth/session 返回 HTTP {session_status or 0}。')
                return {
                    'session_payload': session_payload,
                    'session_status': session_status,
                    'session_text': session_text,
                    'access_token': access_token,
                    'workspace_ctx': workspace_ctx,
                    'session_summary': session_summary,
                }
            if not access_token:
                await _emit_log(log, 'warn', f'【Codex OAuth】{log_message_prefix}未拿到 accessToken，将继续尝试 authorize / 登录链路。')
                return {
                    'session_payload': session_payload,
                    'session_status': session_status,
                    'session_text': session_text,
                    'access_token': access_token,
                    'workspace_ctx': workspace_ctx,
                    'session_summary': session_summary,
                }

            await _emit_log(
                log,
                'info',
                f'【Codex OAuth】{log_message_prefix}：'
                f'plan_type={str(session_summary.get("accountPlanType") or "").strip() or "unknown"}，'
                f'selected_workspace={str(session_summary.get("selectedWorkspaceName") or "").strip() or "unknown"}',
            )
            workspace_id = str(workspace_ctx.get('workspace_id') or '').strip()
            workspace_source = str(workspace_ctx.get('source') or '').strip()
            if workspace_id:
                exchange_url = (
                    'https://chatgpt.com/api/auth/session'
                    f'?exchange_workspace_token=true&workspace_id={urllib.parse.quote(workspace_id, safe="")}'
                    '&reason=setCurrentAccount'
                )
                exchange_payload, exchange_status, exchange_text = await _request_json_with_context(
                    request_ctx,
                    url=exchange_url,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                )
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': exchange_stage_name,
                        'workspaceId': workspace_id,
                        'workspaceSource': workspace_source,
                        'status': exchange_status,
                        'tokenAccountIdBefore': str(session_claims.get('account_id') or '').strip(),
                        'bodySnippet': _compress_debug_text(exchange_text, limit=220),
                    }
                )
                exchange_token = extract_access_token_from_session_payload(exchange_payload)
                exchange_claims = _extract_access_token_workspace_claims(exchange_token)
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': exchange_claims_stage_name,
                        'workspaceId': workspace_id,
                        'workspaceSource': workspace_source,
                        'tokenAccountIdAfter': str(exchange_claims.get('account_id') or '').strip(),
                        'tokenPlanTypeAfter': str(exchange_claims.get('plan_type') or '').strip(),
                        'tokenJtiAfter': str(exchange_claims.get('jti') or '').strip(),
                    }
                )
                if exchange_status == 200 and exchange_token:
                    token_account_after = str(exchange_claims.get('account_id') or '').strip()
                    if (
                        enforce_expected_workspace
                        and normalized_expected_workspace_id
                        and token_account_after
                        and token_account_after != normalized_expected_workspace_id
                    ):
                        raise RuntimeError(
                            'workspace_mismatch: '
                            f'token account_id={token_account_after}, expected_workspace_id={normalized_expected_workspace_id}'
                        )
                    if token_account_after and token_account_after != workspace_id:
                        await _emit_log(
                            log,
                            'warn',
                            '【Codex OAuth】workspace exchange 已返回 accessToken，'
                            f'但 token 仍绑定到 {token_account_after}，目标 workspace={workspace_id}。',
                        )
                    else:
                        await _emit_log(log, 'info', f'【Codex OAuth】已通过纯 HTTP 固定当前工作空间：{workspace_id}')
                else:
                    await _emit_log(
                        log,
                        'warn',
                        '【Codex OAuth】workspace exchange 未拿到新 accessToken，'
                        '将继续沿用当前 session 尝试 authorize。',
                    )
            else:
                await _emit_log(log, 'warn', '【Codex OAuth】当前 session 未解析到明确 workspace_id，将沿用现有会话继续。')
            return {
                'session_payload': session_payload,
                'session_status': session_status,
                'session_text': session_text,
                'access_token': access_token,
                'workspace_ctx': workspace_ctx,
                'session_summary': session_summary,
            }

        async def _open_continue_url(*, stage_name: str, continue_url: str) -> tuple[str, str]:
            target_url = str(continue_url or '').strip()
            if not target_url:
                return '', ''
            _payload, status, text, response_url, response_headers = await _request_with_context(
                request_ctx,
                method='GET',
                url=target_url,
                headers=_build_http_html_headers(
                    impersonate=_resolve_request_ctx_impersonate(request_ctx),
                ),
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                max_redirects=0,
            )
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': stage_name,
                    'status': status,
                    'url': _sanitize_url_for_log(response_url),
                    'location': _sanitize_url_for_log(str(response_headers.get('location') or '').strip()),
                    'bodySnippet': _compress_debug_text(text, limit=320),
                }
            )
            merged = '\n'.join([response_url, text]).lower()
            if any(marker in merged for marker in _BLOCK_PAGE_MARKERS):
                raise RuntimeError('http_auth_challenge_blocked: HTTP 登录继续链路命中 Cloudflare challenge，纯 HTTP 无法继续。')
            if any(marker in merged for marker in _ERROR_TEXT_MARKERS):
                detail = _extract_auth_error_detail(response_url) or _compress_debug_text(text, limit=220)
                raise RuntimeError(f'http_auth_authorize_failed: {detail or "登录继续页面返回错误。"}')
            return str(response_url or target_url).strip(), str(text or '')

        def _mask_phone_for_log(phone: str) -> str:
            value = str(phone or '').strip()
            if len(value) <= 6:
                return '*' * len(value)
            return f'{value[:3]}***{value[-3:]}'

        def _resolve_add_phone_local_usage_mode(config: dict[str, Any]) -> str:
            for scope in (
                config,
                config.get('registration_flow') if isinstance(config.get('registration_flow'), dict) else {},
                config.get('http_auth') if isinstance(config.get('http_auth'), dict) else {},
                config.get('add_phone') if isinstance(config.get('add_phone'), dict) else {},
            ):
                if not isinstance(scope, dict):
                    continue
                for key in ('add_phone_local_phone_usage_mode', 'local_phone_usage_mode'):
                    value = str(scope.get(key) or '').strip()
                    if value:
                        return value
            return 'single_use'

        async def _complete_http_add_phone_attempt(
            *,
            continue_url: str,
            source_stage: str,
        ) -> Optional[OAuthCallback | bool]:
            add_phone_url = str(continue_url or '').strip()
            is_add_phone = _is_auth_add_phone_url(add_phone_url)
            is_phone_select_channel = _is_auth_phone_otp_select_channel_url(add_phone_url)
            if (not is_add_phone) and (not is_phone_select_channel):
                return None

            explicit_phone_config = dict(phone_verification or {})
            cfg = (
                explicit_phone_config
                if bool(require_phone_bind)
                else (explicit_phone_config or _load_codex_oauth_config_file())
            )
            usage_mode = _resolve_add_phone_local_usage_mode(cfg)
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': f'{source_stage}_phone_verification_detected',
                    'continueUrl': _sanitize_url_for_log(add_phone_url),
                    'localPhoneUsageMode': usage_mode,
                    'kind': 'add_phone' if is_add_phone else 'select_channel',
                }
            )
            await _emit_log(log, 'info', 'Codex OAuth HTTP phone verification detected; starting SMS verification.')

            candidate: Any = None
            candidate_blacklisted = False
            try:
                if is_add_phone:
                    candidate = await asyncio.to_thread(
                        acquire_http_phone_candidate,
                        cfg,
                        log_fn=managed_mail_log_info,
                        local_phone_usage_mode=usage_mode,
                        owner_key=safe_email,
                    )
                else:
                    candidate = await asyncio.to_thread(
                        acquire_pending_http_phone_candidate,
                        cfg,
                        log_fn=managed_mail_log_info,
                        local_phone_usage_mode=usage_mode,
                        owner_key=safe_email,
                    )
            except Exception as error:
                raise RuntimeError(f'http_auth_add_phone_failed: acquire phone failed: {error}') from error
            if candidate is None:
                raise RuntimeError(
                    'http_auth_add_phone_failed: phone-otp/select-channel requires an existing pending local phone '
                    'for this account, but none was found.'
                )

            phone_number = str(getattr(candidate, 'phone', '') or '').strip()
            if not phone_number:
                raise RuntimeError('http_auth_add_phone_failed: phone provider returned an empty phone number.')
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': f'{source_stage}_add_phone_phone_selected',
                    'phoneMasked': _mask_phone_for_log(phone_number),
                    'source': str(getattr(candidate, 'source', '') or ''),
                }
            )

            async def _raise_phone_send_failure(detail: str) -> None:
                nonlocal candidate_blacklisted
                send_failure_temporary = _is_send_failure_temporary(detail)
                try:
                    if send_failure_temporary:
                        await asyncio.to_thread(cooldown_http_phone, candidate)
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': f'{source_stage}_add_phone_cooldown_after_send_failure',
                                'phoneMasked': _mask_phone_for_log(phone_number),
                                'detail': detail,
                            }
                        )
                    else:
                        await asyncio.to_thread(blacklist_http_phone, candidate)
                        candidate_blacklisted = True
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': f'{source_stage}_add_phone_blacklisted_after_send_failure',
                                'phoneMasked': _mask_phone_for_log(phone_number),
                                'detail': detail,
                            }
                        )
                except Exception as mark_error:
                    await _emit_log(log, 'warn', f'Codex OAuth add-phone mark failed after send rejection: {mark_error}')
                raise RuntimeError(f'http_auth_add_phone_failed: phone verification send failed: {detail}')

            async def _reject_forced_whatsapp() -> None:
                nonlocal candidate_blacklisted
                try:
                    await asyncio.to_thread(blacklist_http_phone, candidate)
                    candidate_blacklisted = True
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': f'{source_stage}_add_phone_blacklisted_after_whatsapp_send',
                            'phoneMasked': _mask_phone_for_log(phone_number),
                        }
                    )
                except Exception as mark_error:
                    await _emit_log(log, 'warn', f'Codex OAuth add-phone blacklist failed after WhatsApp send response: {mark_error}')
                raise RuntimeError('http_auth_add_phone_failed: add-phone switched to WhatsApp verification.')

            validate_payload: Any = {}
            validate_continue_url = ''
            resolved_validate_url = ''
            resolved_validate_text = ''
            try:
                if is_add_phone:
                    send_res = await _request_auth_api_with_context(
                        request_ctx,
                        stage=f'{source_stage}_add_phone_send',
                        path='/add-phone/send',
                        method='POST',
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        trace=trace,
                        referer_url=add_phone_url or 'https://auth.openai.com/add-phone',
                        json_body={'phone_number': phone_number},
                        trace_json_body={'phone_number': '***'},
                    )
                else:
                    selection_url, selection_text = await _open_continue_url(
                        stage_name=f'{source_stage}_phone_otp_select_channel_page',
                        continue_url=add_phone_url or 'https://auth.openai.com/phone-otp/select-channel',
                    )
                    selection_text_lower = str(selection_text or '').lower()
                    selection_options: list[str] = []
                    if re.search(r'\bsms\b', selection_text_lower):
                        selection_options.append('sms')
                    if 'whatsapp' in selection_text_lower or 'whats app' in selection_text_lower:
                        selection_options.append('whatsapp')
                    selection_channel = _choose_auth_phone_channel(
                        selection_options,
                        allow_whatsapp=is_manual_http_phone(candidate),
                    )
                    if not selection_channel:
                        await _reject_forced_whatsapp()
                    send_res = await _request_auth_api_with_context(
                        request_ctx,
                        stage=f'{source_stage}_phone_otp_select_{selection_channel}',
                        path='/phone-otp/select-channel',
                        method='POST',
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        trace=trace,
                        referer_url=selection_url or add_phone_url or 'https://auth.openai.com/phone-otp/select-channel',
                        json_body={'channel': selection_channel},
                    )
                send_status = int(send_res.get('status') or 0)
                send_text = str(send_res.get('text') or '')
                send_payload = send_res.get('payload')
                send_continue_url = _extract_continue_url(send_payload) or add_phone_url
                if send_status not in {200, 201, 202, 204}:
                    err_code, err_msg = _extract_error(send_payload, send_text)
                    detail = str(err_msg or err_code or f'HTTP {send_status}')
                    await _raise_phone_send_failure(detail)

                resolved_send_url = ''
                resolved_send_text = ''
                if send_continue_url:
                    resolved_send_url, resolved_send_text = await _open_continue_url(
                        stage_name=f'{source_stage}_add_phone_send_continue',
                        continue_url=send_continue_url,
                    )
                if is_add_phone and _auth_phone_channel_selection_required(
                    send_payload,
                    url=resolved_send_url or send_continue_url,
                    text=resolved_send_text,
                ):
                    channel_options = _auth_phone_channel_options(send_payload)
                    channel_page_text = '\n'.join((str(resolved_send_text or ''), str(send_text or ''))).lower()
                    if not channel_options:
                        if re.search(r'\bsms\b', channel_page_text):
                            channel_options.append('sms')
                        if 'whatsapp' in channel_page_text or 'whats app' in channel_page_text:
                            channel_options.append('whatsapp')
                    selection_channel = _choose_auth_phone_channel(
                        channel_options,
                        allow_whatsapp=is_manual_http_phone(candidate),
                    )
                    if not selection_channel:
                        await _reject_forced_whatsapp()
                    select_res = await _request_auth_api_with_context(
                        request_ctx,
                        stage=f'{source_stage}_phone_otp_select_{selection_channel}',
                        path='/phone-otp/select-channel',
                        method='POST',
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        trace=trace,
                        referer_url=resolved_send_url or send_continue_url or 'https://auth.openai.com/phone-otp/select-channel',
                        json_body={'channel': selection_channel},
                    )
                    select_status = int(select_res.get('status') or 0)
                    select_text = str(select_res.get('text') or '')
                    select_payload = select_res.get('payload')
                    if select_status not in {200, 201, 202, 204}:
                        err_code, err_msg = _extract_error(select_payload, select_text)
                        await _raise_phone_send_failure(str(err_msg or err_code or f'HTTP {select_status}'))
                    send_payload = select_payload
                    send_text = select_text
                    send_continue_url = _extract_continue_url(select_payload) or send_continue_url
                    resolved_send_url = ''
                    resolved_send_text = ''
                    if send_continue_url:
                        resolved_send_url, resolved_send_text = await _open_continue_url(
                            stage_name=f'{source_stage}_phone_otp_select_{selection_channel}_continue',
                            continue_url=send_continue_url,
                        )

                if (
                    _auth_phone_forced_whatsapp(
                        send_payload,
                        text='\n'.join((send_text, resolved_send_text)),
                        url=resolved_send_url or send_continue_url,
                    )
                    and not is_manual_http_phone(candidate)
                ):
                    await _reject_forced_whatsapp()

                code_value = await asyncio.to_thread(
                    wait_for_http_phone_code,
                    candidate,
                    timeout=int(max(30.0, float(otp_timeout_sec or 120.0))),
                )
                if not code_value:
                    raise RuntimeError('http_auth_add_phone_failed: phone verification code is empty.')

                validate_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=f'{source_stage}_add_phone_validate',
                    path='/phone-otp/validate',
                    method='POST',
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=send_continue_url or add_phone_url or 'https://auth.openai.com/phone-verification',
                    json_body={'code': str(code_value)},
                    trace_json_body={'code': '***'},
                )
                validate_status = int(validate_res.get('status') or 0)
                validate_text = str(validate_res.get('text') or '')
                validate_payload = validate_res.get('payload')
                validate_continue_url = _extract_continue_url(validate_payload)
                err_code, err_msg = _extract_error(
                    validate_payload if isinstance(validate_payload, dict) else None,
                    validate_text,
                )
                if validate_status not in {200, 201, 202, 204} or err_code or err_msg:
                    detail = str(err_msg or err_code or f'HTTP {validate_status}')
                    if _is_validate_recently_used(detail):
                        # 号已收到验证码，仅 OpenAI 认为该号"最近用过"处于冷却期 ——
                        # 号本身没坏，冷却到期可再用，不应永久拉黑。
                        try:
                            await asyncio.to_thread(cooldown_http_phone, candidate)
                            trace.write(
                                {
                                    'ts': _iso_now(),
                                    'stage': f'{source_stage}_add_phone_cooldown_after_validate_recently_used',
                                    'phoneMasked': _mask_phone_for_log(phone_number),
                                    'detail': detail,
                                }
                            )
                        except Exception as cooldown_error:
                            await _emit_log(
                                log,
                                'warn',
                                f'Codex OAuth add-phone cooldown failed after validate recently used: {cooldown_error}',
                            )
                    raise RuntimeError(f'http_auth_add_phone_failed: phone-otp/validate failed: {detail}')

                resolved_validate_url = ''
                resolved_validate_text = ''
                if validate_continue_url:
                    resolved_validate_url, resolved_validate_text = await _open_continue_url(
                        stage_name=f'{source_stage}_add_phone_validate_continue',
                        continue_url=validate_continue_url,
                    )
                bind_progress_url = str(resolved_validate_url or validate_continue_url or '').strip()
                bind_url_still_phone = _auth_phone_step_still_active(
                    {},
                    url=bind_progress_url,
                    text=resolved_validate_text or validate_text,
                )
                bind_payload_still_phone = _auth_phone_step_still_active(
                    validate_payload,
                    url='',
                    text=validate_text,
                )
                bind_accepted = _auth_phone_bind_progress_url(bind_progress_url) or (
                    bool(bind_progress_url)
                    and (not bind_url_still_phone)
                    and (not bind_payload_still_phone)
                )
                if bool(require_phone_bind):
                    if not bind_accepted:
                        raise RuntimeError(
                            'http_auth_add_phone_failed: phone-otp/validate did not leave the phone verification step'
                        )
                    await asyncio.to_thread(mark_http_phone_completed, candidate)
                    candidate_blacklisted = True
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': f'{source_stage}_add_phone_validated',
                            'phoneMasked': _mask_phone_for_log(phone_number),
                            'continueUrl': _sanitize_url_for_log(bind_progress_url),
                        }
                    )
                    raise _PhoneBindCompleted(phone_number)

                if not bind_accepted:
                    raise RuntimeError(
                        'http_auth_add_phone_failed: phone-otp/validate did not leave the phone verification step'
                    )

                pending_phone_candidates.append(candidate)
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': f'{source_stage}_add_phone_validated_pending_credential',
                        'continueUrl': _sanitize_url_for_log(bind_progress_url),
                    }
                )
            except Exception as error:
                if isinstance(error, _PhoneBindCompleted):
                    raise
                if candidate is not None and is_manual_http_phone(candidate):
                    if not _is_retryable_manual_phone_error(error):
                        raise
                    retry_message = str(error or "手机号验证失败，请更换号码后重试。")
                    if "manual phone number was replaced" in retry_message.lower():
                        retry_message = "已收到新手机号，正在重新发送验证码。"
                    await asyncio.to_thread(report_http_phone_failure, candidate, retry_message)
                    await _emit_log(log, 'warn', f'手动手机号本次尝试未完成：{retry_message}')
                    raise _ManualPhoneRetryRequested(retry_message) from error
                if candidate is not None and is_phone_provider_unusable(error):
                    try:
                        await asyncio.to_thread(blacklist_http_phone, candidate)
                        candidate_blacklisted = True
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': f'{source_stage}_add_phone_blacklisted_after_unusable_number',
                                'phoneMasked': _mask_phone_for_log(str(getattr(candidate, 'phone', '') or '')),
                                'detail': _compress_debug_text(str(error), limit=220),
                            }
                        )
                    except Exception as blacklist_error:
                        await _emit_log(
                            log,
                            'warn',
                            f'Codex OAuth add-phone blacklist failed after unusable number: {blacklist_error}',
                        )
                if candidate is not None and (candidate not in pending_phone_candidates) and (not candidate_blacklisted):
                    try:
                        await asyncio.to_thread(dispose_http_phone_after_failure, candidate)
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': f'{source_stage}_add_phone_disposed_after_failure',
                                'phoneMasked': _mask_phone_for_log(str(getattr(candidate, 'phone', '') or '')),
                            }
                        )
                    except Exception as cancel_error:
                        await _emit_log(log, 'warn', f'Codex OAuth add-phone dispose failed after flow error: {cancel_error}')
                raise

            progress_url = str(resolved_validate_url or validate_continue_url or '').strip()
            callback = _callback_from_url(
                url=progress_url,
                expected_state=state,
                redirect_uri=oauth_cfg.redirect_uri,
            )
            if callback is not None and (callback.code or callback.error or callback.state):
                return callback
            consent_continue_url = ''
            if _is_codex_consent_step(validate_payload):
                consent_continue_url = str(_extract_continue_url(validate_payload) or '').strip()
            if (not consent_continue_url) and _is_codex_consent_url(progress_url):
                consent_continue_url = progress_url
            if consent_continue_url:
                return await _complete_http_codex_consent(consent_url=consent_continue_url)
            if validate_continue_url and not resolved_validate_url:
                await _open_continue_url(
                    stage_name=f'{source_stage}_add_phone_validate_continue',
                    continue_url=validate_continue_url,
                )
            return True

        async def _complete_http_add_phone_if_required(
            *,
            continue_url: str,
            source_stage: str,
        ) -> Optional[OAuthCallback | bool]:
            retry_count = 0
            while True:
                attempt_stage = source_stage if retry_count == 0 else f'{source_stage}_manual_retry_{retry_count}'
                attempt_continue_url = (
                    continue_url
                    if retry_count == 0
                    else 'https://auth.openai.com/add-phone'
                )
                try:
                    return await _complete_http_add_phone_attempt(
                        continue_url=attempt_continue_url,
                        source_stage=attempt_stage,
                    )
                except _ManualPhoneRetryRequested:
                    retry_count += 1

        async def _complete_http_codex_consent_via_browser(*, consent_url: str) -> OAuthCallback:
            target_url = str(consent_url or '').strip()
            if not _is_codex_consent_url(target_url):
                raise RuntimeError('http_auth_consent_failed: 登录继续链路未提供有效的 Codex consent URL。')
            await _emit_log(log, 'info', '【Codex OAuth】HTTP 登录链路进入 Codex 授权确认页，准备复用浏览器完成 consent。')
            consent_dir = (_repo_root() / 'tmp' / 'codex_http_consent').resolve()
            consent_dir.mkdir(parents=True, exist_ok=True)
            state_filename = (
                f"http_consent_{_safe_filename_slug(safe_email or 'user')}_"
                f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
            )
            state_path_tmp = consent_dir / state_filename
            try:
                try:
                    await request_ctx.storage_state(path=str(state_path_tmp))
                except TypeError:
                    state_payload = await request_ctx.storage_state()
                    state_path_tmp.write_text(
                        json.dumps(state_payload, ensure_ascii=False, indent=2),
                        encoding='utf-8',
                    )
            except Exception as error:
                raise RuntimeError(f'http_auth_consent_failed: 导出当前 HTTP 会话 storage_state 失败：{error}') from error

            stop_event = threading.Event()
            browser_timeout_sec = max(20.0, min(float(timeout_sec), 90.0))
            browser_res: dict[str, Any] = {}
            try:
                browser_res = await asyncio.to_thread(
                    _run_codex_browser_flow_sync,
                    auth_url=target_url,
                    redirect_uri=oauth_cfg.redirect_uri,
                    expected_state=state,
                    email=safe_email,
                    password=str(password or ''),
                    storage_state_path=str(state_path_tmp),
                    headless=bool(headless),
                    log=log,
                    loop=asyncio.get_running_loop(),
                    stop_event=stop_event,
                    callback_url_hints=oauth_cfg.callback_url_hints,
                    timeout_sec=browser_timeout_sec,
                    otp_timeout_sec=float(otp_timeout_sec),
                    otp_interval_sec=float(otp_interval_sec),
                    mfa_totp_secret=str(mfa_totp_secret or '').strip(),
                    use_imap_otp=bool(use_imap_otp),
                    imap_host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
                    imap_port=int(imap_port or 993),
                    imap_user=str(imap_user or '').strip(),
                    imap_pass=str(imap_pass or ''),
                    imap_folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
                    imap_latest_n=int(imap_latest_n or 10),
                    trace=trace,
                    reuse_profile_state=True,
                    hydrate_storage_state=True,
                )
            finally:
                stop_event.set()
                try:
                    state_path_tmp.unlink(missing_ok=True)
                except Exception:
                    pass

            callback = browser_res.get('callback')
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_auth_consent_browser_result',
                    'consentUrl': _sanitize_url_for_log(target_url),
                    'success': bool(browser_res.get('success')),
                    'hasCallback': isinstance(callback, OAuthCallback),
                    'hasCode': bool(getattr(callback, 'code', '')),
                    'error': _compress_debug_text(browser_res.get('error'), limit=220),
                }
            )
            if browser_res.get('success') and isinstance(callback, OAuthCallback):
                return callback
            raise RuntimeError(
                'http_auth_consent_failed: 浏览器 consent 确认未完成，'
                f'{str(browser_res.get("error") or "unknown").strip() or "unknown"}'
            )

        async def _complete_http_codex_consent(*, consent_url: str) -> OAuthCallback:
            nonlocal workspace_ctx, token_exchange_storage_state, token_exchange_payload
            workspace_ctx = await _resolve_http_provider_workspace_context_for_consent(
                request_ctx=request_ctx,
                workspace_ctx=workspace_ctx,
                consent_url=consent_url,
                timeout_sec=float(timeout_sec),
                trace=trace,
                log=log,
                expected_workspace_id=normalized_expected_workspace_id,
            )
            workspace_ctx = _prefer_expected_workspace_context(workspace_ctx, normalized_expected_workspace_id)
            callback_result = await _complete_http_codex_consent_via_http(
                request_ctx=request_ctx,
                auth_url=auth_url,
                consent_url=consent_url,
                redirect_uri=oauth_cfg.redirect_uri,
                expected_state=state,
                pkce=pkce,
                client_id=oauth_cfg.client_id,
                workspace_ctx=workspace_ctx,
                timeout_sec=float(timeout_sec),
                trace=trace,
                log=log,
                proxy_url=resolved_proxy_url,
            )
            callback = callback_result
            if isinstance(callback_result, dict):
                maybe_state = callback_result.get('storage_state')
                if isinstance(maybe_state, dict):
                    token_exchange_storage_state = maybe_state
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_auth_token_exchange_state_captured',
                            'cookieCount': len(maybe_state.get('cookies') or []),
                        }
                    )
                token_result = callback_result.get('token_result')
                if isinstance(token_result, dict):
                    token_payload = token_result.get('payload')
                    token_status = int(token_result.get('status') or 0)
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_token_exchange_same_session',
                            'status': token_status,
                            'responseUrl': _sanitize_url_for_log(str(token_result.get('response_url') or '').strip()),
                            'responseSummary': _summarize_oauth_token_response_for_trace(
                                payload=token_payload if isinstance(token_payload, dict) else {},
                                text=str(token_result.get('text') or token_result.get('error') or ''),
                            ),
                        }
                    )
                    if 200 <= token_status < 300 and isinstance(token_payload, dict) and str(token_payload.get('access_token') or '').strip():
                        token_exchange_payload = token_payload
                callback = callback_result.get('callback')
            if isinstance(callback, OAuthCallback):
                return callback
            raise RuntimeError('http_auth_consent_failed: curl_cffi 未能完成 workspace/select 到 callback 的纯 HTTP 闭环。')

        async def _submit_http_mfa_challenge_if_required(
            *,
            payload: Any,
            continue_url: str = '',
        ) -> Optional[OAuthCallback | bool]:
            page_obj = payload.get('page') if isinstance(payload, dict) and isinstance(payload.get('page'), dict) else {}
            if str(page_obj.get('type') or '').strip().lower() != 'mfa_challenge':
                return None
            page_payload = page_obj.get('payload') if isinstance(page_obj.get('payload'), dict) else {}
            factors = page_payload.get('factors') if isinstance(page_payload.get('factors'), list) else []
            totp_factor = next(
                (
                    item
                    for item in factors
                    if isinstance(item, dict) and str(item.get('factor_type') or '').strip().lower() == 'totp'
                ),
                None,
            )
            if not normalized_totp_secret or not isinstance(totp_factor, dict):
                raise RuntimeError('http_auth_mfa_secret_missing: 账号已开启 2FA，但本地没有可用的 TOTP 密钥。')
            factor_id = str(totp_factor.get('id') or '').strip()
            if not factor_id:
                raise RuntimeError('http_auth_mfa_failed: 平台返回的 TOTP 因子无效。')

            referer_url = str(
                continue_url or _extract_continue_url(payload) or 'https://auth.openai.com/mfa-challenge'
            ).strip()
            submitted_codes: set[str] = set()
            last_error = ''
            for attempt in range(1, 3):
                issue_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=f'http_auth_mfa_issue_totp_{attempt}',
                    path='/mfa/issue_challenge',
                    method='POST',
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=referer_url,
                    json_body={
                        'id': factor_id,
                        'type': 'totp',
                        'force_fresh_challenge': bool(attempt > 1),
                    },
                )
                issue_status = int(issue_res.get('status') or 0)
                if issue_status not in {200, 201, 202, 204}:
                    err_code, err_msg = _extract_error(issue_res.get('payload'), str(issue_res.get('text') or ''))
                    raise RuntimeError(
                        f'http_auth_mfa_failed: TOTP 挑战创建失败：{err_code or err_msg or ("HTTP " + str(issue_status))}'
                    )

                remaining_seconds = totp_seconds_remaining()
                if remaining_seconds <= 3:
                    await asyncio.sleep(float(remaining_seconds + 1))
                    remaining_seconds = totp_seconds_remaining()
                code_value = generate_totp_code(normalized_totp_secret)
                if code_value in submitted_codes:
                    await asyncio.sleep(float(max(1, remaining_seconds + 1)))
                    code_value = generate_totp_code(normalized_totp_secret)
                submitted_codes.add(code_value)
                await _emit_log(
                    log,
                    'info',
                    f'【Codex OAuth】提交已保存的 TOTP（attempt={attempt}/2）。',
                )
                verify_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=f'http_auth_mfa_verify_totp_{attempt}',
                    path='/mfa/verify',
                    method='POST',
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=referer_url,
                    json_body={'id': factor_id, 'type': 'totp', 'code': str(code_value)},
                    trace_json_body={'id': factor_id, 'type': 'totp', 'code': '***'},
                )
                verify_status = int(verify_res.get('status') or 0)
                verify_text = str(verify_res.get('text') or '')
                verify_payload = verify_res.get('payload')
                next_url = str(_extract_continue_url(verify_payload) or '').strip()
                if verify_status in {200, 201, 202, 204}:
                    callback = _callback_from_url(
                        url=next_url,
                        expected_state=state,
                        redirect_uri=oauth_cfg.redirect_uri,
                    )
                    if callback is not None and (callback.code or callback.error or callback.state):
                        return callback
                    add_phone_callback = await _complete_http_add_phone_if_required(
                        continue_url=next_url,
                        source_stage=f'http_auth_mfa_verify_totp_{attempt}',
                    )
                    if add_phone_callback is not None:
                        return add_phone_callback
                    if next_url:
                        await _open_continue_url(
                            stage_name=f'http_auth_mfa_verify_totp_continue_{attempt}',
                            continue_url=next_url,
                        )
                    consent_url = ''
                    if _is_codex_consent_step(verify_payload):
                        consent_url = str(_extract_continue_url(verify_payload) or '').strip()
                    if (not consent_url) and _is_codex_consent_url(next_url):
                        consent_url = next_url
                    if consent_url:
                        return await _complete_http_codex_consent(consent_url=consent_url)
                    return True

                err_code, err_msg = _extract_error(verify_payload, verify_text)
                last_error = str(err_code or err_msg or f'HTTP {verify_status}')
                low = f'{err_code}\n{err_msg}\n{verify_text}'.lower()
                if verify_status == 429 or any(
                    marker in low
                    for marker in ('max_check_attempts', 'too many tries', 'too many attempts', 'rate limit')
                ):
                    raise RuntimeError('http_auth_mfa_cooldown: TOTP 尝试次数已达上限，请等待远端冷却后再试。')
                if verify_status == 401 or any(marker in low for marker in _OTP_INVALID_MARKERS):
                    continue
                break
            raise RuntimeError(f'http_auth_mfa_failed: TOTP 验证失败：{last_error or "unknown"}')

        async def _submit_http_otp_if_required(
            *,
            payload: Any,
            preferred_send_path: str = '',
            allow_totp: bool = False,
        ) -> Optional[OAuthCallback | bool]:
            if not _is_email_otp_verification_step(payload):
                return None
            await _emit_log(log, 'info', '【Codex OAuth】HTTP 登录链路进入 OTP/TOTP 验证，开始自动提交验证码。')
            if normalized_totp_secret and allow_totp:
                last_error = ''
                submitted_codes: set[str] = set()
                for attempt in range(1, 3):
                    try:
                        remaining_seconds = totp_seconds_remaining()
                        if remaining_seconds <= 3:
                            await asyncio.sleep(float(remaining_seconds + 1))
                            remaining_seconds = totp_seconds_remaining()
                        code_value = generate_totp_code(normalized_totp_secret)
                    except Exception as error:
                        raise RuntimeError(f'http_auth_otp_failed: 生成 TOTP 验证码失败：{error}') from error
                    if code_value in submitted_codes:
                        await asyncio.sleep(float(max(1, remaining_seconds + 1)))
                        remaining_seconds = totp_seconds_remaining()
                        code_value = generate_totp_code(normalized_totp_secret)
                    submitted_codes.add(code_value)
                    await _emit_log(
                        log,
                        'info',
                        f'【Codex OAuth】检测到密码后的 TOTP 挑战，准备提交验证码（attempt={attempt}/2, 剩余 {remaining_seconds}s）。',
                    )
                    submit_res = await _request_auth_api_with_context(
                        request_ctx,
                        stage=f'http_auth_otp_submit_totp_{attempt}',
                        path='/email-otp/validate',
                        method='POST',
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        trace=trace,
                        referer_url=_extract_continue_url(payload) or 'https://auth.openai.com/email-verification',
                        json_body={'code': str(code_value)},
                        trace_json_body={'code': '***'},
                    )
                    submit_status = int(submit_res.get('status') or 0)
                    submit_text = str(submit_res.get('text') or '')
                    submit_payload = submit_res.get('payload')
                    submit_continue_url = _extract_continue_url(submit_payload)
                    submit_callback = _callback_from_url(
                        url=submit_continue_url,
                        expected_state=state,
                        redirect_uri=oauth_cfg.redirect_uri,
                    )
                    if submit_callback is not None and (submit_callback.code or submit_callback.error or submit_callback.state):
                        return submit_callback
                    add_phone_callback = await _complete_http_add_phone_if_required(
                        continue_url=submit_continue_url,
                        source_stage=f'http_auth_otp_submit_totp_{attempt}',
                    )
                    if add_phone_callback is not None:
                        return add_phone_callback
                    if submit_continue_url:
                        await _open_continue_url(
                            stage_name=f'http_auth_otp_submit_totp_continue_{attempt}',
                            continue_url=submit_continue_url,
                        )
                    consent_continue_url = ''
                    if _is_codex_consent_step(submit_payload):
                        consent_continue_url = str(_extract_continue_url(submit_payload) or '').strip()
                    if (not consent_continue_url) and _is_codex_consent_url(submit_continue_url):
                        consent_continue_url = str(submit_continue_url or '').strip()
                    if consent_continue_url:
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': 'http_auth_consent_detected_after_totp',
                                'continueUrl': _sanitize_url_for_log(consent_continue_url),
                                'hints': _collect_auth_step_hints(submit_payload),
                            }
                        )
                        return await _complete_http_codex_consent(consent_url=consent_continue_url)
                    if submit_status in {200, 201, 202, 204}:
                        return None
                    err_code, err_msg = _extract_error(submit_payload, submit_text)
                    last_error = str(err_code or err_msg or f'HTTP {submit_status}')
                    low = f'{err_code}\n{err_msg}\n{submit_text}'.lower()
                    if submit_status == 429 or any(
                        marker in low
                        for marker in ('max_check_attempts', 'too many tries', 'too many attempts', 'rate limit')
                    ):
                        raise RuntimeError(
                            'http_auth_totp_cooldown: TOTP 尝试次数已达上限，请等待远端冷却后再试。'
                        )
                    if (submit_status == 401) or any(marker in low for marker in _OTP_INVALID_MARKERS):
                        if attempt >= 2:
                            break
                        wait_seconds = float(max(1, remaining_seconds + 1))
                        await _emit_log(
                            log,
                            'warn',
                            f'【Codex OAuth】TOTP 验证码未通过，将等待下一组验证码（约 {wait_seconds:.0f}s）。',
                        )
                        await asyncio.sleep(wait_seconds)
                        continue
                    break
                raise RuntimeError(f'http_auth_otp_failed: TOTP 提交失败：{last_error or "unknown"}')

            managed_mail_enabled = bool(use_managed_mail_otp) and bool(str(managed_mail_jwt or '').strip()) and bool(
                str(managed_mail_api_base or '').strip()
            )
            domain_mail_enabled = bool(use_domain_mail_otp) and bool(str(domain_mail_api_base or '').strip()) and bool(
                str(domain_mail_token or '').strip()
            )
            otp_api_url_enabled = bool(str(otp_api_url or '').strip())
            imap_profiles = _normalize_imap_profiles_payload(
                imap_profiles_json,
                fallback_host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
                fallback_port=int(imap_port or 993),
                fallback_user=str(imap_user or '').strip(),
                fallback_pass=str(imap_pass or ''),
                fallback_folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
                fallback_latest_n=int(imap_latest_n or 10),
                fallback_auth_type=str(imap_auth_type or 'password').strip() or 'password',
                fallback_oauth_client_id=str(imap_oauth_client_id or '').strip(),
                fallback_oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
                fallback_password_fallback=bool(imap_password_fallback),
                fallback_pop3_fallback=bool(imap_pop3_fallback),
            )
            imap_enabled = bool(use_imap_otp) and bool(imap_profiles)
            if (not managed_mail_enabled) and (not domain_mail_enabled) and (not otp_api_url_enabled) and (not imap_enabled):
                if bool(use_domain_mail_otp):
                    raise RuntimeError(
                        'http_auth_otp_required: current flow requires email OTP, but domain_mail_api_base / domain_mail_token is unavailable.'
                    )
                if bool(use_managed_mail_otp):
                    raise RuntimeError(
                        'http_auth_otp_required: current flow requires email OTP, but mail_jwt / mail_api_base is unavailable.'
                    )
                if not bool(use_imap_otp):
                    raise RuntimeError('http_auth_otp_required: current flow requires email OTP, but API URL / domain mail / managed mail / IMAP OTP is unavailable.')
                raise RuntimeError('http_auth_otp_required: current flow requires email OTP, but API URL, domain mail or IMAP credentials are missing.')

            last_error = ''
            max_attempts = 3
            otp_send_path, otp_send_method = _choose_http_otp_send_request(
                payload,
                default_path=str(preferred_send_path or '/email-otp/send'),
            )
            otp_referer_url = _extract_continue_url(payload) or 'https://auth.openai.com/email-verification'
            for attempt in range(1, max_attempts + 1):
                should_send = attempt > 1
                if should_send:
                    await _emit_log(
                        log,
                        'info',
                        'Codex OAuth is requesting a fresh email OTP '
                        f'(attempt={attempt}/{max_attempts}, endpoint={otp_send_method} {otp_send_path}).',
                    )
                    send_res = await _request_auth_api_with_context(
                        request_ctx,
                        stage=f'http_auth_otp_send_{attempt}',
                        path=otp_send_path,
                        method=otp_send_method,
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        trace=trace,
                        referer_url=otp_referer_url,
                        accept='application/json',
                        include_json_content_type=True,
                        json_body={},
                    )
                    send_status = int(send_res.get('status') or 0)
                    send_text = str(send_res.get('text') or '')
                    send_payload = send_res.get('payload')
                    otp_send_path, otp_send_method = _choose_http_otp_send_request(
                        send_payload,
                        default_path=otp_send_path,
                    )
                    if otp_send_path == '/email-otp/resend':
                        otp_send_method = 'POST'
                    if send_status not in {200, 201, 202, 204}:
                        err_code, err_msg = _extract_error(send_payload, send_text)
                        last_error = str(err_code or err_msg or f'HTTP {send_status}')
                        continue
                    send_continue_url = _extract_continue_url(send_payload)
                    if send_continue_url:
                        otp_referer_url = send_continue_url
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': f'http_auth_otp_send_continue_{attempt}_deferred',
                                'continueUrl': _sanitize_url_for_log(send_continue_url),
                            }
                        )
                    not_before_ts = max(0.0, time.time() - _OTP_IMAP_POST_SEND_GRACE_SEC)
                else:
                    not_before_ts = max(0.0, time.time() - _OTP_IMAP_NOT_BEFORE_GRACE_SEC)
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': f'http_auth_otp_skip_send_{attempt}',
                            'reason': 'email_verification_already_active',
                            'notBeforeTs': float(not_before_ts),
                            'resendPath': otp_send_path,
                            'resendMethod': otp_send_method,
                        }
                    )

                code_value = ''
                otp_source = (
                    'managed_mail'
                    if managed_mail_enabled
                    else ('domain_mail' if domain_mail_enabled else ('otp_api_url' if otp_api_url_enabled else 'imap'))
                )
                if managed_mail_enabled:
                    await _emit_log(
                        log,
                        'info',
                        f'Codex OAuth is polling OTP from managed mail JWT (attempt={attempt}/{max_attempts}, target={_mask_email(safe_email)}).',
                    )
                    code_value = await asyncio.to_thread(
                        poll_managed_mail_verification_code_sync,
                        email=safe_email,
                        mail_provider=str(managed_mail_provider or '').strip(),
                        mail_jwt=str(managed_mail_jwt or '').strip(),
                        mail_api_base=str(managed_mail_api_base or '').strip(),
                        mail_frontend_base=str(managed_mail_frontend_base or '').strip(),
                        otp_timeout_sec=float(otp_timeout_sec),
                        otp_interval_sec=float(otp_interval_sec),
                        blocked_codes=blocked_otp_codes,
                        not_before_ts=float(not_before_ts),
                        latest_n=int(managed_mail_latest_n or 20),
                        log_info=managed_mail_log_info,
                        log_warn=managed_mail_log_warn,
                    )
                elif domain_mail_enabled:
                    await _emit_log(
                        log,
                        'info',
                        f'Codex OAuth is polling OTP from domain mail (attempt={attempt}/{max_attempts}, target={_mask_email(safe_email)}).',
                    )
                    code_value = await asyncio.to_thread(
                        poll_domain_mail_verification_code_sync,
                        email=safe_email,
                        api_base=str(domain_mail_api_base or '').strip(),
                        domain=str(domain_mail_domain or '').strip(),
                        token=str(domain_mail_token or '').strip(),
                        otp_timeout_sec=float(otp_timeout_sec),
                        otp_interval_sec=float(otp_interval_sec),
                        blocked_codes=blocked_otp_codes,
                        not_before_ts=float(not_before_ts),
                        latest_n=int(domain_mail_latest_n or 20),
                        log_info=managed_mail_log_info,
                        log_warn=managed_mail_log_warn,
                    )
                elif otp_api_url_enabled:
                    await _emit_log(
                        log,
                        'info',
                        f'Codex OAuth is polling OTP from the configured API URL (attempt={attempt}/{max_attempts}, target={_mask_email(safe_email)}).',
                    )
                    code_value = await asyncio.to_thread(
                        _poll_otp_api_url_verification_code_sync,
                        otp_api_url=str(otp_api_url or '').strip(),
                        otp_timeout_sec=float(otp_timeout_sec),
                        otp_interval_sec=float(otp_interval_sec),
                        blocked_codes=blocked_otp_codes,
                        not_before_ts=float(not_before_ts),
                    )
                else:
                    await _emit_log(
                        log,
                        'info',
                        'Codex OAuth is polling OTP from IMAP '
                        f'(attempt={attempt}/{max_attempts}, profiles={len(imap_profiles)}, target={_mask_email(safe_email)}).',
                    )
                    code_value = await asyncio.to_thread(
                        _poll_imap_code_multi_sync,
                        email=safe_email,
                        otp_timeout_sec=float(otp_timeout_sec),
                        otp_interval_sec=float(otp_interval_sec),
                        imap_profiles=imap_profiles,
                        blocked_codes=blocked_otp_codes,
                        not_before_ts=float(not_before_ts),
                        log=log,
                        loop=log_loop,
                    )
                if not code_value:
                    last_error = 'otp_timeout'
                    continue
                submit_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=f'http_auth_otp_submit_{otp_source}_{attempt}',
                    path='/email-otp/validate',
                    method='POST',
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=otp_referer_url,
                    json_body={'code': str(code_value)},
                    trace_json_body={'code': '***'},
                )
                submit_status = int(submit_res.get('status') or 0)
                submit_text = str(submit_res.get('text') or '')
                submit_payload = submit_res.get('payload')
                submit_continue_url = _extract_continue_url(submit_payload)
                submit_callback = _callback_from_url(
                    url=submit_continue_url,
                    expected_state=state,
                    redirect_uri=oauth_cfg.redirect_uri,
                )
                if submit_callback is not None and (submit_callback.code or submit_callback.error or submit_callback.state):
                    return submit_callback
                mfa_callback = await _submit_http_mfa_challenge_if_required(
                    payload=submit_payload,
                    continue_url=submit_continue_url,
                )
                if mfa_callback is not None:
                    return mfa_callback
                add_phone_callback = await _complete_http_add_phone_if_required(
                    continue_url=submit_continue_url,
                    source_stage=f'http_auth_otp_submit_{otp_source}_{attempt}',
                )
                if add_phone_callback is not None:
                    return add_phone_callback
                if submit_continue_url:
                    await _open_continue_url(
                        stage_name=f'http_auth_otp_submit_{otp_source}_continue_{attempt}',
                        continue_url=submit_continue_url,
                    )
                consent_continue_url = ''
                if _is_codex_consent_step(submit_payload):
                    consent_continue_url = str(_extract_continue_url(submit_payload) or '').strip()
                if (not consent_continue_url) and _is_codex_consent_url(submit_continue_url):
                    consent_continue_url = str(submit_continue_url or '').strip()
                if consent_continue_url:
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': f'http_auth_consent_detected_after_{otp_source}_otp',
                            'continueUrl': _sanitize_url_for_log(consent_continue_url),
                            'hints': _collect_auth_step_hints(submit_payload),
                        }
                    )
                    return await _complete_http_codex_consent(consent_url=consent_continue_url)
                if submit_status in {200, 201, 202, 204}:
                    return None
                err_code, err_msg = _extract_error(submit_payload, submit_text)
                last_error = str(err_code or err_msg or f'HTTP {submit_status}')
                low = f'{err_code}\n{err_msg}\n{submit_text}'.lower()
                if submit_status == 429 or any(
                    marker in low
                    for marker in ('max_check_attempts', 'too many tries', 'too many attempts', 'rate limit')
                ):
                    raise RuntimeError(
                        'http_auth_otp_cooldown: 邮箱验证码尝试次数已达上限，请等待远端冷却后再试。'
                    )
                if (submit_status == 401) or any(marker in low for marker in _OTP_INVALID_MARKERS):
                    blocked_otp_codes.add(str(code_value))
                    await _emit_log(log, 'warn', 'Codex OAuth OTP validation failed, retrying with a fresh code.')
                    continue
                break

            if last_error == 'otp_timeout':
                raise RuntimeError('http_auth_otp_failed: timed out waiting for a usable email OTP.')
            raise RuntimeError(f'http_auth_otp_failed: email OTP submit failed: {last_error or "unknown"}')

        async def _handle_http_interactive_signup(interactive_url: str, interactive_body_text: str) -> bool | OAuthCallback:
            from chatgpt_register_http import run_http_oauth_inline_signup_from_interactive_page

            if not str(password or '').strip():
                raise RuntimeError('http_auth_signup_required: OAuth 内联注册需要密码。')
            await _emit_log(log, 'info', '【Codex OAuth】authorize 交互页走 OAuth 内联注册（screen_hint=signup）')
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_auth_oauth_inline_signup_entry',
                    'url': _sanitize_url_for_log(interactive_url),
                    'bodySnippet': _compress_debug_text(interactive_body_text, limit=320),
                }
            )
            signup_result = await run_http_oauth_inline_signup_from_interactive_page(
                request_ctx=request_ctx,
                interactive_url=interactive_url,
                email=safe_email,
                password=str(password or ''),
                trace=trace,
                log=log,
                timeout_sec=float(timeout_sec),
                otp_timeout_sec=float(otp_timeout_sec),
                otp_interval_sec=float(otp_interval_sec),
                use_managed_mail_otp=bool(use_managed_mail_otp),
                managed_mail_provider=str(managed_mail_provider or '').strip(),
                managed_mail_jwt=str(managed_mail_jwt or '').strip(),
                managed_mail_api_base=str(managed_mail_api_base or '').strip(),
                managed_mail_frontend_base=str(managed_mail_frontend_base or '').strip(),
                managed_mail_latest_n=int(managed_mail_latest_n or 20),
                use_domain_mail_otp=bool(use_domain_mail_otp),
                domain_mail_api_base=str(domain_mail_api_base or '').strip(),
                domain_mail_domain=str(domain_mail_domain or '').strip(),
                domain_mail_token=str(domain_mail_token or ''),
                domain_mail_latest_n=int(domain_mail_latest_n or 20),
                use_imap_otp=bool(use_imap_otp),
                imap_host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
                imap_port=int(imap_port or 993),
                imap_user=str(imap_user or '').strip(),
                imap_pass=str(imap_pass or ''),
                imap_folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
                imap_latest_n=int(imap_latest_n or 10),
                imap_auth_type=str(imap_auth_type or 'password').strip() or 'password',
                imap_oauth_client_id=str(imap_oauth_client_id or '').strip(),
                imap_oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
                imap_password_fallback=bool(imap_password_fallback),
                imap_pop3_fallback=bool(imap_pop3_fallback),
            )
            if not bool(signup_result.get('ok')):
                raise RuntimeError(
                    'http_auth_oauth_inline_signup_failed: '
                    f'{str(signup_result.get("error") or "unknown").strip() or "unknown"}'
                )
            final_payload = signup_result.get('final_payload') if isinstance(signup_result.get('final_payload'), dict) else {}
            final_continue_url = str(signup_result.get('final_continue_url') or _extract_continue_url(final_payload) or '').strip()
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_auth_oauth_inline_signup_completed',
                    'signupRoute': str(signup_result.get('signup_route') or 'oauth_inline'),
                    'continueUrl': _sanitize_url_for_log(final_continue_url),
                    'hints': _collect_auth_step_hints(final_payload),
                }
            )
            signup_callback = _callback_from_url(
                url=final_continue_url,
                expected_state=state,
                redirect_uri=oauth_cfg.redirect_uri,
            )
            if signup_callback is not None and (signup_callback.code or signup_callback.error or signup_callback.state):
                return signup_callback
            add_phone_callback = await _complete_http_add_phone_if_required(
                continue_url=final_continue_url,
                source_stage='http_auth_oauth_inline_signup',
            )
            if isinstance(add_phone_callback, OAuthCallback):
                return add_phone_callback
            if add_phone_callback is True:
                await _refresh_session_state(
                    stage_name='http_session_bootstrap_after_oauth_inline_signup_phone',
                    exchange_stage_name='http_workspace_exchange_after_oauth_inline_signup_phone',
                    exchange_claims_stage_name='http_workspace_exchange_claims_after_oauth_inline_signup_phone',
                    log_message_prefix='OAuth 内联注册后手机验证完成，刷新 session',
                )
                return True
            consent_continue_url = ''
            if _is_codex_consent_step(final_payload):
                consent_continue_url = str(_extract_continue_url(final_payload) or '').strip()
            if (not consent_continue_url) and _is_codex_consent_url(final_continue_url):
                consent_continue_url = final_continue_url
            if consent_continue_url:
                return await _complete_http_codex_consent(consent_url=consent_continue_url)
            otp_callback = await _submit_http_otp_if_required(payload=final_payload)
            if isinstance(otp_callback, OAuthCallback):
                return otp_callback
            if otp_callback is True:
                await _refresh_session_state(
                    stage_name='http_session_bootstrap_after_oauth_inline_signup_otp',
                    exchange_stage_name='http_workspace_exchange_after_oauth_inline_signup_otp',
                    exchange_claims_stage_name='http_workspace_exchange_claims_after_oauth_inline_signup_otp',
                    log_message_prefix='OAuth 内联注册后 OTP 完成，刷新 session',
                )
                return True
            await _refresh_session_state(
                stage_name='http_session_bootstrap_after_oauth_inline_signup',
                exchange_stage_name='http_workspace_exchange_after_oauth_inline_signup',
                exchange_claims_stage_name='http_workspace_exchange_claims_after_oauth_inline_signup',
                log_message_prefix='OAuth 内联注册完成，刷新 session',
            )
            return True

        async def _handle_http_interactive_login(interactive_url: str, interactive_body_text: str) -> bool:
            if not str(password or '').strip():
                raise RuntimeError('http_auth_login_required: authorize 已进入登录页，但当前账号未提供密码，纯 HTTP 无法继续。')
            await _emit_log(log, 'info', '【Codex OAuth】步骤 4/8：authorize 已回落到登录页，开始纯 HTTP 登录继续链路')
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_auth_login_entry',
                    'url': _sanitize_url_for_log(interactive_url),
                    'bodySnippet': _compress_debug_text(interactive_body_text, limit=320),
                }
            )

            sentinel_header_candidates = await _collect_http_sentinel_header_candidates_for_flows(
                flow_names=(
                    _HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW,
                    _HTTP_PASSWORD_VERIFY_SENTINEL_FLOW,
                ),
                playwright=None,
                storage_state_path='',
                proxy_opt=proxy_opt,
                trace=trace,
                timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
            authorize_continue_header_candidates = list(
                sentinel_header_candidates.get(_HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW) or []
            )
            login_hint_status = 0
            login_hint_payload: Any = {}
            login_hint_text = ''
            login_hint_error = ''
            for candidate_name, candidate_headers in authorize_continue_header_candidates:
                login_hint_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=f'http_auth_login_hint_{candidate_name}',
                    path='/authorize/continue',
                    method='POST',
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=interactive_url,
                    json_body={
                        'username': {'kind': 'email', 'value': safe_email},
                    },
                    extra_headers=candidate_headers,
                )
                login_hint_status = int(login_hint_res.get('status') or 0)
                login_hint_payload = login_hint_res.get('payload')
                login_hint_text = str(login_hint_res.get('text') or '')
                if login_hint_status in {200, 201, 202, 204}:
                    break
                err_code, err_msg = _extract_error(login_hint_payload, login_hint_text)
                login_hint_error = str(err_msg or err_code or f'HTTP {login_hint_status}')
                if err_code in {'invalid_state', 'preauth_cookie_invalid'}:
                    raise RuntimeError('http_auth_login_failed: 当前纯 HTTP 新会话已失效，请重新开始邮箱/密码/OTP 登录流程。')
                if err_code in {'invalid_state', 'preauth_cookie_invalid'}:
                    raise RuntimeError('http_auth_login_failed: 登录链路 client/session 无效，请重新注入最新 storage_state 后重试。')
            if login_hint_status not in {200, 201, 202, 204}:
                raise RuntimeError(f'http_auth_login_failed: 登录链路未接受邮箱：{login_hint_error or f"HTTP {login_hint_status}"}')
            login_continue_url = _extract_continue_url(login_hint_payload)
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_auth_login_hint_parsed',
                    'status': login_hint_status,
                    'continueUrl': _sanitize_url_for_log(login_continue_url),
                    'hints': _collect_auth_step_hints(login_hint_payload),
                }
            )
            if login_continue_url:
                await _open_continue_url(stage_name='http_auth_login_continue_page', continue_url=login_continue_url)
            if _is_email_otp_verification_step(login_hint_payload):
                login_hint_callback = await _submit_http_otp_if_required(payload=login_hint_payload)
                if isinstance(login_hint_callback, OAuthCallback):
                    return login_hint_callback
                if login_hint_callback is True:
                    await _refresh_session_state(
                        stage_name='http_session_bootstrap_after_login_hint_otp',
                        exchange_stage_name='http_workspace_exchange_after_login_hint_otp',
                        exchange_claims_stage_name='http_workspace_exchange_claims_after_login_hint_otp',
                        log_message_prefix='HTTP 登录提示 OTP 完成后刷新 session',
                    )
                    return True

            password_verify_header_candidates = list(
                sentinel_header_candidates.get(_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW) or []
            )
            password_attempts = [
                (
                    f'http_auth_password_verify_{candidate_name}',
                    '/password/verify',
                    {'password': str(password)},
                    candidate_headers,
                )
                for candidate_name, candidate_headers in password_verify_header_candidates
            ]
            final_payload: Any = {}
            final_continue_url = ''
            final_error = ''
            final_otp_send_path = '/email-otp/send'
            invalid_password_error_code = ''
            invalid_password_error_message = ''
            for stage_name, path, body, extra_headers in password_attempts:
                submit_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=stage_name,
                    path=path,
                    method='POST',
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=login_continue_url or interactive_url,
                    json_body=body,
                    extra_headers=extra_headers,
                )
                submit_status = int(submit_res.get('status') or 0)
                submit_payload = submit_res.get('payload')
                submit_text = str(submit_res.get('text') or '')
                submit_continue_url = _extract_continue_url(submit_payload)
                if submit_continue_url:
                    await _open_continue_url(stage_name=f'{stage_name}_continue_page', continue_url=submit_continue_url)
                if submit_status in {200, 201, 202, 204}:
                    final_payload = submit_payload
                    final_continue_url = submit_continue_url
                    break
                err_code, err_msg = _extract_error(submit_payload, submit_text)
                final_error = str(err_msg or err_code or f'HTTP {submit_status}')
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': f'{stage_name}_failed',
                        'status': submit_status,
                        'errorCode': str(err_code or '').strip(),
                        'errorMessage': str(err_msg or '').strip(),
                        'hints': _collect_auth_step_hints(submit_payload),
                    }
                )
                if err_code in {'invalid_username_or_password', 'invalid_credentials'} or _is_invalid_authorization_step(
                    err_code=err_code,
                    err_msg=err_msg,
                    text=submit_text,
                ):
                    invalid_password_error_code = str(err_code or 'invalid_authorization_step').strip()
                    invalid_password_error_message = str(err_msg or submit_text or '').strip()
                    continue

            if (not final_payload) and (not final_continue_url):
                if _should_try_http_passwordless_login_fallback(
                    login_payload=login_hint_payload,
                    err_code=invalid_password_error_code,
                    err_msg=invalid_password_error_message,
                    email=safe_email,
                    use_imap_otp=bool(use_imap_otp),
                    imap_user=imap_user,
                    imap_pass=imap_pass,
                    imap_auth_type=imap_auth_type,
                    imap_oauth_client_id=imap_oauth_client_id,
                    imap_oauth_refresh_token=imap_oauth_refresh_token,
                ):
                    await _emit_log(log, 'warn', '【Codex OAuth】密码校验失败，尝试切换到一次性验证码登录链路。')
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_auth_passwordless_send_otp_start',
                            'reason': invalid_password_error_code or invalid_password_error_message or final_error,
                            'loginHints': _collect_auth_step_hints(login_hint_payload),
                        }
                    )
                    passwordless_res = await _request_auth_api_with_context(
                        request_ctx,
                        stage='http_auth_passwordless_send_otp',
                        path='/passwordless/send-otp',
                        method='POST',
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        trace=trace,
                        referer_url=login_continue_url or interactive_url,
                    )
                    passwordless_status = int(passwordless_res.get('status') or 0)
                    passwordless_payload = passwordless_res.get('payload')
                    passwordless_text = str(passwordless_res.get('text') or '')
                    passwordless_continue_url = _extract_continue_url(passwordless_payload)
                    if passwordless_continue_url:
                        await _open_continue_url(
                            stage_name='http_auth_passwordless_send_otp_continue_page',
                            continue_url=passwordless_continue_url,
                        )
                    if passwordless_status in {200, 201, 202, 204}:
                        final_payload = (
                            passwordless_payload
                            if isinstance(passwordless_payload, dict)
                            else ({'continue_url': passwordless_continue_url} if passwordless_continue_url else {})
                        )
                        final_continue_url = passwordless_continue_url
                        final_otp_send_path = '/passwordless/send-otp'
                    else:
                        err_code, err_msg = _extract_error(passwordless_payload, passwordless_text)
                        final_error = str(err_msg or err_code or f'HTTP {passwordless_status}')
                        trace.write(
                            {
                                'ts': _iso_now(),
                                'stage': 'http_auth_passwordless_send_otp_failed',
                                'status': passwordless_status,
                                'errorCode': str(err_code or '').strip(),
                                'errorMessage': str(err_msg or '').strip(),
                                'hints': _collect_auth_step_hints(passwordless_payload),
                            }
                        )
                elif invalid_password_error_code or invalid_password_error_message:
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_auth_passwordless_fallback_skipped',
                            'reason': 'disabled',
                            'errorCode': invalid_password_error_code,
                            'errorMessage': invalid_password_error_message,
                            'loginHints': _collect_auth_step_hints(login_hint_payload),
                        }
                    )

            if not isinstance(final_payload, dict):
                final_payload = {}
            final_hints = _collect_auth_step_hints(final_payload)
            if final_continue_url and ('/log-in/password' in str(final_continue_url or '').strip().lower()) and not final_hints:
                raise RuntimeError('http_auth_login_failed: 密码提交后仍停留在 login_password 页面，未进入 callback 链路。')
            if final_payload:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_password_submit_result',
                        'continueUrl': _sanitize_url_for_log(final_continue_url),
                        'hints': final_hints,
                    }
                )
            if (not final_payload) and (not final_continue_url):
                raise RuntimeError(f'http_auth_login_failed: 密码提交未完成：{final_error or "unknown"}')

            add_phone_callback = await _complete_http_add_phone_if_required(
                continue_url=final_continue_url,
                source_stage='http_auth_password_submit',
            )
            if isinstance(add_phone_callback, OAuthCallback):
                return add_phone_callback
            if add_phone_callback is True:
                await _refresh_session_state(
                    stage_name='http_session_bootstrap_after_password_phone',
                    exchange_stage_name='http_workspace_exchange_after_password_phone',
                    exchange_claims_stage_name='http_workspace_exchange_claims_after_password_phone',
                    log_message_prefix='HTTP 手机验证完成后刷新 session',
                )
                return True

            consent_continue_url = ''
            if _is_codex_consent_step(final_payload):
                consent_continue_url = str(_extract_continue_url(final_payload) or '').strip()
            if (not consent_continue_url) and _is_codex_consent_url(final_continue_url):
                consent_continue_url = str(final_continue_url or '').strip()
            if consent_continue_url:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_consent_detected',
                        'continueUrl': _sanitize_url_for_log(consent_continue_url),
                        'hints': final_hints,
                    }
                )
                return await _complete_http_codex_consent(consent_url=consent_continue_url)

            mfa_callback = await _submit_http_mfa_challenge_if_required(
                payload=final_payload,
                continue_url=final_continue_url,
            )
            if isinstance(mfa_callback, OAuthCallback):
                return mfa_callback
            if mfa_callback is True:
                await _refresh_session_state(
                    stage_name='http_session_bootstrap_after_password_mfa',
                    exchange_stage_name='http_workspace_exchange_after_password_mfa',
                    exchange_claims_stage_name='http_workspace_exchange_claims_after_password_mfa',
                    log_message_prefix='HTTP TOTP 完成后刷新 session',
                )
                return True

            otp_callback = await _submit_http_otp_if_required(
                payload=final_payload,
                preferred_send_path=final_otp_send_path,
                allow_totp=False,
            )
            if isinstance(otp_callback, OAuthCallback):
                return otp_callback
            if otp_callback is True:
                await _refresh_session_state(
                    stage_name='http_session_bootstrap_after_final_otp_phone',
                    exchange_stage_name='http_workspace_exchange_after_final_otp_phone',
                    exchange_claims_stage_name='http_workspace_exchange_claims_after_final_otp_phone',
                    log_message_prefix='HTTP 最终 OTP/手机验证完成后刷新 session',
                )
                return True
            await _refresh_session_state(
                stage_name='http_session_bootstrap_after_login',
                exchange_stage_name='http_workspace_exchange_after_login',
                exchange_claims_stage_name='http_workspace_exchange_claims_after_login',
                log_message_prefix='HTTP 登录链路完成后刷新 session',
            )
            return True

        await _emit_log(log, 'info', '【Codex OAuth】步骤 3/8：探测 chatgpt.com 当前 session / workspace')
        await _refresh_session_state(
            stage_name='http_session_bootstrap',
            exchange_stage_name='http_workspace_exchange',
            exchange_claims_stage_name='http_workspace_exchange_claims',
            log_message_prefix='已复用现有 session',
        )

        await _emit_log(log, 'info', '【Codex OAuth】步骤 5/8：通过纯 HTTP 跟随 OAuth authorize 跳转链')
        interactive_handler = _handle_http_interactive_signup if inline_signup_test else _handle_http_interactive_login
        callback = await _follow_http_authorize_chain(
            request_ctx,
            auth_url=auth_url,
            redirect_uri=oauth_cfg.redirect_uri,
            expected_state=state,
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0)),
            trace=trace,
            interactive_handler=interactive_handler,
            phone_handler=lambda continue_url: _complete_http_add_phone_if_required(
                continue_url=continue_url,
                source_stage='http_authorize_terminal',
            ),
        )
        if str(callback.error or '').strip():
            desc = str(callback.error_description or '').strip()
            raise RuntimeError(f'http_auth_authorize_failed: {callback.error}{f" ({desc})" if desc else ""}')
        code = str(callback.code or '').strip()
        if not code:
            raise RuntimeError('http_auth_code_missing: OAuth 回调缺少 code。')
        if bool(require_phone_bind):
            raise RuntimeError(
                'phone_bind_not_offered: the authenticated OAuth transaction completed without an add-phone step'
            )

        await _emit_log(log, 'info', '【Codex OAuth】步骤 6/8：开始交换 access_token / refresh_token')
        if isinstance(token_exchange_payload, dict) and str(token_exchange_payload.get('access_token') or '').strip():
            token_resp = token_exchange_payload
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'http_token_exchange_reused_same_session_result',
                    'responseSummary': _summarize_oauth_token_response_for_trace(payload=token_resp, text=''),
                }
            )
        else:
            token_resp = {}
            if isinstance(token_exchange_storage_state, dict) and token_exchange_storage_state.get('cookies'):
                exchange_ctx = request_ctx
                exchange_ctx_owned = False
                exchange_ctx = await asyncio.to_thread(
                    _build_http_provider_request_context,
                    storage_state=token_exchange_storage_state,
                    proxy_url=resolved_proxy_url,
                    impersonate=resolved_impersonate,
                )
                exchange_ctx_owned = True
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_token_exchange_context_switched',
                        'cookieCount': len(token_exchange_storage_state.get('cookies') or []),
                    }
                )
                try:
                    token_resp = await _exchange_code_for_tokens_with_context(
                        exchange_ctx,
                        code=code,
                        pkce=pkce,
                        client_id=oauth_cfg.client_id,
                        redirect_uri=oauth_cfg.redirect_uri,
                        trace=trace,
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0)),
                    )
                finally:
                    if exchange_ctx_owned:
                        try:
                            await exchange_ctx.dispose()
                        except Exception:
                            pass
            else:
                try:
                    token_resp = await asyncio.to_thread(
                        _exchange_code_for_tokens,
                        code=code,
                        pkce=pkce,
                        client_id=oauth_cfg.client_id,
                        redirect_uri=oauth_cfg.redirect_uri,
                        proxy_url=resolved_proxy_url,
                    )
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_token_exchange_plain_success',
                            'responseSummary': _summarize_oauth_token_response_for_trace(payload=token_resp, text=''),
                        }
                    )
                except Exception as plain_error:
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_token_exchange_plain_failed',
                            'error': _compress_debug_text(str(plain_error), limit=320),
                        }
                    )
                    raise
        persisted = await _persist_codex_token_payload(
            log=log,
            safe_email=safe_email,
            output_path=output_path,
            token_resp=token_resp,
            trace_path=trace_path,
            expected_workspace_id=normalized_expected_workspace_id,
            bound_phone_numbers=[
                str(getattr(candidate, 'phone', '') or '').strip()
                for candidate in pending_phone_candidates
                if str(getattr(candidate, 'phone', '') or '').strip()
            ],
        )
        phone_usage_committed = True
        for candidate in list(pending_phone_candidates):
            try:
                await asyncio.to_thread(mark_http_phone_completed, candidate)
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_add_phone_counted_after_credential_persist',
                        'phoneMasked': _mask_phone_for_log(str(getattr(candidate, 'phone', '') or '')),
                    }
                )
            except Exception as error:
                await _emit_log(log, 'warn', f'Codex OAuth phone usage count update failed after credential persisted: {error}')
        try:
            cfg = _load_codex_oauth_config_file()
            usage_mode = _resolve_add_phone_local_usage_mode(cfg)
            owner_marked = await asyncio.to_thread(
                mark_http_phone_completed_for_owner,
                cfg,
                owner_key=safe_email,
                log_fn=managed_mail_log_info,
                local_phone_usage_mode=usage_mode,
            )
            if owner_marked:
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'http_auth_add_phone_pending_owner_counted_after_credential_persist',
                        'owner': _mask_email(safe_email),
                    }
                )
        except Exception as error:
            await _emit_log(log, 'warn', f'Codex OAuth pending phone owner count update failed after credential persisted: {error}')
        return persisted
    except _PhoneBindCompleted as completed:
        phone_usage_committed = True
        updated_storage_state: dict[str, Any] = {}
        if request_ctx is not None:
            try:
                updated_storage_state = await _read_request_context_storage_state(request_ctx)
            except Exception:
                await _emit_log(
                    log,
                    'warn',
                    'Phone binding succeeded, but the refreshed storage state could not be exported.',
                )
        return {
            'success': True,
            'trace_path': trace_path,
            'bound_phone': completed.phone,
            'phone_number': completed.phone,
            'storage_state': updated_storage_state,
            'phone_bind_validated': True,
        }
    finally:
        if (not phone_usage_committed) and pending_phone_candidates:
            for candidate in list(pending_phone_candidates):
                try:
                    await asyncio.to_thread(dispose_http_phone_after_failure, candidate)
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'http_auth_add_phone_disposed_after_uncommitted_flow',
                            'phoneMasked': _mask_phone_for_log(str(getattr(candidate, 'phone', '') or '')),
                        }
                    )
                except Exception as error:
                    await _emit_log(log, 'warn', f'Codex OAuth pending phone dispose failed after flow error: {error}')
            pending_phone_candidates.clear()
        if request_ctx is not None:
            try:
                await request_ctx.dispose()
            except Exception:
                pass


def _normalize_plan(plan: str) -> str:
    p = str(plan or '').strip().lower()
    if not p:
        return ''
    out: list[str] = []
    for ch in p:
        if ch.isalnum():
            out.append(ch)
        elif ch in {' ', '_', '.', '/'}:
            out.append('-')
    return ''.join(out).strip('-')[:40]


def build_output_path(*, base_dir: str, safe_email: str, plan_type: str, account_id: str) -> str:
    root = Path(base_dir).expanduser()
    out_dir = root / 'codex_oauth'
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f'codex-{safe_email}.json'
    return str(out_dir / filename)


async def _emit_log(log: Any, level: str, message: str) -> None:
    try:
        emit = getattr(log, 'emit', None)
        if callable(emit):
            await emit(level, message)
            return
    except Exception:
        pass

    fn = None
    if level == 'warn':
        fn = getattr(log, 'warn', None) or getattr(log, 'warning', None)
    elif level == 'error':
        fn = getattr(log, 'error', None)
    elif level == 'success':
        fn = getattr(log, 'success', None) or getattr(log, 'info', None)
    else:
        fn = getattr(log, 'info', None)
    if callable(fn):
        fn(message)


def _emit_log_sync(loop: asyncio.AbstractEventLoop, log: Any, level: str, message: str) -> None:
    try:
        future = asyncio.run_coroutine_threadsafe(_emit_log(log, level, message), loop)
        future.result(timeout=10)
        return
    except Exception:
        pass
    try:
        if level == 'warn':
            fn = getattr(log, 'warn', None) or getattr(log, 'warning', None)
        elif level == 'error':
            fn = getattr(log, 'error', None)
        elif level == 'success':
            fn = getattr(log, 'success', None) or getattr(log, 'info', None)
        else:
            fn = getattr(log, 'info', None)
        if callable(fn):
            fn(message)
    except Exception:
        pass


def _sanitize_url_for_log(url: str) -> str:
    return str(url or '').strip()


def _compress_debug_text(text: Any, *, limit: int = 1000) -> str:
    merged = re.sub(r'\s+', ' ', str(text or '')).strip()
    if len(merged) <= limit:
        return merged
    return merged[: max(0, limit - 1)].rstrip() + '…'


def _extract_auth_error_detail(url: str) -> str:
    raw = str(url or '').strip()
    if not raw:
        return ''
    try:
        parsed = urllib.parse.urlsplit(raw)
        payload = str((urllib.parse.parse_qs(parsed.query).get('payload') or [''])[0] or '').strip()
        if not payload:
            return ''
        pad = '=' * ((4 - (len(payload) % 4)) % 4)
        decoded = base64.urlsafe_b64decode((payload + pad).encode('utf-8')).decode('utf-8')
        obj = json.loads(decoded)
        if not isinstance(obj, dict):
            return ''
        kind = str(obj.get('kind') or '').strip()
        code = str(obj.get('errorCode') or '').strip()
        request_id = str(obj.get('requestId') or '').strip()
        parts = [part for part in (kind, code, f'request_id={request_id}' if request_id else '') if part]
        return ' / '.join(parts)
    except Exception:
        return ''


def _safe_debug_tag(tag: str) -> str:
    safe = re.sub(r'[^0-9A-Za-z._-]+', '_', str(tag or '').strip())
    safe = safe.strip('._-')
    return safe or 'snapshot'


def _normalize_proxy_server(proxy_url: str) -> str:
    return _normalize_browser_proxy_url(proxy_url)


def _resolve_codex_proxy_url() -> str:
    if 'AIO_API_PROXY' in os.environ:
        explicit = str(os.getenv('AIO_API_PROXY') or '').strip()
        return '' if explicit.lower() in _DIRECT_PROXY_MARKERS else explicit
    codex_proxy = str(os.getenv('AIO_CODEX_OAUTH_PROXY_URL') or '').strip()
    if codex_proxy.lower() in _DIRECT_PROXY_MARKERS:
        return ''
    return (
        codex_proxy
        or str(os.getenv('HTTPS_PROXY') or '').strip()
        or str(os.getenv('HTTP_PROXY') or '').strip()
    )


def _resolve_browser_path() -> tuple[str, tuple[str, ...]]:
    notices: list[str] = []
    raw = str(os.getenv('AIO_CODEX_OAUTH_BROWSER_PATH') or '').strip() or str(os.getenv('AIO_DRISSION_EDGE_PATH') or '').strip()
    if raw:
        p = Path(raw).expanduser()
        if p.exists() and p.is_file():
            return str(p), tuple(notices)
        notices.append(f'指定的 Drission 浏览器路径不存在：{p}，将继续尝试默认 Edge/Chrome。')

    candidates = [
        Path('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'),
        Path('C:/Program Files/Microsoft/Edge/Application/msedge.exe'),
        Path('C:/Program Files/Google/Chrome/Application/chrome.exe'),
        Path('C:/Program Files (x86)/Google/Chrome/Application/chrome.exe'),
        Path('/usr/bin/microsoft-edge'),
        Path('/usr/bin/microsoft-edge-stable'),
        Path('/opt/microsoft/msedge/msedge'),
        Path('/usr/bin/google-chrome'),
        Path('/usr/bin/google-chrome-stable'),
        Path('/snap/bin/chromium'),
        Path('/usr/bin/chromium'),
        Path('/usr/bin/chromium-browser'),
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate), tuple(notices)

    joined = '；'.join(str(item) for item in candidates)
    notices.append('未找到可用的 Edge/Chrome 可执行文件。')
    raise FileNotFoundError('；'.join(notices) + f' 已检查路径：{joined}')


def _resolve_profile_root() -> Path:
    raw = str(os.getenv('AIO_CODEX_OAUTH_PROFILE_ROOT') or '').strip()
    if raw:
        return _resolve_any_path(raw)
    return (_repo_root() / 'tmp' / 'codex_oauth_profiles').resolve()


def _safe_get(tab: Any, url: str, *, timeout_seconds: float) -> bool:
    try:
        result = tab.get(str(url), timeout=float(timeout_seconds), retry=1, interval=1)
        return bool(result)
    except Exception:
        return False


def _run_async(coro: Any) -> Any:
    try:
        _ = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_storage_state_payload(state_path: str) -> dict[str, Any]:
    safe_path = str(state_path or '').strip()
    if not safe_path:
        raise ValueError('storage_state 路径为空。')
    path = _resolve_any_path(safe_path)
    if not path.exists():
        raise FileNotFoundError(f'storage_state 文件不存在：{path}')
    payload = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(payload, dict):
        raise ValueError('storage_state 文件格式错误：根节点必须为对象。')
    return payload


def _normalize_cookie_for_cdp(raw: dict[str, Any]) -> dict[str, Any] | None:
    name = str(raw.get('name') or '').strip()
    value = str(raw.get('value') or '')
    domain = str(raw.get('domain') or '').strip()
    url = str(raw.get('url') or '').strip()
    if not name or (not domain and not url):
        return None
    out: dict[str, Any] = {
        'name': name,
        'value': value,
    }
    if url:
        out['url'] = url
    else:
        out['domain'] = domain
        out['path'] = str(raw.get('path') or '/').strip() or '/'
    if 'secure' in raw:
        out['secure'] = bool(raw.get('secure'))
    if 'httpOnly' in raw:
        out['httpOnly'] = bool(raw.get('httpOnly'))
    same_site = str(raw.get('sameSite') or '').strip().capitalize()
    if same_site in {'Lax', 'Strict', 'None'}:
        out['sameSite'] = same_site
    try:
        expires = float(raw.get('expires'))
        if expires > 0:
            out['expires'] = expires
    except Exception:
        pass
    return out


def _hydrate_storage_state_to_tab(
    *,
    tab: Any,
    storage_state_path: str,
    timeout_seconds: float,
    trace: _TraceWriter,
) -> dict[str, Any]:
    safe_path = str(storage_state_path or '').strip()
    if not safe_path:
        return {'ok': False, 'reason': 'storage_state_missing'}
    try:
        payload = _load_storage_state_payload(safe_path)
    except Exception as error:
        trace.write({'ts': _iso_now(), 'stage': 'hydrate_storage_state', 'ok': False, 'error': str(error)})
        return {'ok': False, 'reason': str(error)}

    cookies_raw = payload.get('cookies') or []
    if not isinstance(cookies_raw, list):
        cookies_raw = []
    cdp_cookies = [item for item in (_normalize_cookie_for_cdp(row) for row in cookies_raw if isinstance(row, dict)) if item]
    cookie_count = 0
    try:
        if cdp_cookies:
            tab.run_cdp('Network.setCookies', cookies=cdp_cookies)
            cookie_count = len(cdp_cookies)
    except Exception as error:
        trace.write({'ts': _iso_now(), 'stage': 'hydrate_storage_state_set_cookies', 'ok': False, 'error': str(error)})

    origins_raw = payload.get('origins') or []
    if not isinstance(origins_raw, list):
        origins_raw = []
    preferred: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    for row in origins_raw:
        if not isinstance(row, dict):
            continue
        origin = str(row.get('origin') or '').strip().lower()
        if 'auth.openai.com' in origin or 'chatgpt.com' in origin:
            preferred.append(row)
        else:
            others.append(row)
    ordered_origins = preferred + others

    origin_count = 0
    for row in ordered_origins[:8]:
        origin = str(row.get('origin') or '').strip()
        if not origin.startswith(('http://', 'https://')):
            continue
        local_rows = row.get('localStorage') or []
        if not isinstance(local_rows, list) or not local_rows:
            continue
        if not _safe_get(tab, origin, timeout_seconds=max(8.0, float(timeout_seconds))):
            continue
        try:
            result = tab.run_js(_SET_LOCAL_STORAGE_JS, {'items': local_rows}, timeout=8)
            if isinstance(result, dict) and bool(result.get('ok')):
                origin_count += 1
        except Exception as error:
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'hydrate_storage_state_set_local_storage',
                    'origin': origin,
                    'ok': False,
                    'error': str(error),
                }
            )
        time.sleep(0.2)

    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'hydrate_storage_state',
            'ok': bool(cookie_count or origin_count),
            'cookieCount': int(cookie_count),
            'originCount': int(origin_count),
            'path': str(_resolve_any_path(safe_path)),
        }
    )
    return {
        'ok': bool(cookie_count or origin_count),
        'cookieCount': int(cookie_count),
        'originCount': int(origin_count),
    }


def _collect_page_snapshot(tab: Any) -> dict[str, Any]:
    fallback_url = ''
    fallback_title = ''
    try:
        fallback_url = str(tab.url or '')
    except Exception:
        fallback_url = ''
    try:
        fallback_title = str(tab.title or '')
    except Exception:
        fallback_title = ''

    try:
        result = tab.run_js(
            _PAGE_SNAPSHOT_JS,
            {
                'emailSelectors': list(_EMAIL_SELECTORS),
                'passwordSelectors': list(_PASSWORD_SELECTORS),
                'otpSelectors': list(_OTP_SELECTORS),
            },
            timeout=8,
        )
    except Exception:
        result = {}
    if not isinstance(result, dict):
        result = {}

    button_texts = result.get('buttonTexts') or []
    frame_urls = result.get('frameUrls') or []
    return {
        'url': str(result.get('url') or fallback_url or ''),
        'title': str(result.get('title') or fallback_title or ''),
        'bodyText': str(result.get('bodyText') or ''),
        'emailVisible': bool(result.get('emailVisible')),
        'passwordVisible': bool(result.get('passwordVisible')),
        'otpVisible': bool(result.get('otpVisible')),
        'buttonTexts': [str(item or '').strip() for item in button_texts if str(item or '').strip()],
        'frameUrls': [str(item or '').strip() for item in frame_urls if str(item or '').strip()],
    }


def _save_debug_screenshot(tab: Any, path: Path) -> bool:
    candidates = [
        ('save_screenshot', {'path': str(path), 'full_page': True}),
        ('save_screenshot', {'path': str(path)}),
        ('get_screenshot', {'path': str(path), 'full_page': True}),
        ('get_screenshot', {'path': str(path)}),
    ]
    for method_name, kwargs in candidates:
        fn = getattr(tab, method_name, None)
        if not callable(fn):
            continue
        try:
            fn(**kwargs)
            return True
        except TypeError:
            try:
                fn(str(path))
                return True
            except Exception:
                continue
        except Exception:
            continue
    return False


def _read_challenge_active_element_summary(tab: Any) -> dict[str, Any]:
    try:
        result = tab.run_js(
            """
try {
  const root = document;
  const focusChain = [];
  const visited = new Set();
  let current = root.activeElement || null;
  while (current && !visited.has(current)) {
    visited.add(current);
    const attrs = {};
    for (const name of ['role', 'title', 'name', 'id', 'class', 'type', 'tabindex', 'aria-label', 'aria-checked', 'data-testid']) {
      try {
        const value = current.getAttribute ? current.getAttribute(name) : '';
        if (value) {
          attrs[name] = String(value);
        }
      } catch (error) {
      }
    }
    focusChain.push({
      tag: String(current.tagName || '').toLowerCase(),
      text: String(current.innerText || current.textContent || '').trim().slice(0, 160),
      attributes: attrs,
    });
    if (current.shadowRoot && current.shadowRoot.activeElement) {
      current = current.shadowRoot.activeElement;
      continue;
    }
    break;
  }
  const el = current;
  if (!el) {
    return {ok: false, reason: 'no_active_element', focusChain};
  }
  const attrs = {};
  for (const name of ['role', 'title', 'name', 'id', 'class', 'type', 'tabindex', 'aria-label', 'aria-checked', 'data-testid']) {
    try {
      const value = el.getAttribute ? el.getAttribute(name) : '';
      if (value) {
        attrs[name] = String(value);
      }
    } catch (error) {
    }
  }
  return {
    ok: true,
    tag: String(el.tagName || '').toLowerCase(),
    text: String(el.innerText || el.textContent || '').trim().slice(0, 240),
    role: String((el.getAttribute && el.getAttribute('role')) || '').trim(),
    title: String((el.getAttribute && el.getAttribute('title')) || '').trim(),
    name: String((el.getAttribute && el.getAttribute('name')) || '').trim(),
    id: String(el.id || '').trim(),
    className: String(el.className || '').trim().slice(0, 240),
    type: String((el.getAttribute && el.getAttribute('type')) || '').trim(),
    ariaLabel: String((el.getAttribute && el.getAttribute('aria-label')) || '').trim(),
    ariaChecked: String((el.getAttribute && el.getAttribute('aria-checked')) || '').trim(),
    rect: (typeof el.getBoundingClientRect === 'function')
      ? {
          x: Number(el.getBoundingClientRect().x || 0),
          y: Number(el.getBoundingClientRect().y || 0),
          width: Number(el.getBoundingClientRect().width || 0),
          height: Number(el.getBoundingClientRect().height || 0),
        }
      : null,
    attributes: attrs,
    focusChain,
  };
} catch (error) {
  return {ok: false, reason: String((error && error.message) || error || 'unknown_error')};
}
            """,
            timeout=4,
        )
    except Exception as error:
        return {'ok': False, 'reason': str(error)}

    if not isinstance(result, dict):
        return {'ok': False, 'reason': 'invalid_result'}

    attrs_raw = result.get('attributes')
    attrs: dict[str, str] = {}
    if isinstance(attrs_raw, dict):
        for key, value in attrs_raw.items():
            key_text = str(key or '').strip()
            value_text = str(value or '').strip()
            if key_text and value_text:
                attrs[key_text] = value_text[:240]

    focus_chain_raw = result.get('focusChain')
    focus_chain: list[dict[str, Any]] = []
    if isinstance(focus_chain_raw, list):
        for item in focus_chain_raw[:6]:
            if not isinstance(item, dict):
                continue
            chain_attrs_raw = item.get('attributes')
            chain_attrs: dict[str, str] = {}
            if isinstance(chain_attrs_raw, dict):
                for key, value in chain_attrs_raw.items():
                    key_text = str(key or '').strip()
                    value_text = str(value or '').strip()
                    if key_text and value_text:
                        chain_attrs[key_text] = value_text[:240]
            focus_chain.append(
                {
                    'tag': str(item.get('tag') or '').strip().lower(),
                    'text': str(item.get('text') or '').strip()[:160],
                    'attributes': chain_attrs,
                }
            )

    rect_raw = result.get('rect')
    rect: dict[str, float] = {}
    if isinstance(rect_raw, dict):
        for key in ('x', 'y', 'width', 'height'):
            try:
                rect[key] = float(rect_raw.get(key) or 0.0)
            except Exception:
                rect[key] = 0.0

    return {
        'ok': bool(result.get('ok')),
        'reason': str(result.get('reason') or '').strip(),
        'tag': str(result.get('tag') or '').strip().lower(),
        'text': str(result.get('text') or '').strip()[:240],
        'role': str(result.get('role') or '').strip().lower(),
        'title': str(result.get('title') or '').strip()[:240],
        'name': str(result.get('name') or '').strip()[:240],
        'id': str(result.get('id') or '').strip()[:240],
        'className': str(result.get('className') or '').strip()[:240],
        'type': str(result.get('type') or '').strip().lower(),
        'ariaLabel': str(result.get('ariaLabel') or '').strip()[:240],
        'ariaChecked': str(result.get('ariaChecked') or '').strip().lower(),
        'rect': rect,
        'attributes': attrs,
        'focusChain': focus_chain,
    }


def _challenge_focus_matches_checkbox(summary: dict[str, Any]) -> bool:
    if not isinstance(summary, dict) or not bool(summary.get('ok')):
        return False

    pieces: list[str] = [
        str(summary.get('tag') or ''),
        str(summary.get('role') or ''),
        str(summary.get('title') or ''),
        str(summary.get('name') or ''),
        str(summary.get('id') or ''),
        str(summary.get('className') or ''),
        str(summary.get('type') or ''),
        str(summary.get('ariaLabel') or ''),
        str(summary.get('ariaChecked') or ''),
        str(summary.get('text') or ''),
    ]
    attrs = summary.get('attributes')
    if isinstance(attrs, dict):
        for key, value in attrs.items():
            pieces.append(f'{key}={value}')
    focus_chain = summary.get('focusChain')
    if isinstance(focus_chain, list):
        for item in focus_chain:
            if not isinstance(item, dict):
                continue
            pieces.append(str(item.get('tag') or ''))
            pieces.append(str(item.get('text') or ''))
            chain_attrs = item.get('attributes')
            if isinstance(chain_attrs, dict):
                for key, value in chain_attrs.items():
                    pieces.append(f'{key}={value}')

    merged = ' '.join(part for part in pieces if part).lower()
    if not merged:
        return False
    if 'cloudflare' in merged and any(token in merged for token in ('checkbox', 'challenge', 'security', 'verify', 'verification', 'widget', 'turnstile')):
        return True
    if 'turnstile' in merged:
        return True
    if 'checkbox' in merged and any(token in merged for token in ('security', 'verify', 'verification', 'challenge')):
        return True
    rect = summary.get('rect')
    rect_width = 0.0
    rect_height = 0.0
    if isinstance(rect, dict):
        try:
            rect_width = float(rect.get('width') or 0.0)
        except Exception:
            rect_width = 0.0
        try:
            rect_height = float(rect.get('height') or 0.0)
        except Exception:
            rect_height = 0.0
    if (
        str(summary.get('tag') or '').strip().lower() in {'div', 'iframe'}
        and (not str(summary.get('text') or '').strip())
        and rect_width >= 12.0
        and rect_height >= 12.0
    ):
        return True
    return False


def _format_challenge_focus_summary(summary: dict[str, Any]) -> str:
    if not isinstance(summary, dict):
        return '无摘要'
    parts: list[str] = []
    for key in ('tag', 'role', 'title', 'name', 'id', 'type', 'ariaLabel', 'ariaChecked'):
        value = str(summary.get(key) or '').strip()
        if value:
            parts.append(f'{key}={value}')
    text = str(summary.get('text') or '').strip()
    if text:
        parts.append(f'text={text[:80]}')
    rect = summary.get('rect')
    if isinstance(rect, dict):
        try:
            width = float(rect.get('width') or 0.0)
            height = float(rect.get('height') or 0.0)
            x = float(rect.get('x') or 0.0)
            y = float(rect.get('y') or 0.0)
            parts.append(f'rect=({x:.0f},{y:.0f},{width:.0f},{height:.0f})')
        except Exception:
            pass
    focus_chain = summary.get('focusChain')
    if isinstance(focus_chain, list) and focus_chain:
        chain_text = ' > '.join(
            str(item.get('tag') or '').strip()
            for item in focus_chain
            if isinstance(item, dict) and str(item.get('tag') or '').strip()
        )
        if chain_text:
            parts.append(f'focusChain={chain_text}')
    return '，'.join(parts) if parts else '无摘要'


def _resolve_challenge_click_point(summary: dict[str, Any]) -> tuple[float, float] | None:
    if not isinstance(summary, dict) or not bool(summary.get('ok')):
        return None
    rect = summary.get('rect')
    if not isinstance(rect, dict):
        return None
    try:
        x = float(rect.get('x') or 0.0)
        y = float(rect.get('y') or 0.0)
        width = float(rect.get('width') or 0.0)
        height = float(rect.get('height') or 0.0)
    except Exception:
        return None
    if width < 8.0 or height < 8.0:
        return None

    click_x = x + (width / 2.0)
    click_y = y + (height / 2.0)
    tag = str(summary.get('tag') or '').strip().lower()
    text = str(summary.get('text') or '').strip()
    if tag in {'div', 'iframe'} and (not text) and width >= max(80.0, height * 2.2):
        click_x = x + min(max(18.0, height * 0.48), max(22.0, width * 0.18))
    return (round(click_x, 2), round(click_y, 2))


def _try_click_focused_challenge_control(
    tab: Any,
    *,
    focus_summary: dict[str, Any],
    trace: _TraceWriter,
    log: Any,
    loop: asyncio.AbstractEventLoop,
    attempt: int,
) -> bool:
    actions = getattr(tab, 'actions', None)
    move_to_fn = getattr(actions, 'move_to', None)
    if not callable(move_to_fn):
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'challenge_auto_pointer_click',
                'attempt': int(attempt),
                'result': 'skipped',
                'reason': 'actions_move_to_missing',
            }
        )
        _emit_log_sync(loop, log, 'warn', '��Codex OAuth��Cloudflare ҳ���Զ��ָ�����ʧ�ܣ���ǰ��ǩҳ��֧�� actions.move_to��')
        return False

    click_point = _resolve_challenge_click_point(focus_summary)
    if click_point is None:
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'challenge_auto_pointer_click',
                'attempt': int(attempt),
                'result': 'skipped',
                'reason': 'click_point_missing',
                'focusSummary': focus_summary,
            }
        )
        return False

    click_x, click_y = click_point
    try:
        move_to_fn((click_x, click_y), duration=0.18).click()
    except Exception as error:
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'challenge_auto_pointer_click',
                'attempt': int(attempt),
                'result': 'error',
                'error': str(error),
                'clickPoint': {'x': click_x, 'y': click_y},
            }
        )
        _emit_log_sync(loop, log, 'warn', f'��Codex OAuth��Cloudflare ҳ���Զ��ָ�����ʧ�ܣ�{error}')
        return False

    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'challenge_auto_pointer_click',
            'attempt': int(attempt),
            'result': 'sent',
            'clickPoint': {'x': click_x, 'y': click_y},
            'focusSummary': focus_summary,
        }
    )
    _emit_log_sync(
        loop,
        log,
        'info',
        f'��Codex OAuth����⵽ Cloudflare challenge ����δ��ͨ�����ѶԽ��㿪��ִ�ж���ָ������� point=({click_x:.0f}, {click_y:.0f})��',
    )
    return True


def _try_press_tab_enter_on_challenge(
    tab: Any,
    *,
    trace: _TraceWriter,
    log: Any,
    loop: asyncio.AbstractEventLoop,
    attempt: int,
) -> bool:
    actions = getattr(tab, 'actions', None)
    type_fn = getattr(actions, 'type', None)
    if not callable(type_fn):
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'challenge_auto_tab_enter',
                'attempt': int(attempt),
                'result': 'skipped',
                'reason': 'actions_type_missing',
            }
        )
        _emit_log_sync(loop, log, 'warn', '【Codex OAuth】Cloudflare 页面自动执行 Tab + Enter 失败：当前标签页不支持 actions.type。')
        return False

    tab_key = getattr(Keys, 'TAB', '\ue004') if Keys is not None else '\ue004'
    enter_key = getattr(Keys, 'ENTER', '\ue007') if Keys is not None else '\ue007'
    max_tab_presses = max(1, int(_CHALLENGE_AUTO_TAB_PRESS_MAX))

    try:
        try:
            tab.run_js(
                """
try {
  window.focus();
  if (document.body && typeof document.body.focus === 'function') {
    document.body.focus();
  }
  if (document.documentElement && typeof document.documentElement.focus === 'function') {
    document.documentElement.focus();
  }
  return true;
} catch (error) {
  return false;
}
                """,
                timeout=3,
            )
        except Exception:
            pass

        matched_focus_summary: dict[str, Any] | None = None
        for focus_index in range(1, max_tab_presses + 1):
            type_fn(tab_key, interval=0.2)
            time.sleep(0.35)
            focus_summary = _read_challenge_active_element_summary(tab)
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'challenge_auto_tab_focus',
                    'attempt': int(attempt),
                    'focusIndex': int(focus_index),
                    'focusSummary': focus_summary,
                }
            )
            if _challenge_focus_matches_checkbox(focus_summary):
                matched_focus_summary = focus_summary
                _emit_log_sync(
                    loop,
                    log,
                    'info',
                    f'【Codex OAuth】Cloudflare 页面第 {int(focus_index)} 次 Tab 后已选中 challenge 控件：{_format_challenge_focus_summary(focus_summary)}',
                )
                break

        if matched_focus_summary is None:
            trace.write(
                {
                    'ts': _iso_now(),
                    'stage': 'challenge_auto_tab_enter',
                    'attempt': int(attempt),
                    'result': 'skipped',
                    'reason': 'challenge_focus_not_found',
                }
            )
            _emit_log_sync(
                loop,
                log,
                'warn',
                f'【Codex OAuth】Cloudflare 页面自动执行 Tab + Enter 失败：连续 {int(max_tab_presses)} 次 Tab 后仍未选中 challenge 控件。',
            )
            return False

        type_fn(enter_key, interval=0.2)
    except Exception as error:
        trace.write(
            {
                'ts': _iso_now(),
                'stage': 'challenge_auto_tab_enter',
                'attempt': int(attempt),
                'result': 'error',
                'error': str(error),
            }
        )
        _emit_log_sync(loop, log, 'warn', f'【Codex OAuth】Cloudflare 页面自动执行 Tab + Enter 失败：{error}')
        return False

    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'challenge_auto_tab_enter',
            'attempt': int(attempt),
            'result': 'sent',
            'maxTabPresses': int(max_tab_presses),
        }
    )
    _emit_log_sync(loop, log, 'info', f'【Codex OAuth】检测到 Cloudflare/安全验证页面，已在选中 challenge 控件后执行 Enter，第 {int(attempt)} 次自动尝试。')
    return True


def _is_retryable_auth_error_snapshot(snapshot: dict[str, Any]) -> bool:
    url = _sanitize_url_for_log(str(snapshot.get('url') or '')).lower()
    title = str(snapshot.get('title') or '').lower()
    body = str(snapshot.get('bodyText') or '').lower()
    buttons = ' '.join(str(item or '').lower() for item in (snapshot.get('buttonTexts') or []))
    merged = '\n'.join([title, body, buttons])
    if 'auth.openai.com' not in url:
        return False
    has_error_marker = any(marker in merged for marker in _RETRYABLE_ERROR_TEXT_MARKERS)
    has_retry_button = any(marker in buttons for marker in _RETRYABLE_ERROR_BUTTON_TEXTS)
    login_like_url = any(token in url for token in ('/log-in', '/login', '/authorize'))
    return bool(has_error_marker and (has_retry_button or login_like_url))


def _is_chatgpt_home_workspace_switch_snapshot(snapshot: dict[str, Any]) -> bool:
    url = _sanitize_url_for_log(str(snapshot.get('url') or '')).lower()
    body = str(snapshot.get('bodyText') or '').lower()
    buttons = ' '.join(str(item or '').lower() for item in (snapshot.get('buttonTexts') or []))
    frames = ' '.join(str(item or '').lower() for item in (snapshot.get('frameUrls') or []))
    merged = '\n'.join([body, buttons, frames])
    if 'chatgpt.com' not in url:
        return False
    return any(marker in merged for marker in _CHATGPT_HOME_WORKSPACE_TEXT_MARKERS)


def _is_openai_marketing_home_snapshot(snapshot: dict[str, Any]) -> bool:
    url = _sanitize_url_for_log(str(snapshot.get('url') or '')).strip()
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    host = str(parsed.netloc or '').strip().lower()
    if host not in {'openai.com', 'www.openai.com'}:
        return False
    title = str(snapshot.get('title') or '').lower()
    body = str(snapshot.get('bodyText') or '').lower()
    buttons = ' '.join(str(item or '').lower() for item in (snapshot.get('buttonTexts') or []))
    merged = '\n'.join([title, body, buttons])
    return any(marker in merged for marker in _OPENAI_MARKETING_HOME_TEXT_MARKERS)


def _is_codex_workspace_consent_snapshot(snapshot: dict[str, Any]) -> bool:
    """
    功能目的：
        识别 Codex 专用 consent 页面，并统一归入工作空间选择阶段。

    说明：
        - 真实页面虽然走的是 `/sign-in-with-chatgpt/codex/consent` 路径，
          但主体动作是“优先选择非个人工作空间；若没有则允许个人继续”；
        - 继续沿用 `authorize` 分支会直接点击 Continue，跳过工作空间选择，
          从而把当前账号错误地推进到个人态。
    """

    url = _sanitize_url_for_log(str(snapshot.get('url') or '')).lower()
    return _is_codex_consent_url(url)


def _infer_codex_oauth_stage(snapshot: dict[str, Any], callback_url_hints: tuple[str, ...]) -> str:
    url = _sanitize_url_for_log(str(snapshot.get('url') or '')).lower()
    title = str(snapshot.get('title') or '').lower()
    body = str(snapshot.get('bodyText') or '').lower()
    buttons = ' '.join(str(item or '').lower() for item in (snapshot.get('buttonTexts') or []))
    frames = ' '.join(str(item or '').lower() for item in (snapshot.get('frameUrls') or []))
    merged = '\n'.join([url, title, body, buttons, frames])
    content_merged = '\n'.join([body, buttons, frames])

    if any(str(hint or '').lower() in url for hint in callback_url_hints):
        return 'callback'
    if CALLBACK_PATH in url and ('localhost' in url or '127.0.0.1' in url):
        return 'callback'
    if _is_retryable_auth_error_snapshot(snapshot):
        return 'retryable_error'
    if 'auth.openai.com/error' in url or ('auth.openai.com' in url and '/error' in url):
        return 'error'
    if any(marker in content_merged for marker in _ERROR_TEXT_MARKERS):
        return 'error'
    if any(marker in merged for marker in _BLOCK_PAGE_MARKERS):
        return 'challenge'
    if any(marker in merged for marker in _LOADING_PAGE_MARKERS):
        return 'loading'
    if _is_auth_add_phone_url(url) or '/add-phone' in url:
        return 'add_phone'
    if '/about-you' in url:
        return 'profile'
    if '/create-account' in url:
        return 'signup'
    if bool(snapshot.get('passwordVisible')):
        return 'password'
    if bool(snapshot.get('otpVisible')) or any(marker in content_merged for marker in _OTP_TEXT_MARKERS):
        return 'otp'
    if bool(snapshot.get('emailVisible')):
        return 'email'
    if '/log-in' in url or 'welcome back' in title or '欢迎回来' in title:
        return 'email'
    if _is_codex_workspace_consent_snapshot(snapshot):
        return 'workspace'
    if '/sign-in-with-chatgpt/' in url:
        return 'authorize'
    if any(marker in content_merged for marker in _CHATGPT_ROLE_PROMPT_TEXT_MARKERS):
        return 'chatgpt_role_prompt'
    if any(marker in content_merged for marker in _CHATGPT_WORK_APPS_TEXT_MARKERS):
        return 'chatgpt_work_apps'
    if _is_chatgpt_home_workspace_switch_snapshot(snapshot):
        return 'workspace'
    if _is_openai_marketing_home_snapshot(snapshot):
        return 'openai_home'
    if any(marker in content_merged for marker in _WORKSPACE_TEXT_MARKERS):
        return 'workspace'
    if any(marker in content_merged for marker in _AUTHORIZE_TEXT_MARKERS):
        return 'authorize'
    return 'unknown'


def _capture_codex_debug_snapshot_sync(
    *,
    tab: Any,
    log: Any,
    loop: asyncio.AbstractEventLoop,
    trace: _TraceWriter,
    tag: str,
    callback_url_hints: tuple[str, ...] = (),
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    snapshot = _collect_page_snapshot(tab)
    stage = _infer_codex_oauth_stage(snapshot, callback_url_hints)
    debug_dir = (_repo_root() / 'tmp' / 'codex_oauth_debug').resolve()
    debug_dir.mkdir(parents=True, exist_ok=True)
    filename = f"codex_debug_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{_safe_debug_tag(tag)}.png"
    screenshot_path = debug_dir / filename
    saved = _save_debug_screenshot(tab, screenshot_path)
    frame_urls = snapshot.get('frameUrls') or []
    frame_text = ', '.join(str(item) for item in frame_urls[:3])
    if len(frame_urls) > 3:
        frame_text += ', …'
    try:
        extra_text = json.dumps(extra or {}, ensure_ascii=False, sort_keys=True)
    except Exception:
        extra_text = str(extra or '')
    extra_text = _compress_debug_text(extra_text, limit=240)
    body_excerpt = _compress_debug_text(snapshot.get('bodyText') or '', limit=520)

    _emit_log_sync(
        loop,
        log,
        'info',
        '【Codex OAuth/调试】快照：'
        f'tag={tag}，stage={stage}，title={_compress_debug_text(snapshot.get("title") or "", limit=120)}，'
        f'url={_sanitize_url_for_log(snapshot.get("url") or "")}，frames={len(frame_urls)}，'
        f'截图={str(screenshot_path) if saved else "未保存"}，extra={extra_text}',
    )
    _emit_log_sync(
        loop,
        log,
        'info',
        '【Codex OAuth/调试】页面摘要：'
        f'tag={tag}，email_input={bool(snapshot.get("emailVisible"))}，'
        f'password_input={bool(snapshot.get("passwordVisible"))}，otp_input={bool(snapshot.get("otpVisible"))}，'
        f'action_button={bool(snapshot.get("buttonTexts"))}，frame_urls={frame_text or "无"}，body={body_excerpt}',
    )
    trace.write(
        {
            'ts': _iso_now(),
            'stage': 'debug_snapshot',
            'tag': str(tag or ''),
            'url': _sanitize_url_for_log(snapshot.get('url') or ''),
            'title': str(snapshot.get('title') or ''),
            'inferredStage': stage,
            'emailVisible': bool(snapshot.get('emailVisible')),
            'passwordVisible': bool(snapshot.get('passwordVisible')),
            'otpVisible': bool(snapshot.get('otpVisible')),
            'buttonTexts': list(snapshot.get('buttonTexts') or []),
            'frameUrls': list(snapshot.get('frameUrls') or []),
            'screenshotPath': str(screenshot_path) if saved else '',
            'extra': dict(extra or {}),
        }
    )
    return snapshot


def _js_set_first_visible_input(tab: Any, selectors: tuple[str, ...], value: str) -> bool:
    try:
        result = tab.run_js(_SET_INPUT_JS, {'selectors': list(selectors), 'value': str(value or '')}, timeout=8)
        return bool(isinstance(result, dict) and result.get('ok'))
    except Exception:
        return False


def _js_click_first_matching_text_result(
    tab: Any,
    texts: tuple[str, ...],
    *,
    max_scroll_passes: int = 0,
    fallback_to_primary_action: bool = False,
) -> dict[str, Any]:
    try:
        result = tab.run_js(
            _CLICK_TEXT_JS,
            {
                'patterns': list(texts),
                'maxScrollPasses': int(max(0, max_scroll_passes)),
                'fallbackToPrimaryAction': bool(fallback_to_primary_action),
            },
            timeout=8,
        )
        return result if isinstance(result, dict) else {'ok': False}
    except Exception as error:
        return {'ok': False, 'error': str(error)}


def _js_click_first_matching_text(
    tab: Any,
    texts: tuple[str, ...],
    *,
    max_scroll_passes: int = 0,
    fallback_to_primary_action: bool = False,
) -> bool:
    return bool(
        _js_click_first_matching_text_result(
            tab,
            texts,
            max_scroll_passes=max_scroll_passes,
            fallback_to_primary_action=fallback_to_primary_action,
        ).get('ok')
    )


def _js_click_matching_text_with_retry(
    tab: Any,
    texts: tuple[str, ...],
    delays: tuple[float, ...] = (0.0,),
    *,
    max_scroll_passes: int = 0,
    fallback_to_primary_action: bool = False,
) -> dict[str, Any]:
    last_result: dict[str, Any] = {'ok': False}
    effective_delays = delays or (0.0,)
    for index, delay in enumerate(effective_delays):
        if index > 0 and float(delay) > 0:
            time.sleep(float(delay))
        current = _js_click_first_matching_text_result(
            tab,
            texts,
            max_scroll_passes=max_scroll_passes,
            fallback_to_primary_action=fallback_to_primary_action,
        )
        if isinstance(current, dict):
            last_result = current
        if bool(last_result.get('ok')):
            return last_result
    return last_result


def _js_scroll_page_for_continue(tab: Any, *, texts: tuple[str, ...], passes: int = 1) -> dict[str, Any]:
    """
    功能目的：
        在工作空间选择之后主动向下滚动页面，尽快把 Continue/继续按钮滚入可见区域。
    """

    try:
        result = tab.run_js(
            _SCROLL_PAGE_FOR_CONTINUE_JS,
            {
                'patterns': list(texts),
                'passes': int(max(1, passes)),
                'minStep': 240,
                'stepRatio': 0.9,
            },
            timeout=6,
        )
        return result if isinstance(result, dict) else {'ok': False, 'reason': 'invalid_result'}
    except Exception as error:
        return {'ok': False, 'reason': str(error)}


def _js_click_matching_text_after_workspace_selection(
    tab: Any,
    texts: tuple[str, ...],
    *,
    max_scroll_passes: int,
    fallback_to_primary_action: bool = False,
    delays: tuple[float, ...] = _WORKSPACE_POST_SELECT_SCROLL_RETRY_DELAYS_SEC,
) -> dict[str, Any]:
    """
    功能目的：
        在选中非个人空间后，立刻开始下滑页面并查找 Continue/继续。

    说明：
        - 选中非个人空间后，先立刻执行一次“朝 Continue/继续 方向滚动”的动作，
          再尝试点击，避免页面刚重排时出现“这一轮没滚、下一轮才滚”的不稳定体验；
        - 若未命中，则继续按“短等待 -> 再滚 -> 再找按钮”的节奏快进重试。
    """

    last_result: dict[str, Any] = {'ok': False, 'reason': 'continue_not_found_after_workspace_selection'}
    effective_delays = delays or (0.0,)
    for index, delay in enumerate(effective_delays):
        if float(delay) > 0:
            time.sleep(float(delay))
        _js_scroll_page_for_continue(
            tab,
            texts=texts,
            passes=_WORKSPACE_POST_SELECT_SCROLL_PASSES_PER_ROUND,
        )
        current = _js_click_first_matching_text_result(
            tab,
            texts,
            max_scroll_passes=0 if index == 0 else max_scroll_passes,
            fallback_to_primary_action=fallback_to_primary_action,
        )
        if isinstance(current, dict):
            last_result = current
        if bool(last_result.get('ok')):
            return last_result
    return last_result


def _is_workspace_selection_confirmed(result: dict[str, Any]) -> bool:
    if not isinstance(result, dict) or not bool(result.get('ok')):
        return False
    if bool(result.get('selectionConfirmed')) or bool(result.get('continueReady')):
        return True
    if bool(result.get('alreadyChecked')):
        return True
    confidence = str(result.get('signalConfidence') or '').strip().lower()
    selection_kind = str(result.get('selectionKind') or '').strip()
    if selection_kind and confidence in {'high', 'medium'}:
        return True
    return False


def _workspace_continue_visible_in_snapshot(snapshot: dict[str, Any]) -> bool:
    if not isinstance(snapshot, dict):
        return False
    button_texts = tuple(str(item or '').strip().lower() for item in (snapshot.get('buttonTexts') or []) if str(item or '').strip())
    if not button_texts:
        return False
    patterns = tuple(
        str(item or '').strip().lower()
        for item in (_WORKSPACE_BUTTON_TEXTS + _AUTHORIZE_BUTTON_TEXTS + _GENERIC_CONTINUE_TEXTS)
        if str(item or '').strip()
    )
    blocked = ('cancel', 'privacy', 'terms', '取消', '隐私', '条款')
    for text in button_texts:
        if any(flag in text for flag in blocked):
            continue
        if any(pattern in text for pattern in patterns):
            return True
    return False


def _should_attempt_workspace_continue(select_result: dict[str, Any], snapshot: dict[str, Any]) -> bool:
    if _is_workspace_selection_confirmed(select_result):
        return True
    if not isinstance(select_result, dict) or not bool(select_result.get('ok')):
        return False
    if not bool(select_result.get('clicked')):
        return False
    return _workspace_continue_visible_in_snapshot(snapshot)


def _js_select_non_personal_workspace(
    tab: Any,
    *,
    expected_email: str = '',
    prepare_real_click: bool = False,
) -> dict[str, Any]:
    try:
        result = tab.run_js(
            _SELECT_NON_PERSONAL_WORKSPACE_JS,
            {
                'personalKeywords': _build_workspace_personal_keywords(expected_email),
                'continueKeywords': list(_WORKSPACE_BUTTON_TEXTS) + list(_AUTHORIZE_BUTTON_TEXTS),
                'prepareRealClick': bool(prepare_real_click),
            },
            timeout=8,
        )
        return result if isinstance(result, dict) else {'ok': False, 'reason': 'invalid_result'}
    except Exception as error:
        return {'ok': False, 'reason': str(error)}


def _click_workspace_target_by_point(tab: Any, prepared_result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(prepared_result, dict):
        return {'ok': False, 'reason': 'invalid_prepare_result'}
    if not bool(prepared_result.get('realClickReady')):
        return {'ok': False, 'reason': str(prepared_result.get('reason') or 'real_click_not_ready')}
    try:
        x = float(prepared_result.get('clickPointX') or 0.0)
        y = float(prepared_result.get('clickPointY') or 0.0)
    except Exception:
        return {'ok': False, 'reason': 'invalid_click_point'}
    if x <= 0 or y <= 0:
        return {'ok': False, 'reason': 'invalid_click_point'}
    try:
        tab.actions.move_to((x, y), duration=0.18).click()
        return {
            'ok': True,
            'x': x,
            'y': y,
            'text': str(prepared_result.get('clickTargetText') or prepared_result.get('text') or '').strip(),
            'clickTargetKind': str(prepared_result.get('clickTargetKind') or '').strip(),
            'selectionMethod': 'drission_real_click',
        }
    except Exception as error:
        return {'ok': False, 'reason': f'real_click_failed: {error}'}


def _wait_workspace_real_click_settle(
    tab: Any,
    *,
    before_snapshot: dict[str, Any],
    timeout_seconds: float = _WORKSPACE_REAL_CLICK_SETTLE_TIMEOUT_SEC,
) -> dict[str, Any]:
    before_url = str(before_snapshot.get('url') or '').strip()
    deadline = time.time() + max(0.8, float(timeout_seconds or 0.0))
    last_snapshot = before_snapshot if isinstance(before_snapshot, dict) else {}
    last_stage = str(_infer_codex_oauth_stage(last_snapshot, tuple())).strip().lower() if last_snapshot else ''
    last_url = before_url
    continue_ready = _workspace_continue_visible_in_snapshot(last_snapshot)

    while time.time() < deadline:
        time.sleep(_WORKSPACE_REAL_CLICK_POLL_INTERVAL_SEC)
        snapshot = _collect_page_snapshot(tab)
        last_snapshot = snapshot if isinstance(snapshot, dict) else {}
        last_stage = str(_infer_codex_oauth_stage(last_snapshot, tuple())).strip().lower()
        last_url = str(last_snapshot.get('url') or '').strip()
        continue_ready = _workspace_continue_visible_in_snapshot(last_snapshot)
        if continue_ready:
            return {
                'changed': True,
                'reason': 'continue_visible',
                'stage': last_stage,
                'url': last_url,
                'continueReady': True,
            }
        if last_stage and last_stage not in {'workspace', 'loading'}:
            return {
                'changed': True,
                'reason': 'stage_advanced',
                'stage': last_stage,
                'url': last_url,
                'continueReady': False,
            }
        if last_url and before_url and last_url != before_url:
            return {
                'changed': True,
                'reason': 'url_changed',
                'stage': last_stage,
                'url': last_url,
                'continueReady': False,
            }

    return {
        'changed': False,
        'reason': 'timeout',
        'stage': last_stage,
        'url': last_url,
        'continueReady': bool(continue_ready),
    }


def _select_non_personal_workspace_with_real_click(tab: Any, *, expected_email: str = '') -> dict[str, Any]:
    before_snapshot = _collect_page_snapshot(tab)
    prepared = _js_select_non_personal_workspace(
        tab,
        expected_email=expected_email,
        prepare_real_click=True,
    )
    if _is_workspace_selection_confirmed(prepared):
        return dict(prepared)
    if not isinstance(prepared, dict) or not bool(prepared.get('ok')):
        fallback = _js_select_non_personal_workspace(tab, expected_email=expected_email)
        if isinstance(fallback, dict) and bool(fallback.get('ok')):
            fallback['selectionMethod'] = 'js_click_fallback'
            return fallback
        return prepared if isinstance(prepared, dict) else {'ok': False, 'reason': 'prepare_real_click_failed'}

    click_result = _click_workspace_target_by_point(tab, prepared)
    merged = dict(prepared)
    merged['clicked'] = bool(click_result.get('ok'))
    merged['selectionMethod'] = str(click_result.get('selectionMethod') or 'drission_real_click')
    merged['realClick'] = dict(click_result)
    if not bool(click_result.get('ok')):
        fallback = _js_select_non_personal_workspace(tab, expected_email=expected_email)
        if isinstance(fallback, dict) and bool(fallback.get('ok')):
            fallback['selectionMethod'] = 'js_click_fallback'
            return fallback
        merged['ok'] = False
        merged['reason'] = str(click_result.get('reason') or 'real_click_failed')
        return merged

    settle = _wait_workspace_real_click_settle(tab, before_snapshot=before_snapshot)
    merged['postClickSettled'] = True
    merged['postClickStage'] = str(settle.get('stage') or '').strip()
    merged['postClickUrl'] = str(settle.get('url') or '').strip()
    merged['continueReady'] = bool(merged.get('continueReady')) or bool(settle.get('continueReady'))

    if str(settle.get('reason') or '').strip() == 'stage_advanced':
        merged['selectionConfirmed'] = True
        merged['reason'] = 'advanced_after_real_click'
        return merged

    verification = _js_select_non_personal_workspace(
        tab,
        expected_email=expected_email,
        prepare_real_click=True,
    )
    if isinstance(verification, dict):
        merged['verification'] = dict(verification)
        if _is_workspace_selection_confirmed(verification):
            confirmed = dict(verification)
            confirmed['clicked'] = True
            confirmed['selectionMethod'] = 'drission_real_click'
            confirmed['realClick'] = dict(click_result)
            confirmed['postClickSettled'] = True
            confirmed['postClickStage'] = str(settle.get('stage') or '').strip()
            confirmed['postClickUrl'] = str(settle.get('url') or '').strip()
            confirmed['continueReady'] = bool(confirmed.get('continueReady')) or bool(settle.get('continueReady'))
            return confirmed

    return merged


def _build_workspace_personal_keywords(expected_email: str = "") -> list[str]:
    keywords: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        token = str(value or '').strip().lower()
        if not token or token in seen:
            return
        seen.add(token)
        keywords.append(token)

    for item in _CHATGPT_HOME_WORKSPACE_PERSONAL_KEYWORDS:
        _add(str(item))

    safe_email = str(expected_email or '').strip().lower()
    if '@' not in safe_email:
        return keywords

    local_part = safe_email.split('@', 1)[0].strip()
    if not local_part:
        return keywords

    _add(local_part)
    _add(f'@{local_part}')
    for item in re.split(r'[^0-9a-z]+', local_part):
        if len(item) >= 3:
            _add(item)
    collapsed = re.sub(r'[^0-9a-z]+', '', local_part)
    if len(collapsed) >= 3:
        _add(collapsed)
    return keywords


def _build_chatgpt_home_workspace_personal_keywords(expected_email: str = "") -> list[str]:
    return _build_workspace_personal_keywords(expected_email)


def _select_non_personal_workspace_with_confirmation(
    tab: Any,
    *,
    is_chatgpt_home_workspace: bool,
    expected_email: str = '',
    delays: tuple[float, ...] = _WORKSPACE_SELECTION_RETRY_DELAYS_SEC,
) -> dict[str, Any]:
    if bool(is_chatgpt_home_workspace):
        def select_fn(current_tab: Any) -> dict[str, Any]:
            return _js_select_non_personal_workspace_from_chatgpt_home(
                current_tab,
                expected_email=expected_email,
            )
    else:
        def select_fn(current_tab: Any) -> dict[str, Any]:
            return _select_non_personal_workspace_with_real_click(
                current_tab,
                expected_email=expected_email,
            )
    last_result: dict[str, Any] = {'ok': False, 'reason': 'workspace_selection_unconfirmed'}
    effective_delays = delays or (0.0,)
    for index, delay in enumerate(effective_delays):
        if index > 0 and float(delay) > 0:
            time.sleep(float(delay))
        current = select_fn(tab)
        if isinstance(current, dict):
            last_result = current
        if _is_workspace_selection_confirmed(last_result):
            return last_result
    return last_result


def _js_select_non_personal_workspace_from_chatgpt_home(tab: Any, *, expected_email: str = '') -> dict[str, Any]:
    try:
        result = tab.run_js(
            _SELECT_CHATGPT_HOME_NON_PERSONAL_WORKSPACE_JS,
            {
                'personalKeywords': _build_chatgpt_home_workspace_personal_keywords(expected_email),
                'menuBlockedKeywords': list(_CHATGPT_HOME_WORKSPACE_MENU_BLOCKED_KEYWORDS),
                'anchorBlockedKeywords': ['invite', '邀请团队成员', 'new chat', 'search', '搜索聊天'],
            },
            timeout=8,
        )
        return result if isinstance(result, dict) else {'ok': False, 'reason': 'invalid_result'}
    except Exception as error:
        return {'ok': False, 'reason': str(error)}


def _handle_workspace_stage_actions(
    tab: Any,
    snapshot: dict[str, Any],
    *,
    expected_email: str = '',
) -> dict[str, Any]:
    """
    功能目的：
        统一处理 Codex OAuth 的工作空间选择阶段。

    说明：
        - 先尝试选择非个人空间；
        - 选择成功后，立即进入“下滑找 Continue/继续”的快进链路。
    """

    is_chatgpt_home_workspace = _is_chatgpt_home_workspace_switch_snapshot(snapshot)
    select_res = _select_non_personal_workspace_with_confirmation(
        tab,
        is_chatgpt_home_workspace=is_chatgpt_home_workspace,
        expected_email=expected_email,
    )

    migration_result: dict[str, Any] = {'ok': False}
    clicked_result: dict[str, Any] = {'ok': False}
    texts = _WORKSPACE_BUTTON_TEXTS + _AUTHORIZE_BUTTON_TEXTS + _GENERIC_CONTINUE_TEXTS
    continue_fallback_ready = _should_attempt_workspace_continue(select_res, snapshot)
    natural_real_click_waited = (
        str(select_res.get('selectionMethod') or '').strip() == 'drission_real_click'
        and bool(select_res.get('postClickSettled'))
    )
    should_fast_continue = bool(select_res.get('clicked')) or bool(continue_fallback_ready)
    if natural_real_click_waited:
        should_fast_continue = bool(select_res.get('continueReady'))
    if should_fast_continue:
        if is_chatgpt_home_workspace:
            migration_result = _js_click_matching_text_with_retry(
                tab,
                _CHATGPT_HOME_MIGRATION_OPTION_TEXTS,
                _FAST_STAGE_BUTTON_RETRY_DELAYS_SEC,
                max_scroll_passes=2,
            )
        clicked_result = _js_click_matching_text_after_workspace_selection(
            tab,
            texts,
            max_scroll_passes=_WORKSPACE_STAGE_CLICK_SCROLL_PASSES,
            fallback_to_primary_action=True,
        )
    return {
        'isChatgptHomeWorkspace': bool(is_chatgpt_home_workspace),
        'select': select_res,
        'migration': migration_result,
        'clicked': clicked_result,
        'continueFallbackReady': bool(continue_fallback_ready),
        'startedFastContinue': bool(should_fast_continue),
    }


def _js_fill_otp_value(tab: Any, code: str) -> bool:
    try:
        result = tab.run_js(
            _FILL_OTP_JS,
            {'code': str(code or '').strip(), 'selectors': list(_OTP_SELECTORS)},
            timeout=8,
        )
        return bool(isinstance(result, dict) and result.get('ok'))
    except Exception:
        return False


def _poll_imap_code_sync(
    *,
    email: str,
    otp_timeout_sec: float,
    otp_interval_sec: float,
    imap_host: str,
    imap_port: int,
    imap_user: str,
    imap_pass: str,
    imap_folder: str,
    imap_latest_n: int,
    imap_auth_type: str,
    imap_oauth_client_id: str,
    imap_oauth_refresh_token: str,
    imap_password_fallback: bool,
    imap_pop3_fallback: bool,
    blocked_codes: set[str],
    not_before_ts: float,
    baseline_uids: Any = (),
    log: Any,
    loop: asyncio.AbstractEventLoop,
) -> str:
    if not _has_imap_otp_credentials(
        use_imap_otp=True,
        imap_user=imap_user,
        imap_pass=imap_pass,
        imap_auth_type=imap_auth_type,
        imap_oauth_client_id=imap_oauth_client_id,
        imap_oauth_refresh_token=imap_oauth_refresh_token,
    ):
        return ''
    single_poll_timeout_sec = min(
        max(3.0, float(_OTP_IMAP_SINGLE_POLL_TIMEOUT_CAP_SEC)),
        max(3.0, float(otp_timeout_sec or 120.0)),
    )
    cfg = Imap2925Config(
        host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
        port=int(imap_port or 993),
        username=str(imap_user or '').strip(),
        password=str(imap_pass or ''),
        auth_type=str(imap_auth_type or 'password').strip() or 'password',
        oauth_client_id=str(imap_oauth_client_id or '').strip(),
        oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
        password_fallback_enabled=bool(imap_password_fallback),
        pop3_fallback_enabled=bool(imap_pop3_fallback),
        folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
        latest_n=max(1, int(imap_latest_n or 10)),
        poll_interval_seconds=max(1.0, float(otp_interval_sec or 3.0)),
        # 单次 IMAP 轮询不要阻塞太久，避免页面已跳到 workspace 时主循环还卡在 OTP 分支。
        poll_timeout_seconds=float(single_poll_timeout_sec),
        not_before_ts=max(0.0, float(not_before_ts or 0.0)),
        # HTTP passwordless 链路同轮可能收到多封验证码，优先扫描最新邮件可减少误取旧码。
        scan_newest_first=True,
        stop_on_not_before_boundary=True,
        baseline_uids=tuple(str(uid or "").strip() for uid in (baseline_uids or ()) if str(uid or "").strip()),
    )
    return str(
        _run_async(
            poll_imap_for_verification_code(
                config=cfg,
                expected_email=str(email or '').strip(),
                keywords=list(_DEFAULT_OTP_KEYWORDS),
                blocked_codes=blocked_codes,
                logInfo=lambda msg: _emit_log_sync(loop, log, 'info', f'【Codex OAuth/IMAP】{msg}'),
                logWarn=lambda msg: _emit_log_sync(loop, log, 'warn', f'【Codex OAuth/IMAP】{msg}'),
            )
        )
        or ''
    ).strip()


def _normalize_imap_profiles_payload(
    profiles_payload: Any,
    *,
    fallback_host: str,
    fallback_port: int,
    fallback_user: str,
    fallback_pass: str,
    fallback_folder: str,
    fallback_latest_n: int,
    fallback_auth_type: str = "password",
    fallback_oauth_client_id: str = "",
    fallback_oauth_refresh_token: str = "",
    fallback_password_fallback: bool = False,
    fallback_pop3_fallback: bool = False,
) -> list[dict[str, Any]]:
    raw: Any = profiles_payload
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            raw = []
        else:
            try:
                raw = json.loads(text)
            except Exception:
                raw = []
    if isinstance(raw, dict):
        candidates = raw.get('profiles') if isinstance(raw.get('profiles'), list) else [raw]
    elif isinstance(raw, list):
        candidates = raw
    else:
        candidates = []

    if not candidates and _has_imap_otp_credentials(
        use_imap_otp=True,
        imap_user=fallback_user,
        imap_pass=fallback_pass,
        imap_auth_type=fallback_auth_type,
        imap_oauth_client_id=fallback_oauth_client_id,
        imap_oauth_refresh_token=fallback_oauth_refresh_token,
    ):
        candidates = [
            {
                'host': fallback_host,
                'port': fallback_port,
                'user': fallback_user,
                'password': fallback_pass,
                'folder': fallback_folder,
                'latest_n': fallback_latest_n,
                'auth_type': fallback_auth_type,
                'oauth_client_id': fallback_oauth_client_id,
                'oauth_refresh_token': fallback_oauth_refresh_token,
                'password_fallback': bool(fallback_password_fallback),
                'pop3_fallback': bool(fallback_pop3_fallback),
            }
        ]

    profiles: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for item in candidates:
        if not isinstance(item, dict):
            continue
        user = str(item.get('user') or item.get('imap_user') or item.get('username') or '').strip()
        password = str(item.get('password') or item.get('imap_pass') or item.get('pass') or '')
        auth_type = str(item.get('auth_type') or item.get('imap_auth_type') or fallback_auth_type or 'password').strip() or 'password'
        oauth_client_id = str(item.get('oauth_client_id') or item.get('imap_oauth_client_id') or fallback_oauth_client_id or '').strip()
        oauth_refresh_token = str(
            item.get('oauth_refresh_token') or item.get('imap_oauth_refresh_token') or fallback_oauth_refresh_token or ''
        ).strip()
        password_fallback = bool(
            item.get('password_fallback')
            if item.get('password_fallback') is not None
            else item.get('imap_password_fallback', fallback_password_fallback)
        )
        pop3_fallback = bool(
            item.get('pop3_fallback')
            if item.get('pop3_fallback') is not None
            else item.get('imap_pop3_fallback', fallback_pop3_fallback)
        )
        if not _has_imap_otp_credentials(
            use_imap_otp=True,
            imap_user=user,
            imap_pass=password,
            imap_auth_type=auth_type,
            imap_oauth_client_id=oauth_client_id,
            imap_oauth_refresh_token=oauth_refresh_token,
        ):
            continue
        host = str(item.get('host') or item.get('imap_host') or fallback_host or 'imap.2925.com').strip() or 'imap.2925.com'
        try:
            port = int(item.get('port') or item.get('imap_port') or fallback_port or 993)
        except Exception:
            port = int(fallback_port or 993)
        folder = str(item.get('folder') or item.get('imap_folder') or fallback_folder or 'Inbox').strip() or 'Inbox'
        try:
            latest_n = int(item.get('latest_n') or item.get('imap_latest_n') or fallback_latest_n or 10)
        except Exception:
            latest_n = int(fallback_latest_n or 10)
        key = (user.lower(), host.lower(), int(port), folder.lower())
        if key in seen:
            continue
        seen.add(key)
        profiles.append(
            {
                'host': host,
                'port': max(1, min(65535, int(port))),
                'user': user,
                'password': password,
                'folder': folder,
                'latest_n': max(1, min(5000, int(latest_n))),
                'auth_type': 'oauth2' if auth_type.lower() == 'oauth2' else 'password',
                'oauth_client_id': oauth_client_id,
                'oauth_refresh_token': oauth_refresh_token,
                'password_fallback': password_fallback,
                'pop3_fallback': pop3_fallback,
                'baseline_uids': tuple(
                    str(uid or '').strip()
                    for uid in (item.get('baseline_uids') or item.get('imap_baseline_uids') or ())
                    if str(uid or '').strip()
                ),
            }
        )
    return profiles


def _poll_imap_code_multi_sync(
    *,
    email: str,
    otp_timeout_sec: float,
    otp_interval_sec: float,
    imap_profiles: list[dict[str, Any]],
    blocked_codes: set[str],
    not_before_ts: float,
    log: Any,
    loop: asyncio.AbstractEventLoop,
) -> str:
    profiles = list(imap_profiles or [])
    if not profiles:
        return ''
    if len(profiles) == 1:
        profile = profiles[0]
        return _poll_imap_code_sync(
            email=email,
            otp_timeout_sec=otp_timeout_sec,
            otp_interval_sec=otp_interval_sec,
            imap_host=str(profile.get('host') or 'imap.2925.com'),
            imap_port=int(profile.get('port') or 993),
            imap_user=str(profile.get('user') or ''),
            imap_pass=str(profile.get('password') or ''),
            imap_folder=str(profile.get('folder') or 'Inbox'),
            imap_latest_n=int(profile.get('latest_n') or 10),
            imap_auth_type=str(profile.get('auth_type') or 'password'),
            imap_oauth_client_id=str(profile.get('oauth_client_id') or ''),
            imap_oauth_refresh_token=str(profile.get('oauth_refresh_token') or ''),
            imap_password_fallback=bool(profile.get('password_fallback')),
            imap_pop3_fallback=bool(profile.get('pop3_fallback')),
            blocked_codes=blocked_codes,
            not_before_ts=not_before_ts,
            baseline_uids=profile.get('baseline_uids') or (),
            log=log,
            loop=loop,
        )

    async def _poll_all() -> str:
        tasks: dict[asyncio.Task[Any], dict[str, Any]] = {}
        single_poll_timeout_sec = min(
            max(3.0, float(_OTP_IMAP_SINGLE_POLL_TIMEOUT_CAP_SEC)),
            max(3.0, float(otp_timeout_sec or 120.0)),
        )
        for index, profile in enumerate(profiles, start=1):
            cfg = Imap2925Config(
                host=str(profile.get('host') or 'imap.2925.com').strip() or 'imap.2925.com',
                port=int(profile.get('port') or 993),
                username=str(profile.get('user') or '').strip(),
                password=str(profile.get('password') or ''),
                auth_type=str(profile.get('auth_type') or 'password').strip() or 'password',
                oauth_client_id=str(profile.get('oauth_client_id') or '').strip(),
                oauth_refresh_token=str(profile.get('oauth_refresh_token') or '').strip(),
                password_fallback_enabled=bool(profile.get('password_fallback')),
                pop3_fallback_enabled=bool(profile.get('pop3_fallback')),
                folder=str(profile.get('folder') or 'Inbox').strip() or 'Inbox',
                latest_n=max(1, int(profile.get('latest_n') or 10)),
                poll_interval_seconds=max(1.0, float(otp_interval_sec or 3.0)),
                poll_timeout_seconds=float(single_poll_timeout_sec),
                not_before_ts=max(0.0, float(not_before_ts or 0.0)),
                scan_newest_first=True,
                stop_on_not_before_boundary=True,
                baseline_uids=tuple(
                    str(uid or "").strip()
                    for uid in (profile.get('baseline_uids') or ())
                    if str(uid or "").strip()
                ),
            )
            if not cfg.is_configured():
                continue
            label = f'{index}/{len(profiles)} {_mask_email(cfg.username)}'
            tasks[
                asyncio.create_task(
                    poll_imap_for_verification_code(
                        config=cfg,
                        expected_email=str(email or '').strip(),
                        keywords=list(_DEFAULT_OTP_KEYWORDS),
                        blocked_codes=blocked_codes,
                        logInfo=lambda msg, label=label: _emit_log_sync(
                            loop, log, 'info', f'【Codex OAuth/IMAP {label}】{msg}'
                        ),
                        logWarn=lambda msg, label=label: _emit_log_sync(
                            loop, log, 'warn', f'【Codex OAuth/IMAP {label}】{msg}'
                        ),
                    )
                )
            ] = profile
        pending = set(tasks)
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    code = str(task.result() or '').strip()
                except Exception:
                    code = ''
                if code:
                    profile = tasks.get(task) or {}
                    _emit_log_sync(
                        loop,
                        log,
                        'info',
                        f'【Codex OAuth/IMAP】多主邮箱已命中：{_mask_email(str(profile.get("user") or ""))}',
                    )
                    for item in pending:
                        item.cancel()
                    return code
        return ''

    return str(_run_async(_poll_all()) or '').strip()


def _run_codex_browser_flow_sync(
    *,
    auth_url: str,
    redirect_uri: str,
    expected_state: str,
    email: str,
    password: str,
    storage_state_path: str,
    headless: bool,
    log: Any,
    loop: asyncio.AbstractEventLoop,
    stop_event: threading.Event,
    callback_url_hints: tuple[str, ...],
    timeout_sec: float,
    otp_timeout_sec: float,
    otp_interval_sec: float,
    mfa_totp_secret: str,
    use_imap_otp: bool,
    use_managed_mail_otp: bool = True,
    managed_mail_provider: str = '',
    managed_mail_jwt: str = '',
    managed_mail_api_base: str = '',
    managed_mail_frontend_base: str = '',
    managed_mail_latest_n: int = 20,
    use_domain_mail_otp: bool = True,
    domain_mail_api_base: str = '',
    domain_mail_domain: str = '',
    domain_mail_token: str = '',
    domain_mail_latest_n: int = 20,
    imap_host: str = 'imap.2925.com',
    imap_port: int = 993,
    imap_user: str = '',
    imap_pass: str = '',
    imap_folder: str = 'Inbox',
    imap_latest_n: int = 10,
    imap_auth_type: str = 'password',
    imap_oauth_client_id: str = '',
    imap_oauth_refresh_token: str = '',
    imap_password_fallback: bool = False,
    imap_pop3_fallback: bool = False,
    imap_profiles_json: str = '',
    trace: _TraceWriter,
    reuse_profile_state: bool = False,
    hydrate_storage_state: bool = False,
) -> dict[str, Any]:
    browser = None
    tab = None
    deadline = time.time() + max(30.0, float(timeout_sec))
    stage_action_ts: dict[str, float] = {}
    stage_enter_ts: dict[str, float] = {}
    last_stage = ''
    last_hint_ts = 0.0
    last_challenge_log_ts = 0.0
    blocked_otp_codes: set[str] = set()
    otp_resend_count = 0
    otp_auto_retry_exhausted = False
    retryable_error_reload_count = 0
    challenge_tab_enter_count = 0
    challenge_tab_enter_last_ts = 0.0
    openai_home_reopen_count = 0
    normalized_totp_secret = normalize_totp_secret(mfa_totp_secret)
    totp_generation_failed = False

    def info(msg: str) -> None:
        _emit_log_sync(loop, log, 'info', msg)

    def warn(msg: str) -> None:
        _emit_log_sync(loop, log, 'warn', msg)

    try:
        browser_local_port = _pick_free_loopback_port() if bool(reuse_profile_state) else 0
        browser_path, notices = _resolve_browser_path()
        for notice in notices:
            warn(f'【Codex OAuth】{notice}')

        browser_cfg = _BrowserConfig(
            browser_path=browser_path,
            headless=bool(headless),
            # 说明：
            #   复用固定 profile 时不能再走无痕窗口，否则 cf_clearance / challenge 通过态
            #   无法稳定沉淀到当前账号的浏览器环境里。
            incognito=not bool(reuse_profile_state),
            auto_port=not bool(reuse_profile_state),
            local_port=int(browser_local_port or 0),
            load_mode='normal',
            proxy_url=_resolve_codex_proxy_url(),
        )
        browser_factory = _BrowserFactory(browser_cfg)
        profile_dir = browser_factory.make_profile_dir(str(_resolve_profile_root()), email)

        info(f'【Codex OAuth】Drission 浏览器路径：{browser_path}')
        info(f'【Codex OAuth】Drission profile：{profile_dir}')
        if bool(reuse_profile_state) and int(browser_local_port or 0) > 0:
            info(f'【Codex OAuth】固定 profile 模式已关闭 auto_port，改用本地调试端口 {int(browser_local_port)}')

        browser, tab = _open_drission_browser_with_retry(
            browser_factory,
            profile_dir,
            trace=trace,
            log=log,
            loop=loop,
            max_attempts=2,
            retry_wait_seconds=1.5,
        )
        try:
            browser.set.load_mode('normal')
        except Exception:
            pass
        try:
            tab.set.load_mode('normal')
        except Exception:
            pass

        safe_state_path = str(storage_state_path or '').strip()
        if bool(reuse_profile_state):
            info('【Codex OAuth】已启用固定浏览器 profile 复用，优先复用当前账号的已验证环境态。')
        if safe_state_path:
            if bool(hydrate_storage_state):
                hydrate_result = _hydrate_storage_state_to_tab(
                    tab=tab,
                    storage_state_path=safe_state_path,
                    timeout_seconds=12.0,
                    trace=trace,
                )
                if bool(hydrate_result.get('ok')):
                    info(
                        '【Codex OAuth】已向 Drission 标签页注入 storage_state：'
                        f"cookies={int(hydrate_result.get('cookieCount') or 0)}，"
                        f"origins={int(hydrate_result.get('originCount') or 0)}"
                    )
                else:
                    warn(
                        '【Codex OAuth】Drission storage_state 注入未生效，将继续依赖固定 profile：'
                        f"{str(hydrate_result.get('reason') or 'unknown')}"
                    )
            else:
                info('【Codex OAuth】已禁用 storage_state 注入，忽略现有登录态，直接打开认证链接。')
        else:
            info('【Codex OAuth】未提供 storage_state，直接打开认证链接。')

        if not _safe_get(tab, auth_url, timeout_seconds=30.0):
            return {'success': False, 'error': 'Drission 打开认证链接失败。', 'trace_path': trace.path}
        _capture_codex_debug_snapshot_sync(
            tab=tab,
            log=log,
            loop=loop,
            trace=trace,
            tag='after_open_auth_url',
            callback_url_hints=callback_url_hints,
            extra={'phase': 'after_open_auth_url', 'headless': bool(headless)},
        )
        info('【Codex OAuth】步骤 4/8：开始自动登录（Drission only）')

        while time.time() < deadline:
            if stop_event.is_set():
                return {'success': True, 'trace_path': trace.path}

            snapshot = _collect_page_snapshot(tab)
            stage = _infer_codex_oauth_stage(snapshot, callback_url_hints)
            now = time.time()

            if stage != last_stage:
                prev_stage = last_stage
                if prev_stage == 'otp' and stage != 'otp':
                    otp_resend_count = 0
                    otp_auto_retry_exhausted = False
                if prev_stage == 'retryable_error' and stage != 'retryable_error':
                    retryable_error_reload_count = 0
                if prev_stage == 'challenge' and stage != 'challenge':
                    challenge_tab_enter_count = 0
                    challenge_tab_enter_last_ts = 0.0
                if prev_stage == 'openai_home' and stage != 'openai_home':
                    openai_home_reopen_count = 0
                stage_enter_ts[stage] = now
                info(f'【Codex OAuth】步骤识别为 {stage}，将继续执行。')
                _capture_codex_debug_snapshot_sync(
                    tab=tab,
                    log=log,
                    loop=loop,
                    trace=trace,
                    tag=f'stage_{stage}',
                    callback_url_hints=callback_url_hints,
                    extra={'phase': 'stage_change', 'stage': stage},
                )
                last_stage = stage

            if stage == 'callback':
                callback = _callback_from_snapshot(
                    snapshot=snapshot,
                    expected_state=expected_state,
                    redirect_uri=redirect_uri,
                )
                if callback is not None:
                    trace.write(
                        {
                            'ts': _iso_now(),
                            'stage': 'browser_callback_fallback',
                            'url': _sanitize_url_for_log(str(snapshot.get('url') or '')),
                            'hasCode': bool(callback.code),
                            'hasError': bool(callback.error),
                            'hasState': bool(callback.state),
                        }
                    )
                    info('【Codex OAuth】已从浏览器当前地址直接解析到 OAuth 回调，作为本地监听兜底继续执行。')
                    return {'success': True, 'trace_path': trace.path, 'callback': callback}
                if now - last_hint_ts >= 10:
                    warn('【Codex OAuth】浏览器已进入回调页，但本地监听尚未收到 code，将继续等待并保留当前页面。')
                    last_hint_ts = now
                time.sleep(0.5)
                continue

            if stage == 'challenge':
                if (
                    _cloudflare_tab_enter_enabled()
                    and challenge_tab_enter_count < int(_CHALLENGE_AUTO_TAB_ENTER_MAX_ATTEMPTS)
                    and (
                        challenge_tab_enter_count <= 0
                        or (now - float(challenge_tab_enter_last_ts)) >= float(_CHALLENGE_AUTO_TAB_ENTER_RETRY_INTERVAL_SEC)
                    )
                ):
                    challenge_tab_enter_count += 1
                    challenge_tab_enter_last_ts = now
                    action_sent = False
                    snapshot_tag = ''
                    snapshot_extra: dict[str, Any] = {}
                    if challenge_tab_enter_count > 1:
                        focus_summary = _read_challenge_active_element_summary(tab)
                        if _challenge_focus_matches_checkbox(focus_summary):
                            action_sent = _try_click_focused_challenge_control(
                                tab,
                                focus_summary=focus_summary,
                                trace=trace,
                                log=log,
                                loop=loop,
                                attempt=int(challenge_tab_enter_count),
                            )
                            if action_sent:
                                snapshot_tag = 'challenge_after_pointer_click'
                                snapshot_extra = {
                                    'phase': 'challenge_auto_pointer_click',
                                    'attempt': int(challenge_tab_enter_count),
                                }
                    if (not action_sent) and _try_press_tab_enter_on_challenge(
                        tab,
                        trace=trace,
                        log=log,
                        loop=loop,
                        attempt=int(challenge_tab_enter_count),
                    ):
                        action_sent = True
                        snapshot_tag = 'challenge_after_tab_enter'
                        snapshot_extra = {
                            'phase': 'challenge_auto_tab_enter',
                            'attempt': int(challenge_tab_enter_count),
                        }
                    if action_sent:
                        time.sleep(1.0)
                        _capture_codex_debug_snapshot_sync(
                            tab=tab,
                            log=log,
                            loop=loop,
                            trace=trace,
                            tag=snapshot_tag,
                            callback_url_hints=callback_url_hints,
                            extra=snapshot_extra,
                        )
                if now - last_challenge_log_ts >= 10:
                    warn('【Codex OAuth】检测到 Cloudflare/安全验证页面，请在弹出的浏览器中手动完成验证。')
                    last_challenge_log_ts = now
                time.sleep(1.2)
                continue

            if stage == 'loading':
                time.sleep(1.0)
                continue

            if stage == 'openai_home':
                openai_home_stage_enter_ts = float(stage_enter_ts.get('openai_home', now) or now)
                can_reopen_auth = (
                    _is_codex_consent_url(auth_url)
                    or '/sign-in-with-chatgpt/' in str(auth_url or '').strip().lower()
                )
                if now - stage_action_ts.get('openai_home', 0.0) >= _OPENAI_HOME_STAGE_ACTION_INTERVAL_SEC:
                    stage_action_ts['openai_home'] = now
                    if (
                        can_reopen_auth
                        and (now - openai_home_stage_enter_ts) >= _OPENAI_HOME_REOPEN_AFTER_SEC
                        and openai_home_reopen_count < _OPENAI_HOME_REOPEN_MAX
                    ):
                        openai_home_reopen_count += 1
                        reopened = _safe_get(tab, auth_url, timeout_seconds=30.0)
                        if reopened:
                            info(
                                '【Codex OAuth】当前跳转到了 openai.com 首页，'
                                '已复用当前浏览器态重新打开原始授权链接，准备继续获取 OAuth 回调：'
                                f'{openai_home_reopen_count}/{_OPENAI_HOME_REOPEN_MAX}'
                            )
                            _capture_codex_debug_snapshot_sync(
                                tab=tab,
                                log=log,
                                loop=loop,
                                trace=trace,
                                tag='openai_home_reopen_auth',
                                callback_url_hints=callback_url_hints,
                                extra={
                                    'reloadCount': openai_home_reopen_count,
                                    'authUrl': _sanitize_url_for_log(auth_url),
                                },
                            )
                        elif now - last_hint_ts >= 10:
                            warn('【Codex OAuth】当前跳转到了 openai.com 首页，但重新打开原始授权链接失败，请手动返回授权页重试。')
                            last_hint_ts = now
                    elif now - last_hint_ts >= 10:
                        warn('【Codex OAuth】当前停留在 openai.com 首页，正在等待或重试返回授权页；若长时间无变化，请在浏览器中手动回到授权页面。')
                        last_hint_ts = now
                time.sleep(1.0)
                continue

            if stage == 'retryable_error':
                retryable_stage_enter_ts = float(stage_enter_ts.get('retryable_error', now) or now)
                retryable_elapsed_sec = max(0.0, now - retryable_stage_enter_ts)
                if now - stage_action_ts.get('retryable_error', 0.0) >= _RETRYABLE_ERROR_STAGE_ACTION_INTERVAL_SEC:
                    stage_action_ts['retryable_error'] = now
                    clicked_result = _js_click_matching_text_with_retry(
                        tab,
                        _RETRYABLE_ERROR_BUTTON_TEXTS + _GENERIC_CONTINUE_TEXTS,
                        _FAST_STAGE_BUTTON_RETRY_DELAYS_SEC,
                    )
                    if clicked_result.get('ok'):
                        info(
                            '【Codex OAuth】检测到 OpenAI 登录超时/异常页，已尝试点击重试按钮：'
                            f"{str(clicked_result.get('text') or '').strip() or 'unknown'}"
                        )
                    elif (
                        retryable_elapsed_sec >= _RETRYABLE_ERROR_REOPEN_AFTER_SEC
                        and retryable_error_reload_count < _RETRYABLE_ERROR_MAX_RELOADS
                    ):
                        retryable_error_reload_count += 1
                        reopened = _safe_get(tab, auth_url, timeout_seconds=30.0)
                        if reopened:
                            stage_enter_ts['retryable_error'] = now
                            info(
                                '【Codex OAuth】登录页停留在可重试错误页，已重新打开认证链接：'
                                f'{retryable_error_reload_count}/{_RETRYABLE_ERROR_MAX_RELOADS}'
                            )
                            _capture_codex_debug_snapshot_sync(
                                tab=tab,
                                log=log,
                                loop=loop,
                                trace=trace,
                                tag='retryable_error_reopen_auth',
                                callback_url_hints=callback_url_hints,
                                extra={
                                    'reloadCount': retryable_error_reload_count,
                                    'elapsedSec': round(retryable_elapsed_sec, 2),
                                },
                            )
                        elif now - last_hint_ts >= 10:
                            warn('【Codex OAuth】登录页停留在超时错误页，尝试重新打开认证链接失败，请手动刷新或稍后重试。')
                            last_hint_ts = now
                    elif now - last_hint_ts >= 10:
                        warn('【Codex OAuth】检测到 OpenAI 登录超时/异常页，正在自动重试；若长时间不恢复，请手动点击 Try again。')
                        last_hint_ts = now
                if (
                    retryable_elapsed_sec >= _RETRYABLE_ERROR_FAIL_AFTER_SEC
                    and retryable_error_reload_count >= _RETRYABLE_ERROR_MAX_RELOADS
                ):
                    error_message = 'OpenAI 登录页停留在可重试错误页（如 Operation timed out），已自动重试但仍未恢复。'
                    warn(f'【Codex OAuth】{error_message}')
                    _capture_codex_debug_snapshot_sync(
                        tab=tab,
                        log=log,
                        loop=loop,
                        trace=trace,
                        tag='retryable_error_exhausted',
                        callback_url_hints=callback_url_hints,
                        extra={
                            'reason': error_message,
                            'elapsedSec': round(retryable_elapsed_sec, 2),
                            'reloadCount': retryable_error_reload_count,
                        },
                    )
                    return {'success': False, 'error': error_message, 'trace_path': trace.path}
                time.sleep(1.0)
                continue

            if stage == 'error':
                error_detail = _extract_auth_error_detail(snapshot.get('url') or '')
                error_message = f'OpenAI 授权页返回错误页：{error_detail}' if error_detail else 'OpenAI 授权页返回错误页。'
                warn(f'【Codex OAuth】{error_message}')
                _capture_codex_debug_snapshot_sync(
                    tab=tab,
                    log=log,
                    loop=loop,
                    trace=trace,
                    tag='oauth_error_page',
                    callback_url_hints=callback_url_hints,
                    extra={'reason': error_message},
                )
                return {'success': False, 'error': error_message, 'trace_path': trace.path}

            if stage in {'email', 'signup'}:
                stage_key = 'email' if stage == 'email' else 'signup'
                if (
                    _oauth_browser_inline_signup_enabled()
                    and stage == 'email'
                    and now - stage_action_ts.get('signup_link', 0.0) >= 2.0
                    and ('/log-in' in str(snapshot.get('url') or '').lower() or 'welcome back' in str(snapshot.get('title') or '').lower())
                ):
                    stage_action_ts['signup_link'] = now
                    if _js_click_first_matching_text(tab, _SIGNUP_LINK_TEXTS):
                        info('【Codex OAuth】OAuth 内联注册：已尝试点击 Sign up / 创建账号。')
                        time.sleep(1.0)
                        continue
                if now - stage_action_ts.get(stage_key, 0.0) >= 4.0:
                    stage_action_ts[stage_key] = now
                    if _js_set_first_visible_input(tab, _EMAIL_SELECTORS, email):
                        time.sleep(0.2)
                        clicked = _js_click_first_matching_text(tab, _GENERIC_CONTINUE_TEXTS)
                        info('【Codex OAuth】已尝试填写邮箱并继续（OAuth 内联注册）。' if _oauth_browser_inline_signup_enabled() else '【Codex OAuth】已尝试填写邮箱并继续。')
                        if not clicked:
                            _capture_codex_debug_snapshot_sync(
                                tab=tab,
                                log=log,
                                loop=loop,
                                trace=trace,
                                tag='email_input_missing',
                                callback_url_hints=callback_url_hints,
                                extra={'reason': '邮箱已填写但未找到继续按钮'},
                            )
                    else:
                        _capture_codex_debug_snapshot_sync(
                            tab=tab,
                            log=log,
                            loop=loop,
                            trace=trace,
                            tag='email_input_missing',
                            callback_url_hints=callback_url_hints,
                            extra={'reason': '未找到邮箱输入框'},
                        )
                time.sleep(1.0)
                continue

            if stage == 'profile':
                if now - stage_action_ts.get('profile', 0.0) >= 4.0:
                    stage_action_ts['profile'] = now
                    try:
                        from http_stage_features import random_birth_date, random_full_name

                        profile_name = random_full_name()
                        profile_birth = random_birth_date()
                    except Exception:
                        profile_name = 'Alex Johnson'
                        profile_birth = '1992-06-15'
                    name_ok = _js_set_first_visible_input(tab, _PROFILE_NAME_SELECTORS, profile_name)
                    birth_ok = _js_set_first_visible_input(tab, _PROFILE_BIRTH_SELECTORS, profile_birth)
                    if name_ok or birth_ok:
                        time.sleep(0.2)
                        _js_click_first_matching_text(tab, _GENERIC_CONTINUE_TEXTS + ('create account', 'agree'))
                        info('【Codex OAuth】OAuth 内联注册：已尝试填写姓名/生日并继续。')
                    elif now - last_hint_ts >= 10:
                        warn('【Codex OAuth】当前页面需要填写姓名/生日，请在浏览器中手动完成。')
                        last_hint_ts = now
                time.sleep(1.0)
                continue

            if stage == 'add_phone':
                trace.write(
                    {
                        'ts': _iso_now(),
                        'stage': 'browser_oauth_inline_signup_add_phone_detected',
                        'url': _sanitize_url_for_log(str(snapshot.get('url') or '')),
                    }
                )
                if _oauth_browser_inline_signup_enabled():
                    return {
                        'success': False,
                        'error': 'browser_oauth_inline_signup_add_phone_required',
                        'trace_path': trace.path,
                    }
                if now - last_hint_ts >= 10:
                    warn('【Codex OAuth】当前页面需要手机短信验证，请在浏览器中手动完成。')
                    last_hint_ts = now
                time.sleep(1.0)
                continue

            if stage == 'password':
                if not str(password or '').strip():
                    if now - last_hint_ts >= 10:
                        warn('【Codex OAuth】当前页面需要密码，但号池未保存密码，请在浏览器中手动完成。')
                        last_hint_ts = now
                    time.sleep(1.0)
                    continue
                if now - stage_action_ts.get('password', 0.0) >= 4.0:
                    stage_action_ts['password'] = now
                    if _js_set_first_visible_input(tab, _PASSWORD_SELECTORS, password):
                        time.sleep(0.2)
                        clicked = _js_click_first_matching_text(tab, _PASSWORD_SUBMIT_TEXTS)
                        info('【Codex OAuth】已尝试填写密码并继续。')
                        if not clicked:
                            _capture_codex_debug_snapshot_sync(
                                tab=tab,
                                log=log,
                                loop=loop,
                                trace=trace,
                                tag='password_fill_failed',
                                callback_url_hints=callback_url_hints,
                                extra={'reason': '密码已填写但未找到继续按钮'},
                            )
                    else:
                        _capture_codex_debug_snapshot_sync(
                            tab=tab,
                            log=log,
                            loop=loop,
                            trace=trace,
                            tag='password_input_missing',
                            callback_url_hints=callback_url_hints,
                            extra={'reason': '未找到密码输入框'},
                        )
                time.sleep(1.0)
                continue

            if stage == 'otp':
                can_auto_fill_totp = bool(normalized_totp_secret) and (not totp_generation_failed)
                if can_auto_fill_totp and now - stage_action_ts.get('otp', 0.0) >= _OTP_AUTO_POLL_ACTION_INTERVAL_SEC:
                    stage_action_ts['otp'] = now
                    try:
                        remaining_seconds = totp_seconds_remaining()
                        code_value = generate_totp_code(normalized_totp_secret)
                    except Exception as error:
                        totp_generation_failed = True
                        warn(f'【Codex OAuth】TOTP 密钥不可用，无法自动生成验证码：{error}')
                    else:
                        info(
                            '【Codex OAuth】检测到 2FA/TOTP 页面，'
                            f'准备使用已保存密钥自动生成验证码（剩余 {remaining_seconds}s）。'
                        )
                        if _js_fill_otp_value(tab, code_value):
                            time.sleep(0.2)
                            _js_click_first_matching_text(tab, _OTP_SUBMIT_TEXTS)
                            info('【Codex OAuth】已自动填写 TOTP 验证码并尝试提交。')
                        else:
                            _capture_codex_debug_snapshot_sync(
                                tab=tab,
                                log=log,
                                loop=loop,
                                trace=trace,
                                tag='totp_input_missing',
                                callback_url_hints=callback_url_hints,
                                extra={'reason': '已生成 TOTP 验证码但未找到输入框'},
                            )
                        time.sleep(1.0)
                        continue
                managed_mail_enabled = bool(use_managed_mail_otp) and bool(str(managed_mail_jwt or '').strip()) and bool(
                    str(managed_mail_api_base or '').strip()
                )
                imap_enabled = (
                    bool(use_imap_otp)
                    and bool(
                        _normalize_imap_profiles_payload(
                            imap_profiles_json,
                            fallback_host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
                            fallback_port=int(imap_port or 993),
                            fallback_user=str(imap_user or '').strip(),
                            fallback_pass=str(imap_pass or ''),
                            fallback_folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
                            fallback_latest_n=int(imap_latest_n or 10),
                            fallback_auth_type=str(imap_auth_type or 'password').strip() or 'password',
                            fallback_oauth_client_id=str(imap_oauth_client_id or '').strip(),
                            fallback_oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
                            fallback_password_fallback=bool(imap_password_fallback),
                            fallback_pop3_fallback=bool(imap_pop3_fallback),
                        )
                    )
                )
                can_auto_poll_otp = (managed_mail_enabled or imap_enabled) and (not otp_auto_retry_exhausted)
                if can_auto_poll_otp and now - stage_action_ts.get('otp', 0.0) >= _OTP_AUTO_POLL_ACTION_INTERVAL_SEC:
                    stage_action_ts['otp'] = now
                    otp_stage_enter_ts = float(stage_enter_ts.get('otp', now) or now)
                    if managed_mail_enabled:
                        info(f'【Codex OAuth】检测到邮箱验证码页面，准备通过托管邮箱 JWT 自动取码（目标={_mask_email(email)}）。')
                        code_value = str(
                            poll_managed_mail_verification_code_sync(
                                email=email,
                                mail_provider=str(managed_mail_provider or '').strip(),
                                mail_jwt=str(managed_mail_jwt or '').strip(),
                                mail_api_base=str(managed_mail_api_base or '').strip(),
                                mail_frontend_base=str(managed_mail_frontend_base or '').strip(),
                                otp_timeout_sec=float(otp_timeout_sec),
                                otp_interval_sec=float(otp_interval_sec),
                                blocked_codes=blocked_otp_codes,
                                not_before_ts=max(0.0, otp_stage_enter_ts - _OTP_IMAP_NOT_BEFORE_GRACE_SEC),
                                latest_n=int(managed_mail_latest_n or 20),
                                log_info=info,
                                log_warn=warn,
                            )
                            or ''
                        ).strip()
                    else:
                        imap_profiles = _normalize_imap_profiles_payload(
                            imap_profiles_json,
                            fallback_host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
                            fallback_port=int(imap_port or 993),
                            fallback_user=str(imap_user or '').strip(),
                            fallback_pass=str(imap_pass or ''),
                            fallback_folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
                            fallback_latest_n=int(imap_latest_n or 10),
                            fallback_auth_type=str(imap_auth_type or 'password').strip() or 'password',
                            fallback_oauth_client_id=str(imap_oauth_client_id or '').strip(),
                            fallback_oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
                            fallback_password_fallback=bool(imap_password_fallback),
                            fallback_pop3_fallback=bool(imap_pop3_fallback),
                        )
                        info(
                            f'【Codex OAuth】检测到邮箱验证码页面，准备通过 IMAP 自动取码'
                            f'（profiles={len(imap_profiles)}, 目标={_mask_email(email)}）。'
                        )
                        code_value = _poll_imap_code_multi_sync(
                            email=email,
                            otp_timeout_sec=float(otp_timeout_sec),
                            otp_interval_sec=float(otp_interval_sec),
                            imap_profiles=imap_profiles,
                            blocked_codes=blocked_otp_codes,
                            not_before_ts=max(0.0, otp_stage_enter_ts - _OTP_IMAP_NOT_BEFORE_GRACE_SEC),
                            log=log,
                            loop=loop,
                        )
                    if code_value:
                        if _js_fill_otp_value(tab, code_value):
                            time.sleep(0.2)
                            _js_click_first_matching_text(tab, _OTP_SUBMIT_TEXTS)
                            info('【Codex OAuth】已自动填写邮箱验证码并尝试提交。')
                        else:
                            _capture_codex_debug_snapshot_sync(
                                tab=tab,
                                log=log,
                                loop=loop,
                                trace=trace,
                                tag='otp_input_missing',
                                callback_url_hints=callback_url_hints,
                                extra={'reason': '已取到验证码但未找到输入框'},
                            )
                    else:
                        resend_result = {'ok': False}
                        if otp_resend_count < _MAX_AUTO_OTP_RESENDS:
                            resend_result = _js_click_first_matching_text_result(tab, _OTP_RESEND_TEXTS)
                        if resend_result.get('ok'):
                            otp_resend_count += 1
                            button_text = str(resend_result.get('text') or '').strip()
                            info(
                                f'【Codex OAuth】未在时限内收到邮箱验证码，已自动点击重新获取验证码并准备重试 '
                                f'（第 {otp_resend_count}/{_MAX_AUTO_OTP_RESENDS} 次，按钮={button_text or "未知"}）。'
                            )
                            _capture_codex_debug_snapshot_sync(
                                tab=tab,
                                log=log,
                                loop=loop,
                                trace=trace,
                                tag='otp_resend_clicked',
                                callback_url_hints=callback_url_hints,
                                extra={
                                    'attempt': otp_resend_count,
                                    'buttonText': button_text,
                                },
                            )
                        else:
                            otp_auto_retry_exhausted = True
                            if otp_resend_count >= _MAX_AUTO_OTP_RESENDS:
                                warn(
                                    f'【Codex OAuth】邮箱验证码在 {otp_resend_count} 次自动重发后仍未收到，'
                                    '请在浏览器中手动点击重新获取验证码或直接手动输入。'
                                )
                                _capture_codex_debug_snapshot_sync(
                                    tab=tab,
                                    log=log,
                                    loop=loop,
                                    trace=trace,
                                    tag='otp_resend_exhausted',
                                    callback_url_hints=callback_url_hints,
                                    extra={'attempts': otp_resend_count},
                                )
                            else:
                                warn(
                                    '【Codex OAuth】未在时限内通过'
                                    f'{"托管邮箱 JWT" if managed_mail_enabled else "IMAP"}取到验证码，'
                                    '且未找到重新获取验证码按钮，请在浏览器中手动处理。'
                                )
                                _capture_codex_debug_snapshot_sync(
                                    tab=tab,
                                    log=log,
                                    loop=loop,
                                    trace=trace,
                                    tag='otp_resend_missing',
                                    callback_url_hints=callback_url_hints,
                                    extra={'attempts': otp_resend_count},
                                )
                elif now - last_hint_ts >= 10:
                    if otp_auto_retry_exhausted:
                        warn('【Codex OAuth】当前页面仍停留在邮箱验证码阶段，请在浏览器中手动点重新获取验证码或直接完成验证。')
                    else:
                        warn('【Codex OAuth】当前页面需要邮箱验证码，请在浏览器中手动完成。')
                    last_hint_ts = now
                time.sleep(1.0)
                continue

            if stage == 'chatgpt_role_prompt':
                if now - stage_action_ts.get('chatgpt_role_prompt', 0.0) >= _CHATGPT_HOME_STAGE_ACTION_INTERVAL_SEC:
                    stage_action_ts['chatgpt_role_prompt'] = now
                    clicked_result = _js_click_matching_text_with_retry(
                        tab,
                        _CHATGPT_ROLE_OPTION_TEXTS,
                        _FAST_STAGE_BUTTON_RETRY_DELAYS_SEC,
                        max_scroll_passes=2,
                    )
                    if clicked_result.get('ok'):
                        info(
                            '【Codex OAuth】已尝试完成 ChatGPT 首页职业选择：'
                            f"{str(clicked_result.get('text') or '').strip() or 'unknown'}"
                        )
                    elif now - last_hint_ts >= 10:
                        warn('【Codex OAuth】当前停留在 ChatGPT 首页职业选择页，请在浏览器中手动选择一个职业类型。')
                        last_hint_ts = now
                time.sleep(_FAST_STAGE_LOOP_SLEEP_SEC)
                continue

            if stage == 'chatgpt_work_apps':
                if now - stage_action_ts.get('chatgpt_work_apps', 0.0) >= _CHATGPT_HOME_STAGE_ACTION_INTERVAL_SEC:
                    stage_action_ts['chatgpt_work_apps'] = now
                    clicked_result = _js_click_matching_text_with_retry(
                        tab,
                        _CHATGPT_WORK_APPS_SKIP_TEXTS + _WORKSPACE_BUTTON_TEXTS,
                        _FAST_STAGE_BUTTON_RETRY_DELAYS_SEC,
                        max_scroll_passes=4,
                    )
                    if clicked_result.get('ok'):
                        info(
                            '【Codex OAuth】已尝试跳过 ChatGPT 首页工作应用引导：'
                            f"{str(clicked_result.get('text') or '').strip() or 'unknown'}"
                        )
                    elif now - last_hint_ts >= 10:
                        warn('【Codex OAuth】当前停留在 ChatGPT 首页工作应用引导页，请在浏览器中手动点击跳过或继续。')
                        last_hint_ts = now
                time.sleep(_FAST_STAGE_LOOP_SLEEP_SEC)
                continue

            if stage in {'workspace', 'authorize'}:
                key = stage
                action_interval_sec = (
                    _WORKSPACE_STAGE_ACTION_INTERVAL_SEC if stage == 'workspace' else _AUTHORIZE_STAGE_ACTION_INTERVAL_SEC
                )
                if now - stage_action_ts.get(key, 0.0) >= action_interval_sec:
                    stage_action_ts[key] = now
                    clicked_result: dict[str, Any] = {'ok': False}
                    texts = (
                        _WORKSPACE_BUTTON_TEXTS + _AUTHORIZE_BUTTON_TEXTS + _GENERIC_CONTINUE_TEXTS
                        if stage == 'workspace'
                        else _AUTHORIZE_BUTTON_TEXTS + _GENERIC_CONTINUE_TEXTS
                    )
                    if stage == 'workspace':
                        workspace_action = _handle_workspace_stage_actions(
                            tab,
                            snapshot,
                            expected_email=str(email or '').strip(),
                        )
                        select_res = (
                            workspace_action.get('select')
                            if isinstance(workspace_action, dict)
                            else {'ok': False}
                        )
                        continue_fallback_ready = bool((workspace_action or {}).get('continueFallbackReady'))
                        if _is_workspace_selection_confirmed(select_res):
                            if not bool(select_res.get('alreadyChecked')):
                                info(
                                    '【Codex OAuth】已尝试选择非个人工作区：'
                                    f"{str(select_res.get('text') or '').strip() or 'unknown'}"
                                )
                            elif str(select_res.get('text') or '').strip():
                                info(
                                    '【Codex OAuth】已确认当前为非个人工作区：'
                                    f"{str(select_res.get('text') or '').strip()}"
                                )
                            if bool((workspace_action or {}).get('isChatgptHomeWorkspace')):
                                migration_result = (workspace_action or {}).get('migration') or {'ok': False}
                                if migration_result.get('ok'):
                                    info(
                                    '【Codex OAuth】已尝试选择 ChatGPT Business 进入方式：'
                                    f"{str(migration_result.get('text') or '').strip() or 'unknown'}"
                                )
                            clicked_result = (workspace_action or {}).get('clicked') or {'ok': False}
                        elif continue_fallback_ready:
                            info(
                                '【Codex OAuth】已尝试点击非个人工作区，当前页面已出现 Continue/继续，'
                                '将按可继续分支直接执行下滑与点击。'
                            )
                            clicked_result = (workspace_action or {}).get('clicked') or {'ok': False}
                        elif bool(select_res.get('clicked')):
                            if now - last_hint_ts >= 10:
                                warn(
                                    '【Codex OAuth】已尝试点击非个人工作区，但页面尚未确认选中；'
                                    '正在等待工作区选择状态稳定后再继续。'
                                )
                                last_hint_ts = now
                        elif now - last_hint_ts >= 10:
                            warn(
                                '【Codex OAuth】当前页面需要先选择非个人工作区，再点击继续；'
                                '若自动选择失败，请在浏览器中手动选择团队/工作区账号。'
                            )
                            last_hint_ts = now
                    else:
                        clicked_result = _js_click_matching_text_with_retry(
                            tab,
                            texts,
                            _FAST_STAGE_BUTTON_RETRY_DELAYS_SEC,
                            max_scroll_passes=_AUTHORIZE_STAGE_CLICK_SCROLL_PASSES,
                            fallback_to_primary_action=True,
                        )
                    if clicked_result.get('ok'):
                        info(
                            '【Codex OAuth】已尝试点击继续/授权按钮：'
                            f"{str(clicked_result.get('text') or '').strip() or 'unknown'}"
                        )
                    elif now - last_hint_ts >= 10:
                        warn('【Codex OAuth】当前页面需要继续工作区/授权确认，请在浏览器中手动完成。')
                        last_hint_ts = now
                time.sleep(_FAST_STAGE_LOOP_SLEEP_SEC)
                continue

            if now - stage_action_ts.get('unknown', 0.0) >= 6.0:
                stage_action_ts['unknown'] = now
                clicked = _js_click_first_matching_text(
                    tab,
                    _EMAIL_ENTRY_TEXTS + _GENERIC_CONTINUE_TEXTS + _AUTHORIZE_BUTTON_TEXTS,
                )
                if clicked:
                    info('【Codex OAuth】已尝试点击当前页面可识别的继续按钮。')
                elif now - last_hint_ts >= 15:
                    info('【Codex OAuth】浏览器仍在等待页面变化或人工操作；若看到验证码/MFA，请手动完成。')
                    last_hint_ts = now
            time.sleep(1.0)

        _capture_codex_debug_snapshot_sync(
            tab=tab,
            log=log,
            loop=loop,
            trace=trace,
            tag='callback_timeout',
            callback_url_hints=callback_url_hints,
            extra={'reason': f'等待 OAuth 回调超时（{int(timeout_sec)} 秒）'},
        )
        return {'success': False, 'error': f'等待 OAuth 回调超时（{int(timeout_sec)} 秒）。', 'trace_path': trace.path}
    except Exception as error:
        if tab is not None:
            try:
                _capture_codex_debug_snapshot_sync(
                    tab=tab,
                    log=log,
                    loop=loop,
                    trace=trace,
                    tag='flow_exception',
                    callback_url_hints=callback_url_hints,
                    extra={'error': str(error)},
                )
            except Exception:
                pass
        return {'success': False, 'error': f'Drission Codex OAuth 异常：{error}', 'trace_path': trace.path}
    finally:
        if browser is not None:
            try:
                browser.quit()
            except Exception:
                pass


async def run_codex_oauth_flow(
    *,
    email: str,
    password: str,
    storage_state_path: str = '',
    output_path: str,
    headless: bool,
    log: Any,
    mail_url: str = 'https://mail.2925.com/#/mailList',
    mail_auth_state_path: str = '',
    otp_timeout_sec: float = 120.0,
    otp_interval_sec: float = 3.0,
    otp_api_url: str = '',
    mfa_totp_secret: str = '',
    use_imap_otp: bool = False,
    use_managed_mail_otp: bool = True,
    managed_mail_provider: str = '',
    managed_mail_jwt: str = '',
    managed_mail_api_base: str = '',
    managed_mail_frontend_base: str = '',
    managed_mail_latest_n: int = 20,
    use_domain_mail_otp: bool = True,
    domain_mail_api_base: str = '',
    domain_mail_domain: str = '',
    domain_mail_token: str = '',
    domain_mail_latest_n: int = 20,
    imap_host: str = 'imap.2925.com',
    imap_port: int = 993,
    imap_user: str = '',
    imap_pass: str = '',
    imap_folder: str = 'Inbox',
    imap_latest_n: int = 10,
    imap_auth_type: str = 'password',
    imap_oauth_client_id: str = '',
    imap_oauth_refresh_token: str = '',
    imap_password_fallback: bool = False,
    imap_pop3_fallback: bool = False,
    imap_profiles_json: str = '',
    timeout_sec: float = 300.0,
    callback_hub: Optional[SharedOAuthCallbackHub] = None,
    provider: str = '',
    expected_workspace_id: str = '',
    phone_verification: Optional[dict[str, Any]] = None,
    require_phone_bind: bool = False,
) -> dict[str, Any]:
    _ = mail_url
    _ = mail_auth_state_path
    safe_email = str(email or '').strip()
    if not safe_email or '@' not in safe_email:
        raise RuntimeError('Codex OAuth 失败：邮箱格式无效。')
    provider_text = _normalize_codex_oauth_provider(provider)
    if bool(require_phone_bind) and provider_text != 'http':
        raise RuntimeError('phone_bind_unsupported_provider: post-registration phone binding requires the HTTP provider')
    activate_http_stage_feature_session(safe_email, f'codex_oauth_{provider_text}')
    resolved_imap = _resolve_codex_oauth_imap_runtime_values(
        imap_host=str(imap_host or '').strip(),
        imap_port=int(imap_port or 0),
        imap_user=str(imap_user or '').strip(),
        imap_pass=str(imap_pass or ''),
        imap_folder=str(imap_folder or '').strip(),
        imap_latest_n=int(imap_latest_n or 0),
        imap_auth_type=str(imap_auth_type or 'password').strip() or 'password',
        imap_oauth_client_id=str(imap_oauth_client_id or '').strip(),
        imap_oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
        imap_password_fallback=bool(imap_password_fallback),
        imap_pop3_fallback=bool(imap_pop3_fallback),
    )
    imap_host = str(resolved_imap.get('imap_host') or 'imap.2925.com').strip() or 'imap.2925.com'
    imap_port = int(resolved_imap.get('imap_port') or 993)
    imap_user = str(resolved_imap.get('imap_user') or '').strip()
    imap_pass = str(resolved_imap.get('imap_pass') or '')
    imap_folder = str(resolved_imap.get('imap_folder') or 'Inbox').strip() or 'Inbox'
    imap_latest_n = int(resolved_imap.get('imap_latest_n') or 10)
    imap_auth_type = str(resolved_imap.get('imap_auth_type') or 'password').strip() or 'password'
    imap_oauth_client_id = str(resolved_imap.get('imap_oauth_client_id') or '').strip()
    imap_oauth_refresh_token = str(resolved_imap.get('imap_oauth_refresh_token') or '').strip()
    imap_password_fallback = bool(resolved_imap.get('imap_password_fallback'))
    imap_pop3_fallback = bool(resolved_imap.get('imap_pop3_fallback'))
    imap_profiles = _normalize_imap_profiles_payload(
        imap_profiles_json,
        fallback_host=imap_host,
        fallback_port=int(imap_port),
        fallback_user=imap_user,
        fallback_pass=imap_pass,
        fallback_folder=imap_folder,
        fallback_latest_n=int(imap_latest_n),
        fallback_auth_type=str(imap_auth_type or 'password').strip() or 'password',
        fallback_oauth_client_id=str(imap_oauth_client_id or '').strip(),
        fallback_oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
        fallback_password_fallback=bool(imap_password_fallback),
        fallback_pop3_fallback=bool(imap_pop3_fallback),
    )

    await _emit_log(log, 'info', '【Codex OAuth】步骤 0/8：初始化流程参数')
    oauth_cfg = _resolve_oauth_runtime_config()
    for notice in oauth_cfg.notices:
        await _emit_log(log, 'warn', f'【Codex OAuth】{notice}')
    bridge_desc = 'off'
    if oauth_cfg.bridge_enabled:
        bridge_desc = (
            f'{get_codex_callback_listener_url(host=oauth_cfg.bridge_bind_host, port=oauth_cfg.bridge_port)} '
            f'-> {get_codex_callback_listener_url(host=oauth_cfg.bridge_target_host, port=oauth_cfg.bridge_target_port)}'
        )
    await _emit_log(
        log,
        'info',
        '【Codex OAuth】配置：'
        f'client_id={oauth_cfg.client_id}，redirect_uri={oauth_cfg.redirect_uri}，'
        f'bind={oauth_cfg.callback_bind_host}:{oauth_cfg.callback_port}，bridge={bridge_desc}，engine={provider_text}',
    )
    if bool(use_imap_otp) and _has_imap_otp_credentials(
        use_imap_otp=True,
        imap_user=imap_user,
        imap_pass=imap_pass,
        imap_auth_type=imap_auth_type,
        imap_oauth_client_id=imap_oauth_client_id,
        imap_oauth_refresh_token=imap_oauth_refresh_token,
    ):
        imap_user_source = str((resolved_imap.get('sources') or {}).get('imap_user') or '').strip()
        auth_desc = 'oauth2' if str(imap_auth_type).lower() == 'oauth2' else 'password'
        await _emit_log(
            log,
            'info',
            '【Codex OAuth】已启用自动 IMAP 取码配置：'
            f'host={imap_host}:{int(imap_port)}，user={_mask_email(imap_user)}，auth={auth_desc}，source={imap_user_source or "unknown"}',
        )
    if bool(use_imap_otp) and len(imap_profiles) > 1:
        await _emit_log(log, 'info', f'【Codex OAuth】已加载多主邮箱 IMAP 配置：profiles={len(imap_profiles)}')

    managed_mail_enabled = bool(use_managed_mail_otp) and bool(str(managed_mail_jwt or '').strip()) and bool(
        str(managed_mail_api_base or '').strip()
    )
    if managed_mail_enabled:
        await _emit_log(
            log,
            'info',
            'Codex OAuth managed mail OTP is enabled: '
            f'provider={str(managed_mail_provider or "").strip() or "managed_mail"}, target={_mask_email(safe_email)}',
        )
    domain_mail_enabled = bool(use_domain_mail_otp) and bool(str(domain_mail_api_base or '').strip()) and bool(
        str(domain_mail_token or '').strip()
    )
    if domain_mail_enabled:
        await _emit_log(log, 'info', f'【Codex OAuth】已启用域名邮箱自动取码：target={_mask_email(safe_email)}')
    state = generate_state()
    pkce = generate_pkce()
    await _emit_log(log, 'info', f'【Codex OAuth】state 已生成：{state}')
    await _emit_log(
        log,
        'info',
        f'【Codex OAuth】PKCE 已生成：code_verifier(长度={len(pkce.code_verifier)}), code_challenge={pkce.code_challenge}',
    )

    await _emit_log(log, 'info', '【Codex OAuth】步骤 1/8：获取（生成）认证链接 URL')
    auth_url = build_auth_url(
        state=state,
        pkce=pkce,
        client_id=oauth_cfg.client_id,
        redirect_uri=oauth_cfg.redirect_uri,
    )
    await _emit_log(log, 'info', f'【Codex OAuth】认证链接如下（请勿外泄）：\n{auth_url}')

    trace = _TraceWriter(email=safe_email)
    await _emit_log(log, 'info', f'【Codex OAuth】调试追踪文件：{trace.path}')
    if provider_text == 'http':
        await _emit_log(log, 'info', '【Codex OAuth】模式：http（纯 HTTP + PKCE + redirect 跟随）')
        return await run_codex_oauth_http_flow(
            email=safe_email,
            password=str(password or ''),
            storage_state_path=storage_state_path,
            output_path=output_path,
            headless=bool(headless),
            log=log,
            oauth_cfg=oauth_cfg,
            auth_url=auth_url,
            pkce=pkce,
            state=state,
            timeout_sec=timeout_sec,
            trace=trace,
            mfa_totp_secret=str(mfa_totp_secret or '').strip(),
            otp_api_url=str(otp_api_url or '').strip(),
            use_imap_otp=bool(use_imap_otp),
            use_managed_mail_otp=bool(use_managed_mail_otp),
            managed_mail_provider=str(managed_mail_provider or '').strip(),
            managed_mail_jwt=str(managed_mail_jwt or '').strip(),
            managed_mail_api_base=str(managed_mail_api_base or '').strip(),
            managed_mail_frontend_base=str(managed_mail_frontend_base or '').strip(),
            managed_mail_latest_n=int(managed_mail_latest_n or 20),
            use_domain_mail_otp=bool(use_domain_mail_otp),
            domain_mail_api_base=str(domain_mail_api_base or '').strip(),
            domain_mail_domain=str(domain_mail_domain or '').strip(),
            domain_mail_token=str(domain_mail_token or '').strip(),
            domain_mail_latest_n=int(domain_mail_latest_n or 20),
            otp_timeout_sec=float(otp_timeout_sec),
            otp_interval_sec=float(otp_interval_sec),
            imap_host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
            imap_port=int(imap_port or 993),
            imap_user=str(imap_user or '').strip(),
            imap_pass=str(imap_pass or ''),
            imap_folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
            imap_latest_n=int(imap_latest_n or 10),
            imap_auth_type=str(imap_auth_type or 'password').strip() or 'password',
            imap_oauth_client_id=str(imap_oauth_client_id or '').strip(),
            imap_oauth_refresh_token=str(imap_oauth_refresh_token or '').strip(),
            imap_password_fallback=bool(imap_password_fallback),
            imap_pop3_fallback=bool(imap_pop3_fallback),
            imap_profiles_json=str(imap_profiles_json or ''),
            expected_workspace_id=str(expected_workspace_id or '').strip(),
            phone_verification=dict(phone_verification or {}),
            require_phone_bind=bool(require_phone_bind),
        )

    await _emit_log(log, 'info', '【Codex OAuth】模式：http（纯 HTTP + 本地回调监听 + PKCE token 交换）')
    loop = asyncio.get_running_loop()
    waiter: Optional[OAuthCallbackWaiter] = None
    bridge_lease: Optional[_SharedOAuthCallbackBridgeLease] = None
    if callback_hub is None:
        try:
            waiter = OAuthCallbackWaiter(host=oauth_cfg.callback_bind_host, port=oauth_cfg.callback_port, loop=loop)
        except Exception as error:
            raise _raise_callback_bind_error(
                host=oauth_cfg.callback_bind_host,
                port=oauth_cfg.callback_port,
                error=error,
            ) from error
        waiter.start()
        await _emit_log(
            log,
            'info',
            '【Codex OAuth】步骤 2/8：已启动独占回调监听 '
            f'{get_codex_callback_listener_url(host=oauth_cfg.callback_bind_host, port=oauth_cfg.callback_port)}'
            f'（OAuth redirect_uri={oauth_cfg.redirect_uri}）',
        )
    else:
        callback_hub.start()
        await _emit_log(
            log,
            'info',
            '【Codex OAuth】步骤 2/8：复用共享回调监听 '
            f'{get_codex_callback_listener_url(host=callback_hub.host, port=callback_hub.port)}'
            f'（OAuth redirect_uri={oauth_cfg.redirect_uri}）',
        )

    if oauth_cfg.bridge_enabled:
        try:
            bridge_lease = _acquire_shared_oauth_callback_bridge(
                bind_host=oauth_cfg.bridge_bind_host,
                bind_port=oauth_cfg.bridge_port,
                target_host=oauth_cfg.bridge_target_host,
                target_port=oauth_cfg.bridge_target_port,
            )
        except Exception as error:
            raise _raise_callback_bridge_bind_error(
                host=oauth_cfg.bridge_bind_host,
                port=oauth_cfg.bridge_port,
                error=error,
            ) from error
        await _emit_log(
            log,
            'info',
            '【Codex OAuth】已启用回调桥接 '
            f'{get_codex_callback_listener_url(host=oauth_cfg.bridge_bind_host, port=oauth_cfg.bridge_port)} '
            f'-> {get_codex_callback_listener_url(host=oauth_cfg.bridge_target_host, port=oauth_cfg.bridge_target_port)}',
        )

    stop_event = threading.Event()
    browser_task: Optional[asyncio.Task[dict[str, Any]]] = None
    callback_task: Optional[asyncio.Task[OAuthCallback]] = None
    try:
        await _emit_log(log, 'info', f'【Codex OAuth】步骤 3/8：启动 Drission 浏览器并打开认证链接（headless={bool(headless)}）')
        browser_task = asyncio.create_task(
            asyncio.to_thread(
                _run_codex_browser_flow_sync,
                auth_url=auth_url,
                redirect_uri=oauth_cfg.redirect_uri,
                expected_state=state,
                email=safe_email,
                password=str(password or ''),
                storage_state_path=str(storage_state_path or ''),
                headless=bool(headless),
                log=log,
                loop=loop,
                stop_event=stop_event,
                callback_url_hints=oauth_cfg.callback_url_hints,
                timeout_sec=float(timeout_sec),
                otp_timeout_sec=float(otp_timeout_sec),
                otp_interval_sec=float(otp_interval_sec),
                mfa_totp_secret=str(mfa_totp_secret or '').strip(),
                use_imap_otp=bool(use_imap_otp),
                use_managed_mail_otp=bool(use_managed_mail_otp),
                managed_mail_provider=str(managed_mail_provider or '').strip(),
                managed_mail_jwt=str(managed_mail_jwt or '').strip(),
                managed_mail_api_base=str(managed_mail_api_base or '').strip(),
                managed_mail_frontend_base=str(managed_mail_frontend_base or '').strip(),
                managed_mail_latest_n=int(managed_mail_latest_n or 20),
                imap_host=str(imap_host or 'imap.2925.com').strip() or 'imap.2925.com',
                imap_port=int(imap_port or 993),
                imap_user=str(imap_user or '').strip(),
                imap_pass=str(imap_pass or ''),
                imap_folder=str(imap_folder or 'Inbox').strip() or 'Inbox',
                imap_latest_n=int(imap_latest_n or 10),
                imap_profiles_json=str(imap_profiles_json or ''),
                trace=trace,
            )
        )

        await _emit_log(log, 'info', f'【Codex OAuth】步骤 5/8：等待 OAuth 回调（最长 {int(timeout_sec)} 秒）：{oauth_cfg.redirect_uri}')
        if callback_hub is None:
            if waiter is None:
                raise RuntimeError('回调监听器初始化异常。')
            callback_task = asyncio.create_task(waiter.wait(timeout_sec))
        else:
            callback_task = asyncio.create_task(callback_hub.wait_for_state(state=state, timeout_sec=timeout_sec))

        start_ts = time.monotonic()
        callback: Optional[OAuthCallback] = None
        while True:
            if browser_task.done():
                browser_res = browser_task.result()
                browser_callback = browser_res.get('callback')
                if browser_res.get('success') and isinstance(browser_callback, OAuthCallback):
                    callback = browser_callback
                    break
                if browser_res.get('success') and callback_task.done():
                    callback = callback_task.result()
                    break
                raise RuntimeError(str(browser_res.get('error') or 'Drission 浏览器流程提前结束。'))

            remaining = float(timeout_sec) - (time.monotonic() - start_ts)
            if remaining <= 0:
                raise TimeoutError(f'等待 OAuth 回调超时（{int(timeout_sec)} 秒）。')
            try:
                callback = await asyncio.wait_for(asyncio.shield(callback_task), timeout=min(1.0, remaining))
                break
            except asyncio.TimeoutError:
                continue

        stop_event.set()
        browser_res = {'success': True, 'trace_path': trace.path}
        if browser_task is not None:
            try:
                browser_res = await asyncio.wait_for(browser_task, timeout=20.0)
            except asyncio.TimeoutError:
                await _emit_log(log, 'warn', '【Codex OAuth】浏览器收尾超时，继续执行 token 交换。')
        trace_path = str((browser_res or {}).get('trace_path') or trace.path).strip()

        if callback is None:
            raise RuntimeError('OAuth 回调为空。')
        if str(callback.error or '').strip():
            desc = str(callback.error_description or '').strip()
            raise RuntimeError(f'OAuth 授权失败：{callback.error}{f" ({desc})" if desc else ""}')
        code = str(callback.code or '').strip()
        if not code:
            raise RuntimeError('OAuth 回调缺少 code。')

        await _emit_log(log, 'info', '【Codex OAuth】步骤 6/8：开始交换 access_token / refresh_token')
        token_resp = await asyncio.to_thread(
            _exchange_code_for_tokens,
            code=code,
            pkce=pkce,
            client_id=oauth_cfg.client_id,
            redirect_uri=oauth_cfg.redirect_uri,
            proxy_url=_resolve_codex_proxy_url(),
        )
        return await _persist_codex_token_payload(
            log=log,
            safe_email=safe_email,
            output_path=output_path,
            token_resp=token_resp,
            trace_path=trace_path,
            expected_workspace_id=str(expected_workspace_id or '').strip(),
        )
    finally:
        stop_event.set()
        if callback_task is not None and (not callback_task.done()):
            callback_task.cancel()
        if bridge_lease is not None:
            bridge_lease.close()
        if waiter is not None:
            waiter.stop()
