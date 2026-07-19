from __future__ import annotations

import datetime
import html
import re
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import Page
else:
    Page = Any


# 6 位数字验证码（常见格式）；这里只做解析，不做任何绕过/规避。
sixDigitCodeRegex = re.compile(r"(?<![0-9A-Fa-f#])(\d{6})(?![0-9A-Fa-f])")
_cssHexColorRegex = re.compile(r"#[0-9A-Fa-f]{3,8}\b")
_explicitOtpPatterns = (
    re.compile(
        r"(?:temporary\s+code|verification\s+code|login\s+code|security\s+code|one[-\s]?time\s+code|验证码|安全代码)\s*[:：]?\s*(\d{6})",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:code|验证码)\s*(?:is|为|：|:)\s*(\d{6})",
        re.IGNORECASE,
    ),
    re.compile(r">\s*(\d{6})\s*<"),
)

# 与扩展一致的关键词（用于提高命中率）；你也可以按实际邮件模板调整。
defaultCodeKeywords = [
    "temporary code",
    "verification code",
    "login code",
    "ChatGPT",
    "OpenAI",
    "验证码",
    "verification",
    "verify",
    "code",
    "安全代码",
]


def _normalize_mail_preview_text(pageText: str) -> str:
    text = "" if pageText is None else str(pageText)
    text = re.sub(r"(?is)<(script|style|noscript)\b[^>]*>.*?</\1>", " ", text)
    text = _cssHexColorRegex.sub(" ", text)
    text = re.sub(r"(?i)(?:color|background(?:-color)?)\s*:\s*#[0-9A-Fa-f]{3,8}", " ", text)
    text = re.sub(r"(?i)https?://\S+", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = text.replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _is_plausible_otp_code(codeValue: str, *, sourceText: str = "", matchStart: int = -1) -> bool:
    code = str(codeValue or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        return False
    if len(set(code)) == 1:
        return False
    if matchStart >= 0:
        left = sourceText[max(0, matchStart - 1) : matchStart]
        right = sourceText[matchStart + 6 : matchStart + 7]
        if left == "#" or re.fullmatch(r"[0-9A-Fa-f]", left or "") or re.fullmatch(
            r"[0-9A-Fa-f]", right or ""
        ):
            return False
    return True


def extractVerificationTimestamp(pageText: str) -> float:
    """Extract the timestamp exposed by the configured mail preview page."""

    text = "" if pageText is None else str(pageText)
    candidates: list[str] = []
    for pattern in (
        r"发送日期[：:]\s*</[^>]+>\s*([^<\r\n]+)",
        r"(?:sent|date)[：:]\s*</[^>]+>\s*([^<\r\n]+)",
        r'"(?:sentAt|sent_at|receivedAt|received_at|date)"\s*:\s*"([^"]+)"',
    ):
        candidates.extend(match.group(1) for match in re.finditer(pattern, text, flags=re.IGNORECASE))
    for raw in candidates:
        value = re.sub(r"<[^>]+>", "", html.unescape(str(raw or ""))).strip()
        for fmt in (
            "%m/%d/%Y, %I:%M:%S %p",
            "%m/%d/%Y %I:%M:%S %p",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                parsed = datetime.datetime.strptime(value, fmt)
                return parsed.replace(tzinfo=datetime.timezone.utc).timestamp()
            except ValueError:
                continue
    return 0.0


def extractVerificationCode(
    pageText: str,
    *,
    keywords: list[str],
    blockedCodes: Optional[set[str]] = None,
) -> Optional[str]:
    """
    功能目的：
        从页面文本中提取 6 位验证码。

    参数说明：
        pageText:
            页面正文文本（通常来自页面的 innerText / inner_text）。
        keywords:
            关键词列表；优先在关键词附近寻找验证码，提高准确率。
        blockedCodes:
            已经判定为无效/已使用的验证码集合，用于去重（可选）。

    返回值：
        str | None：
            找到则返回验证码字符串（6 位），找不到返回 None。

    可能抛出的异常：
        不抛出异常（解析失败直接返回 None）。

    重要副作用或注意事项：
        - 本函数只做“文本解析”，不涉及登录、取码、规避检测等动作。
        - 页面文本可能包含多个 6 位数字，这里使用“关键词邻近策略 + 去重”降低误判。
        - 会过滤 HTML 邮件里的 CSS 颜色值（如 #202123）和链接里的数字片段。
    """

    rawText = "" if pageText is None else str(pageText)
    normalizedText = _normalize_mail_preview_text(rawText)
    blockedCodeSet = {str(value) for value in (blockedCodes or set()) if str(value)}

    def _accept(codeValue: str, *, sourceText: str = "", matchStart: int = -1) -> Optional[str]:
        if not _is_plausible_otp_code(codeValue, sourceText=sourceText, matchStart=matchStart):
            return None
        if codeValue in blockedCodeSet:
            return None
        return codeValue

    # 1) 优先匹配明确的“temporary code / 验证码”模板。
    for pattern in _explicitOtpPatterns:
        for match in pattern.finditer(normalizedText):
            accepted = _accept(match.group(1), sourceText=normalizedText, matchStart=match.start(1))
            if accepted:
                return accepted

    # 2) 关键词邻近扫描：命中率更高，误判更低。
    lowerText = normalizedText.lower()
    for keyword in keywords:
        safeKeyword = str(keyword or "").strip()
        if not safeKeyword:
            continue
        keywordLower = safeKeyword.lower()
        index = lowerText.find(keywordLower)
        if index < 0:
            continue

        # 设计意图：与扩展逻辑对齐，优先扫描关键词后 200 字符，同时兼容前 50 字符的“倒序模板”。
        scanStart = max(0, index - 50)
        scanEnd = min(len(normalizedText), index + 200)
        windowText = normalizedText[scanStart:scanEnd]

        for match in sixDigitCodeRegex.finditer(windowText):
            accepted = _accept(
                match.group(1),
                sourceText=windowText,
                matchStart=match.start(1),
            )
            if accepted:
                return accepted

    # 3) 兜底：全局扫描清洗后的正文。
    for match in sixDigitCodeRegex.finditer(normalizedText):
        accepted = _accept(
            match.group(1),
            sourceText=normalizedText,
            matchStart=match.start(1),
        )
        if accepted:
            return accepted

    return None


async def collectAllFrameTexts(page: Page) -> str:
    """
    功能目的：
        收集 Page 内“主文档 + 所有 iframe”的可见文本，用于验证码解析兜底。

    参数说明：
        page:
            Playwright Page 对象。

    返回值：
        str：
            拼接后的文本（可能为空字符串）。

    可能抛出的异常：
        不抛出异常；单个 frame 读取失败会被忽略。

    重要副作用或注意事项：
        - 设计意图：2925 邮件正文有时会渲染在 iframe 中，只读主页面会漏掉验证码。
        - 这里优先用 frame.evaluate 直接读 innerText，避免依赖具体 DOM 结构。
    """

    frameTexts: list[str] = []

    for frame in page.frames:
        try:
            textValue = await frame.evaluate("() => (document.body ? document.body.innerText : '')")
        except Exception:
            # 兼容：跨域 iframe 或 frame 尚未就绪时可能报错，这里直接忽略。
            continue

        safeText = "" if textValue is None else str(textValue).strip()
        if safeText:
            frameTexts.append(safeText)

    return "\n".join(frameTexts)


def maskEmail(email: str) -> str:
    """
    功能目的：
        对邮箱做简单脱敏显示，避免在控制台日志里泄露完整账号。

    参数说明：
        email:
            原始邮箱字符串。

    返回值：
        str：
            脱敏后的邮箱（示例：ab***yz@domain.com）；若无法解析则返回 "***"。

    可能抛出的异常：
        不抛出异常。

    重要副作用或注意事项：
        - 这是“显示层”脱敏，不影响真实业务逻辑。
    """

    emailValue = (email or "").strip()
    if "@" not in emailValue:
        return "***"

    localPart, domainPart = emailValue.split("@", 1)
    localPart = localPart.strip()
    domainPart = domainPart.strip()
    if not localPart or not domainPart:
        return "***"

    if len(localPart) <= 2:
        maskedLocal = f"{localPart[0]}***" if localPart else "***"
    else:
        maskedLocal = f"{localPart[:2]}***{localPart[-2:]}"

    return f"{maskedLocal}@{domainPart}"
