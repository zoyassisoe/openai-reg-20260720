from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLCORE = ROOT / "X9-Free" / "_credential_toolcore"
for candidate in (str(ROOT), str(TOOLCORE)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from code_utils import defaultCodeKeywords, extractVerificationCode  # noqa: E402


class CodeUtilsTests(unittest.TestCase):
    def test_extract_skips_css_hex_colors_and_finds_real_code(self):
        html = """
        <html><head>
        <style>.top{color:#202123}.main{color:#353740}</style>
        <title>Your temporary ChatGPT login code</title>
        </head><body>
        <div class="top" style="background-color: #ffffff;color:#202123;"></div>
        <td style="background-color: #ffffff;color:#353740;">
          <p>enter this temporary code:</p>
          <p>490780</p>
          <a href="https://u20216706.ct.sendgrid.net/ls/click?upn=abc">Open</a>
        </td>
        </body></html>
        """
        self.assertEqual(
            extractVerificationCode(html, keywords=defaultCodeKeywords, blockedCodes=set()),
            "490780",
        )

    def test_extract_respects_blocked_codes(self):
        text = "Your temporary ChatGPT login code is 123456"
        self.assertEqual(
            extractVerificationCode(text, keywords=defaultCodeKeywords, blockedCodes={"123456"}),
            None,
        )


if __name__ == "__main__":
    unittest.main()
