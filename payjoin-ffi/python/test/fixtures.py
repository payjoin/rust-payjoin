from pathlib import Path

_FIXTURES = Path(__file__).resolve().parents[3] / "payjoin-test-utils" / "fixtures"

ORIGINAL_PSBT = (_FIXTURES / "original-psbt.base64").read_text(encoding="ascii")
OHTTP_KEYS = bytes.fromhex((_FIXTURES / "ohttp-keys.hex").read_text(encoding="ascii"))
