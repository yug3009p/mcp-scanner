import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # make `import scanner` work without installing


@pytest.fixture
def load_sample():
    def _load(name: str) -> dict:
        return json.loads((ROOT / "samples" / f"{name}.json").read_text(encoding="utf-8"))

    return _load
