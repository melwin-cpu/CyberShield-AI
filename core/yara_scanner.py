
"""
CyberShield AI - YARA Scanner
Scans files against local YARA rules.

Install dependency:
    pip install yara-python
"""

import os
from pathlib import Path

try:
    import yara
except ImportError:
    yara = None


# Project directories
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules" / "yara"


# Starter rules for basic pattern detection.
# These are demonstrations, not a complete malware detection database.
STARTER_RULES = r'''
rule CyberShield_Suspicious_Test_String
{
    meta:
        description = "Detects a harmless test marker"
        severity = "Low"
        author = "CyberShield AI"

    strings:
        $marker = "CYBERSHIELD_YARA_TEST_MARKER"

    condition:
        $marker
}

rule CyberShield_EICAR_Test
{
    meta:
        description = "Detects the EICAR antivirus test signature"
        severity = "High"
        author = "CyberShield AI"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}
'''


def get_rules_path():
    """Return the local YARA rules directory."""
    return RULES_DIR


def compile_rules():
    """
    Compile .yar and .yara files from the rules directory.
    If no rule files exist, compile the built-in starter rules.
    """
    if yara is None:
        raise RuntimeError(
            "yara-python is not installed. Run: pip install yara-python"
        )

    rule_files = {}

    if RULES_DIR.exists():
        for path in RULES_DIR.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".yar", ".yara"}:
                # Unique namespace for each rules file
                namespace = f"rules_{len(rule_files)}"
                rule_files[namespace] = str(path)

    if rule_files:
        try:
            return yara.compile(filepaths=rule_files)
        except yara.Error as exc:
            raise RuntimeError(f"Could not compile YARA rules: {exc}") from exc

    try:
        return yara.compile(source=STARTER_RULES)
    except yara.Error as exc:
        raise RuntimeError(f"Could not compile starter YARA rules: {exc}") from exc


def scan_file(file_path, timeout=15):
    """
    Scan one file.

    Return format:
    {
        "success": True,
        "matches": [
            {
                "rule": "RuleName",
                "severity": "High",
                "description": "Rule description",
                "tags": []
            }
        ],
        "error": ""
    }
    """
    result = {
        "success": False,
        "matches": [],
        "error": ""
    }

    try:
        if yara is None:
            result["error"] = (
                "yara-python is not installed. Run: pip install yara-python"
            )
            return result

        path = Path(file_path)

        if not path.exists():
            result["error"] = "File does not exist."
            return result

        if not path.is_file():
            result["error"] = "The selected path is not a file."
            return result

        rules = compile_rules()
        matches = rules.match(str(path), timeout=timeout)

        for match in matches:
            metadata = getattr(match, "meta", {}) or {}

            result["matches"].append({
                "rule": str(match.rule),
                "severity": str(metadata.get("severity", "Unknown")),
                "description": str(
                    metadata.get("description", "No description provided")
                ),
                "tags": list(getattr(match, "tags", []) or [])
            })

        result["success"] = True

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result


def test_yara_scanner():
    """Run a basic self-test using the harmless built-in test marker."""
    if yara is None:
        return {
            "success": False,
            "matches": [],
            "error": "yara-python is not installed."
        }

    import tempfile

    test_marker = "CYBERSHIELD_YARA_TEST_MARKER"

    try:
        rules = yara.compile(source=STARTER_RULES)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False
        ) as temp_file:
            temp_file.write(test_marker)
            temp_path = temp_file.name

        try:
            matches = rules.match(temp_path, timeout=5)

            return {
                "success": True,
                "matches": [
                    {
                        "rule": str(match.rule),
                        "severity": str(
                            getattr(match, "meta", {}).get("severity", "Unknown")
                        ),
                        "description": str(
                            getattr(match, "meta", {}).get(
                                "description", "No description provided"
                            )
                        ),
                        "tags": list(getattr(match, "tags", []) or [])
                    }
                    for match in matches
                ],
                "error": ""
            }
        finally:
            os.unlink(temp_path)

    except Exception as exc:
        return {
            "success": False,
            "matches": [],
            "error": f"{type(exc).__name__}: {exc}"
        }


if __name__ == "__main__":
    print("CyberShield AI - YARA Scanner Test")
    print("-" * 40)
    print(test_yara_scanner())
