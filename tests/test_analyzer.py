from pathlib import Path

import pytest

from safety_assessment.analyzer import analyze


@pytest.mark.parametrize("kind, expected", [("unsafe", {"SQL_INJECTION", "COMMAND_INJECTION"}), ("safe", set())])
def test_example_pairs(kind, expected):
    source = Path(__file__).parents[1] / "src" / "safety_assessment" / "examples" / kind / "app.py"
    findings = analyze(source.read_text(encoding="utf-8"), "app.py")
    assert {finding["rule_id"] for finding in findings} == expected
    assert len(findings) == len(expected)


@pytest.mark.parametrize("source,rule", [
    ('import os\ndef run(value):\n os.system(value)', "COMMAND_INJECTION"),
    ('from subprocess import run as execute\ndef action(value):\n execute(value, shell=True)', "COMMAND_INJECTION"),
    ('value = input()\neval(value)', "CODE_INJECTION"),
    ('def run(cursor, value):\n query = "select "\n query += value\n cursor.execute(query)', "SQL_INJECTION"),
    ('def run(cursor, value, check):\n if check:\n  query = value\n else:\n  query = "select 1"\n cursor.execute(query)', "SQL_INJECTION"),
])
def test_rules_and_aliases(source, rule):
    findings = analyze(source, "test.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == rule
    assert findings[0]["line_number"] > 0
    assert findings[0]["evidence_text"]


@pytest.mark.parametrize("source", [
    'import subprocess\ndef run(value):\n subprocess.run(["ping", value], shell=False)',
    'def run(cursor, value):\n cursor.execute("select ?", (value,))',
    'import os\ndef run(value):\n value = "constant"\n os.system(value)',
    '# eval(input())\ntext = "os.system(user_input)"',
])
def test_safe_patterns(source):
    assert analyze(source, "test.py") == []
