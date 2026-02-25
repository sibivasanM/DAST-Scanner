"""
side_parser.py
Parses Selenium IDE .side files and extracts executable test commands.
"""

import json
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SideCommand:
    id: str
    command: str
    target: str
    value: str
    comment: str = ""
    targets: List[List[str]] = field(default_factory=list)


@dataclass
class SideTest:
    id: str
    name: str
    commands: List[SideCommand]


@dataclass
class SideProject:
    id: str
    version: str
    name: str
    url: str
    tests: List[SideTest]


def parse_side_file(filepath: str) -> SideProject:
    """Parse a .side file and return structured project data."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    tests = []
    for test in data.get("tests", []):
        commands = []
        for cmd in test.get("commands", []):
            commands.append(SideCommand(
                id=cmd.get("id", ""),
                command=cmd.get("command", ""),
                target=cmd.get("target", ""),
                value=cmd.get("value", ""),
                comment=cmd.get("comment", ""),
                targets=cmd.get("targets", [])
            ))
        tests.append(SideTest(
            id=test.get("id", ""),
            name=test.get("name", ""),
            commands=commands
        ))

    return SideProject(
        id=data.get("id", ""),
        version=data.get("version", ""),
        name=data.get("name", ""),
        url=data.get("url", ""),
        tests=tests
    )


def get_login_test(project: SideProject) -> Optional[SideTest]:
    """Try to auto-detect the login/auth test from the project."""
    keywords = ["login", "auth", "signin", "sign_in", "log_in", "authentication"]
    for test in project.tests:
        if any(kw in test.name.lower() for kw in keywords):
            return test
    # Fallback: return first test
    return project.tests[0] if project.tests else None


def summarize(project: SideProject) -> dict:
    """Return a human-readable summary of the parsed project."""
    return {
        "project_name": project.name,
        "base_url": project.url,
        "total_tests": len(project.tests),
        "tests": [
            {
                "name": t.name,
                "command_count": len(t.commands),
                "commands": [{"command": c.command, "target": c.target, "value": c.value} for c in t.commands]
            }
            for t in project.tests
        ]
    }
