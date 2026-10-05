"""Keep the declared Python version consistent across the repository.

Renovate manages `python-version` in the workflow files through a custom manager.
Nothing teaches it that ruff's `target-version` in pyproject.toml encodes the same
number in a different notation, so a Python bump would otherwise leave ruff
linting against the old language level with no signal. This test is the signal.
"""

import pathlib
import re
import tomllib
import unittest

ROOT = pathlib.Path(__file__).parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
PYTHON_VERSION = re.compile(r"""python-version:\s+['"]?(\d+\.\d+)['"]?""")


def declared_workflow_versions() -> dict[str, set[str]]:
    return {
        path.name: set(PYTHON_VERSION.findall(path.read_text(encoding="utf-8")))
        for path in WORKFLOWS
    }


class PythonVersionContractTest(unittest.TestCase):
    def test_the_custom_manager_regex_still_matches_something(self):
        # If a workflow is reformatted so the regex stops matching, Renovate goes
        # quiet rather than failing. Fail here instead.
        found = declared_workflow_versions()
        self.assertTrue(WORKFLOWS, "no workflow files were discovered")
        for name, versions in found.items():
            self.assertTrue(
                versions,
                f"{name} declares no python-version the Renovate custom manager can match",
            )

    def test_every_workflow_agrees_on_one_python_version(self):
        found = declared_workflow_versions()
        distinct = set().union(*found.values())
        self.assertEqual(
            len(distinct),
            1,
            f"workflows disagree on the Python version: {found}",
        )

    def test_ruff_target_version_matches_the_workflow_python_version(self):
        distinct = set().union(*declared_workflow_versions().values())
        workflow_version = distinct.pop()

        pyproject = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        target = pyproject["tool"]["ruff"]["target-version"]

        major, minor = workflow_version.split(".")
        self.assertEqual(
            target,
            f"py{major}{minor}",
            "ruff target-version must track the Python version CI runs on; "
            "update pyproject.toml in the same change as the workflow bump",
        )


if __name__ == "__main__":
    unittest.main()
