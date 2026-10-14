"""Tests for redloop v0.6.0 fixes.

Covers the two fixes shipped in v0.6.0:

fix-release-ships-zero-assets
    The release workflow built ``dist/`` (wheel + sdist + checksums) but its
    last step was ``actions/upload-artifact`` — a CI artifact private to the
    workflow run — and no step ever uploaded anything to the GitHub Release.
    The shipped v0.5.0 release has ZERO downloadable assets even though its
    release run (34520117995) completed success. A ``publish`` job now
    downloads the artifact and ``gh release upload``s it onto the release.
    ``TestReleaseWorkflowAttachesAssets`` pins the two steps whose ABSENCE
    caused the silent failure (a missing step is invisible to every runtime
    test, so the regression is asserted at the workflow source level).

fix-cli-input-error-tracebacks
    Four user-input error paths dumped raw internal tracebacks instead of one
    named error + exit code 2: a malformed ``redloop.toml`` leaked ~40 frames
    of ``tomllib`` internals ending in ``TOMLDecodeError``;
    ``[attacker] n_attacks = "eight"`` leaked ``ValueError`` from the unguarded
    ``int()`` coercion (redloop/config.py); ``--config <directory>`` leaked
    ``IsADirectoryError``; and an unwritable ``--emit`` path leaked
    ``PermissionError``/``NotADirectoryError`` from ``emit_jsonl``'s ``mkdir``.
    ``TestCliConfigErrorBoundary`` and ``TestCliEmitErrorBoundary`` pin the
    CLI's boundary: one actionable ``Invalid config file ...`` /
    ``Cannot write ...`` line, exit code 2, and no leaked internal exception
    names. Emit repros use a REGULAR FILE as the emit parent (a uid-independent
    ``NotADirectoryError``), not a chmod-000 directory, so they stay valid
    under a root test runner.

Runnable with::

    pytest tests/test_v060.py
    python tests/test_v060.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make ``redloop`` importable without an installed package.
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from typer.testing import CliRunner  # noqa: E402

from redloop.cli import app  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parent.parent

runner = CliRunner()


class TestReleaseWorkflowAttachesAssets(unittest.TestCase):
    """fix-release-ships-zero-assets: the release workflow must attach dist to the release."""

    def setUp(self):
        self.text = (_REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

    def test_workflow_uploads_dist_to_the_release(self):
        # The exact missing step that left v0.5.0 with zero assets: the build
        # job ended at upload-artifact and nothing ever called
        # `gh release upload`.
        self.assertIn("gh release upload", self.text)

    def test_workflow_has_a_publish_job_that_downloads_the_artifact(self):
        self.assertIn("publish:", self.text)
        self.assertIn("actions/download-artifact", self.text)

    def test_workflow_generates_checksums(self):
        self.assertIn("checksums.txt", self.text)


class TestCliConfigErrorBoundary(unittest.TestCase):
    """fix-cli-input-error-tracebacks: config failures print one named error + exit 2."""

    def test_malformed_toml_prints_named_error_and_exits_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "redloop.toml"
            cfg.write_text("this is not valid toml [[[\n", encoding="utf-8")
            result = runner.invoke(app, ["run", "--no-emit", "--config", str(cfg)])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Invalid config file", result.output)
        # The raw internal exception name must not leak (v0.5.0 behavior).
        self.assertNotIn("TOMLDecodeError", result.output)

    def test_bad_config_value_type_prints_named_error_and_exits_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "redloop.toml"
            cfg.write_text('[attacker]\nn_attacks = "eight"\n', encoding="utf-8")
            result = runner.invoke(app, ["run", "--no-emit", "--config", str(cfg)])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Invalid config file", result.output)
        self.assertNotIn("ValueError", result.output)

    def test_directory_as_config_prints_named_error_and_exits_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "adir"
            cfg.mkdir()
            result = runner.invoke(app, ["run", "--no-emit", "--config", str(cfg)])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Invalid config file", result.output)
        self.assertNotIn("IsADirectoryError", result.output)

    def test_missing_config_file_still_falls_back_to_defaults(self):
        # Guard: the boundary must not break the documented default path (a
        # missing config file returns defaults so the keyless run works).
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "absent.toml"
            result = runner.invoke(app, ["run", "--no-emit", "--config", str(cfg)])
        self.assertEqual(result.exit_code, 0)


class TestCliEmitErrorBoundary(unittest.TestCase):
    """fix-cli-input-error-tracebacks: emit-write failures print one named error + exit 2."""

    def _blocked_emit_path(self, td: str) -> Path:
        # A regular FILE as the emit parent: emit_jsonl's
        # mkdir(parents=True) then fails with NotADirectoryError —
        # deterministic regardless of the runner's uid (a chmod-000 dir
        # would not be, under a root test runner).
        parent = Path(td) / "afile"
        parent.write_text("not a directory\n", encoding="utf-8")
        return parent / "sub" / "out.jsonl"

    def test_probe_emit_to_blocked_path_prints_named_error_and_exits_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            emit = self._blocked_emit_path(td)
            result = runner.invoke(app, ["probe", "--emit", str(emit)])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Cannot write", result.output)
        self.assertNotIn("NotADirectoryError", result.output)
        self.assertNotIn("Traceback", result.output)

    def test_run_emit_to_blocked_path_prints_named_error_and_exits_2(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            emit = self._blocked_emit_path(td)
            result = runner.invoke(
                app, ["run", "--emit", str(emit), "--config", str(Path(td) / "absent.toml")]
            )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Cannot write", result.output)
        self.assertNotIn("Traceback", result.output)

    def test_probe_without_emit_still_works(self):
        # Guard: the dry-run default (no file written) is unaffected.
        result = runner.invoke(app, ["probe"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("HIJACKED", result.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
