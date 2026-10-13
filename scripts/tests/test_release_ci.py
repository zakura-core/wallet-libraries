import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("release_ci", Path(__file__).parents[1] / "release-ci.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
SHA = "a" * 40


class ReleaseCiTests(unittest.TestCase):
    def workflow_run(self, **changes):
        run = {"head_sha": SHA, "head_branch": "main", "event": "push", "run_number": 1,
               "run_attempt": 1, "status": "completed", "conclusion": "success",
               "html_url": "https://github.com/zakura-core/wallet-libraries/actions/runs/1"}
        run.update(changes)
        return run

    def test_only_successful_main_ci_for_the_exact_commit_is_accepted(self):
        bad = ([], [self.workflow_run(head_sha="b" * 40)],
               [self.workflow_run(head_branch="other")], [self.workflow_run(event="pull_request")],
               [self.workflow_run(status="in_progress", conclusion=None)],
               [self.workflow_run(conclusion="failure")], [self.workflow_run(conclusion="cancelled")])
        for runs in bad:
            with self.subTest(runs=runs), \
                 patch.object(ci.subprocess, "check_output", return_value=json.dumps({"workflow_runs": runs})):
                with self.assertRaises(ValueError):
                    ci.require_verified_ci(ci.REPOSITORY, SHA)
        with patch.object(ci.subprocess, "check_output", return_value=json.dumps({"workflow_runs": [self.workflow_run()]})) as api:
            ci.require_verified_ci(ci.REPOSITORY, SHA)
            self.assertIn("actions/workflows/verify.yml", api.call_args.args[0][-1])

    def test_a_failed_new_attempt_does_not_reuse_an_old_success(self):
        runs = [self.workflow_run(), self.workflow_run(run_attempt=2, conclusion="failure")]
        with patch.object(ci.subprocess, "check_output", return_value=json.dumps({"workflow_runs": runs})):
            with self.assertRaises(ValueError):
                ci.require_verified_ci(ci.REPOSITORY, SHA)

    def receipt(self, result="published"):
        return {"commit": SHA, "verification_passed": True,
                "packages": [{"name": "example", "version": "1.0.0", "registry_status": "available", "result": result}]}

    def version(self, **changes):
        version = {"yanked": False, "trustpub_data": {"provider": "github", "repository": ci.REPOSITORY,
                                                    "run_id": 10, "sha": SHA}}
        version.update(changes)
        return version

    def test_new_versions_require_this_runs_registry_attribution(self):
        for attestation in (None, {"provider": "github", "repository": "other/repo", "run_id": 10, "sha": SHA},
                            {"provider": "github", "repository": ci.REPOSITORY, "run_id": 11, "sha": SHA},
                            {"provider": "github", "repository": ci.REPOSITORY, "run_id": 10, "sha": "b" * 40}):
            with self.subTest(attestation=attestation), patch.object(ci, "registry_record", return_value=self.version(trustpub_data=attestation)):
                with self.assertRaises(ValueError):
                    ci.confirm_publication(self.receipt(), ci.REPOSITORY, "10", SHA)
        with patch.object(ci, "registry_record", return_value=self.version()):
            ci.confirm_publication(self.receipt(), ci.REPOSITORY, "10", SHA)

    def test_existing_versions_are_confirmed_without_claiming_this_run_published_them(self):
        with patch.object(ci, "registry_record", return_value=self.version(trustpub_data=None)):
            ci.confirm_publication(self.receipt("previously_available"), ci.REPOSITORY, "10", SHA)

    def test_yanked_and_missing_versions_fail_confirmation(self):
        with patch.object(ci, "registry_record", return_value=self.version(yanked=True)):
            with self.assertRaises(ValueError):
                ci.confirm_publication(self.receipt(), ci.REPOSITORY, "10", SHA)
        with patch.object(ci, "registry_record", side_effect=OSError("unavailable")):
            with self.assertRaises(ValueError):
                ci.confirm_publication(self.receipt(), ci.REPOSITORY, "10", SHA)

    def test_partial_publication_stays_incomplete(self):
        with patch.object(ci, "registry_record") as registry:
            with self.assertRaisesRegex(ValueError, "remaining"):
                ci.confirm_publication(self.receipt("remaining"), ci.REPOSITORY, "10", SHA)
            registry.assert_not_called()
        self.assertIn("remaining", ci.summarize(self.receipt("remaining")))


if __name__ == "__main__":
    unittest.main()
