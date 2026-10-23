"""Regression checks for the public v1.0 release boundary."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseContractTests(unittest.TestCase):
    def test_write_enabled_manual_workflows_are_restricted_to_default_branch(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        container = (workflows / "container.yml").read_text(encoding="utf-8")
        release_notes = (workflows / "release-notes.yml").read_text(encoding="utf-8")

        def condition(source: str, job_name: str) -> str | None:
            job_marker = f"  {job_name}:\n"
            self.assertIn(job_marker, source)
            job_start = source.index(job_marker) + len(job_marker)
            next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", source[job_start:])
            job = source[job_start : job_start + next_job.start()] if next_job else source[job_start:]
            folded_condition = re.search(
                r"(?m)^    if: >-\n((?:^ {6,}[^\n]*\n)+)", job
            )
            if not folded_condition:
                return None
            return " ".join(line.strip() for line in folded_condition.group(1).splitlines())

        self.assertIn("  workflow_dispatch:\n", container)
        self.assertIn("  workflow_dispatch:\n", release_notes)
        publish_job = container.split("  publish:\n", maxsplit=1)[1].split(
            "  publish-stable-manifest:\n", maxsplit=1
        )[0]
        self.assertIn("packages: write", publish_job)
        self.assertIn("attestations: write", publish_job)
        self.assertEqual(
            condition(container, "publish"),
            "github.event_name != 'workflow_dispatch' || "
            "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
        )
        self.assertEqual(
            condition(release_notes, "release"),
            "github.event_name == 'push' || "
            "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
        )
        self.assertIn("  contents: write\n", release_notes)

        release_job = release_notes.split("  release:\n", maxsplit=1)[1]
        self.assertIn("if: github.event_name == 'push' || inputs.dry_run == false", release_job)

        manifest_job = container.split("  publish-stable-manifest:\n", maxsplit=1)[1]
        self.assertIn("      contents: write\n", manifest_job)
        self.assertEqual(
            condition(container, "publish-stable-manifest"),
            "github.event_name == 'push' && "
            "(github.ref == format('refs/heads/{0}', github.event.repository.default_branch) || "
            "(github.ref_type == 'tag' && startsWith(github.ref_name, 'v')))",
        )

    def test_container_digest_summary_is_strict_and_does_not_interpret_markdown(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        step = publish.split("      - name: Record immutable digest\n", maxsplit=1)[1].split(
            "      - name:", maxsplit=1
        )[0]

        self.assertIn("set -euo pipefail", step)
        self.assertIn("printf '%s\\n' '- Platform: ${{ matrix.platform }}'", step)
        self.assertIn("printf '%s\\n' '- Architecture tag suffix: ${{ matrix.suffix }}'", step)
        self.assertNotIn('echo "- Platform: `', step)
        self.assertNotIn('echo "- Architecture tag suffix: `', step)

    def test_runtime_diagnostic_module_is_bundled_in_the_container(self) -> None:
        containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.assertIn("exposure_doctor.py", containerfile)
        self.assertIn("certificate_lifecycle.py", containerfile)
        workflows = ROOT / ".github" / "workflows"
        for workflow in ("ci.yml", "container.yml"):
            self.assertIn("exposure_doctor.py", (workflows / workflow).read_text(encoding="utf-8"))

    def test_public_repository_has_no_router_deployment_workflow(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        self.assertFalse((workflows / "deploy-production.yml").exists())
        self.assertFalse((workflows / "validate-routeros-canary.yml").exists())

        publish = (workflows / "container.yml").read_text(encoding="utf-8")
        self.assertIn("ghcr.io/${{ github.repository }}", publish)
        self.assertIn('".github/workflows/container.yml"', publish)
        self.assertIn('"scripts/routeros/immutable-release-updater.rsc.example"', publish)
        self.assertIn("publish-stable-manifest", publish)
        self.assertIn("github.ref_type == 'tag'", publish)
        self.assertIn("startsWith(github.ref_name, 'v')", publish)
        self.assertNotIn("deploy_routeros_release.py", publish)
        self.assertNotIn("self-hosted", publish)
        self.assertNotIn("ROUTEROS_", publish)

    def test_container_publish_requires_rendered_browser_verification(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        verify = publish.split("  browser-verify:\n", maxsplit=1)[0]
        browser_verify = publish.split("  browser-verify:\n", maxsplit=1)[1].split(
            "  publish:\n", maxsplit=1
        )[0]
        self.assertIn("runs-on: ubuntu-latest", verify)
        self.assertIn("python -m unittest discover -s tests -v", verify)
        self.assertIn("runs-on: windows-latest", browser_verify)
        self.assertIn("npm ci", browser_verify)
        self.assertIn("npx playwright install chromium", browser_verify)
        self.assertIn("npm run test:browser", browser_verify)
        self.assertIn("needs: [verify, browser-verify]", publish)

    def test_stable_manifest_publication_reconciles_and_verifies_readback(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        step = publish.split("      - name: Publish stable manifest asset\n", maxsplit=1)[1].split(
            "      - name:", maxsplit=1
        )[0]

        self.assertIn('gh release upload "$release_tag" routeros-release.json --clobber', step)
        self.assertIn('gh release download "$release_tag"', step)
        self.assertIn('cmp -s routeros-release.json "$verification_dir/routeros-release.json"', step)
        self.assertIn("upload_status=$?", step)
        self.assertIn("reconciled as idempotent success", step)

    def test_release_sbom_and_provenance_are_detached_from_runtime_image(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        release_notes = (ROOT / "docs/RELEASES.md").read_text(encoding="utf-8")

        self.assertIn("sbom: false", publish)
        self.assertIn("provenance: false", publish)
        self.assertIn("anchore/sbom-action@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3", publish)
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2", publish)
        self.assertIn("subject-digest: ${{ steps.build.outputs.digest }}", publish)
        self.assertIn("image: ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}", publish)
        self.assertIn("push-to-registry: false", publish)
        self.assertIn("upload-release-assets: false", publish)
        self.assertIn("gh attestation verify \"oci://$IMAGE\"", publish)
        self.assertIn("--signer-workflow \"$signer_workflow\"", publish)
        self.assertIn("--source-digest \"$SOURCE_COMMIT\"", publish)
        self.assertIn('predicate_args=(--predicate-type "$predicate_type")', publish)
        self.assertIn('verify_attestation "https://spdx.dev/Document/v2.3"', publish)
        self.assertIn('IMAGE="ghcr.io/${REPOSITORY}@${DIGEST}"', release_notes)
        self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", release_notes)
        self.assertIn("--signer-workflow", release_notes)
        self.assertIn("--source-digest", release_notes)
        self.assertIn("not embedded in the image or pushed as OCI", release_notes)
        self.assertIn("Compatibility and validation matrix", release_notes)
        self.assertIn("ARM32 / ARMv5", release_notes)

    def test_release_documentation_describes_the_safe_boundary(self) -> None:
        release_notes = (ROOT / "docs/RELEASES.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs/DEPLOYMENT.md").read_text(encoding="utf-8")
        installation = (ROOT / "docs/INSTALLATION.md").read_text(encoding="utf-8")

        self.assertIn("Public-source boundary", release_notes)
        self.assertIn("router-local", deployment)
        self.assertIn("immutable", deployment)
        self.assertIn("router-local scheduler", installation)
        self.assertIn("credentials, environment values, configuration, database data", installation)
        self.assertIn("canary", deployment.casefold())

    def test_operations_runbook_collects_live_evidence_before_evaluation(self) -> None:
        operations = (ROOT / "docs/OPERATIONS.md").read_text(encoding="utf-8")

        self.assertIn("### Live dashboard troubleshooting", operations)
        self.assertIn("Cloudflare Access session and the dashboard's RouterOS sign-in", operations)
        self.assertIn("before restarting\ncontainers", operations)
        self.assertIn("scripts/collect_release_acceptance.py", operations)
        self.assertIn("--phase canary-prepromotion", operations)
        self.assertIn("private-collected-evidence.json", operations)
        self.assertIn("Run the RouterOS read-only sampler and app collector concurrently", operations)
        self.assertIn("--routeros-report private-routeros-window.json", operations)
        self.assertIn("never promotes or rolls back", operations)
        self.assertIn("readiness-only", operations)
        self.assertIn("scripts/promote_routeros_release.py", operations)
        self.assertIn("cannot update production after the readiness-only", operations)

    def test_router_local_updater_fetch_is_cache_fresh_and_redirect_bounded(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )

        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn("check-certificate=yes", executable)
        self.assertIn("http-max-redirect-count=2", executable)
        self.assertIn('"?cb=" . [:rndnum from=100000 to=999999]', executable)
        self.assertIn("manifestRequestUrl", executable)
        self.assertNotRegex(executable, r":local\s+[A-Za-z][A-Za-z0-9_]*=")
        self.assertIn(":local readinessTransport do=", executable)
        self.assertIn("mode=http", executable)
        self.assertIn(":toip $host", executable)
        self.assertIn('"http://192.168.250.2:8080/readyz"', updater)
        self.assertIn(':local canaryContainer "vpn-dashboard-canary"', updater)
        self.assertIn(':local productionContainer "vpn-dashboard-production"', updater)
        self.assertIn('"\\\"revision\\\":\\\""', updater)
        self.assertIn(":onerror fetchError,fetchAttributes in={", executable)
        self.assertIn(":onerror updaterError,updaterErrorAttributes in={", executable)
        self.assertIn('update failed; step=" . $updaterStep . "; details redacted', executable)
        for step in (
            "manifest-fetch",
            "manifest-response-check",
            "manifest-parse",
            "candidate-validation",
            "readiness-configuration",
            "failure-state-read",
            "container-lookup",
            "container-state-read",
            "pending-state-read",
            "state-directory-probe",
            "canary-lifecycle",
            "canary-readiness",
            "canary-soak",
            "pending-state-write",
            "canary-rollback-lifecycle",
            "canary-rollback-readiness",
            "canary-rollback-soak",
        ):
            self.assertIn(f'"{step}"', executable)
        self.assertNotIn("$updaterError", executable)
        self.assertNotIn("$updaterErrorAttributes", executable)
        self.assertNotIn("see preceding log entry", executable)
        for reason in (
            "fetch-error",
            "http-error-",
            "fetch-incomplete",
            "http-status-",
            "empty-response",
            "not-ready",
            "revision-mismatch",
            "check-error",
        ):
            self.assertIn(reason, executable)
        self.assertIn('result=" . $readinessResult', executable)
        self.assertIn('result=" . $canarySampleResult', executable)
        self.assertNotIn(":log warning $fetchError", executable)
        self.assertNotIn(":log warning $fetchAttributes", executable)
        self.assertNotIn(":log warning $body", executable)
        self.assertNotIn('" . $updaterError', executable)
        self.assertNotIn('" . $updaterErrorAttributes', executable)
        self.assertIn("historyFile", executable)
        self.assertIn('event=" . $event', executable)
        self.assertIn('$recordHistory "canary-staged"', updater)
        self.assertIn('candidate already staged; production unchanged', executable)
        self.assertIn(':local stateDirectory "disk1/vpn-dashboard"', executable)
        self.assertIn(':local pendingFile ($stateDirectory . "/routeros-update-pending.txt")', executable)
        self.assertIn('router-local state directory probe failed; no container changed', executable)
        self.assertIn('($stateDirectory . "/vpn-gui-write-check-"', executable)
        self.assertNotIn('"/.vpn-gui-write-check-"', executable)
        for step in (
            "state-directory-probe-create",
            "state-directory-probe-update",
            "state-directory-probe-verify",
            "state-directory-probe-cleanup",
        ):
            self.assertIn(f'"{step}"', executable)
        self.assertIn(":set updaterStep $stateProbeFailureStep", executable)
        self.assertLess(
            executable.index(":set updaterStep $stateProbeFailureStep"),
            executable.index('router-local state directory probe failed; no container changed'),
        )
        self.assertIn('$writeState $stateProbeFile "probe=created"', executable)
        self.assertIn('$writeState $stateProbeFile $stateProbeContents', executable)
        self.assertIn('[/file/get $stateProbeId contents] != $stateProbeContents', executable)
        self.assertNotIn('$recordHistory "promoted"', executable)
        self.assertNotIn("/container/stop $productionId", executable)
        self.assertNotIn("/container/set $productionId", executable)
        self.assertIn(":local canaryValidationInterval 1m", executable)
        self.assertIn(":local canaryValidationSamples 30", executable)
        self.assertIn(":local pollAttempts 18", executable)
        self.assertIn(":local pollDelay 10s", executable)
        self.assertIn(":if ($canaryValidationSamples < 30)", executable)
        self.assertIn(":if ($canaryValidationInterval < 1m)", executable)
        self.assertIn(":for sample from=1 to=$canaryValidationSamples do={", executable)
        self.assertIn('canary readiness sample " . $sample . "/" . $canaryValidationSamples . " passed revision=" . $commit', executable)
        self.assertIn("canary readiness soak failed", executable)
        self.assertIn("production unchanged", executable)
        self.assertNotIn("canaryValidationSeconds", executable)
        self.assertIn("github.com/aivanov2-godaddy/mikrotik-openvpn-gui/releases/download/routeros-stable/routeros-release.json", updater)
        self.assertIn("ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-", updater)
        self.assertNotIn("github.com/CHANGE-ME/mikrotik-openvpn-gui", updater)
        self.assertNotIn("ghcr.io/CHANGE-ME/mikrotik-openvpn-gui", updater)
        self.assertNotIn(":import", executable)
        self.assertNotIn(":parse", executable)

    def test_router_local_updater_requires_a_sampled_30_minute_canary_gate(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )

        self.assertIn(":local canaryValidationInterval 1m", executable)
        self.assertIn(":local canaryValidationSamples 30", executable)
        self.assertIn(":if ($canaryValidationSamples < 30)", executable)
        self.assertIn(":if ($canaryValidationInterval < 1m)", executable)
        self.assertLess(
            executable.index(":for sample from=1 to=$canaryValidationSamples do={"),
            executable.index('$recordHistory "canary-staged"'),
        )
        self.assertLess(
            executable.index(":if ($canaryValidationSamples < 30)"),
            executable.index("/container/stop $canaryId"),
        )
        self.assertLess(
            executable.index(":if ($canaryValidationInterval < 1m)"),
            executable.index("/container/stop $canaryId"),
        )
        self.assertLess(
            executable.index('$writeState $stateProbeFile "probe=created"'),
            executable.index("/container/stop $canaryId"),
        )
        self.assertIn('$recordFailure $image', executable)
        self.assertIn('"canary readiness soak failed"', executable)

    def test_updater_rolls_back_before_best_effort_failure_journaling(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )

        cases = (
            ("canary lifecycle failed; step=", "canary-rollback-lifecycle", "canary lifecycle gate failed"),
            ("canary readiness failed; step=", "canary-rollback-readiness", "canary readiness gate failed"),
            ("canary soak failed; step=", "canary-rollback-soak", "canary readiness soak failed"),
        )
        for failure_message, rollback_step, terminal_error in cases:
            with self.subTest(rollback_step=rollback_step):
                block_start = executable.index(failure_message)
                block_end = executable.index(f'"{terminal_error}"', block_start)
                block = executable[block_start:block_end]
                self.assertLess(
                    block.index(f':set updaterStep "{rollback_step}"'),
                    block.index(":do { $recordFailure $image } on-error={"),
                )
                self.assertIn(f"step={rollback_step}; details redacted", block)
                self.assertIn("step=failure-state-write; details redacted", block)

    def test_gated_promoter_rechecks_acceptance_before_router_mutation(self) -> None:
        promoter = (ROOT / "scripts" / "promote_routeros_release.py").read_text(encoding="utf-8")

        self.assertIn('evaluate(evidence, now=clock(), phase="canary-prepromotion")', promoter)
        self.assertIn('report.get("promotion_eligible") is not True', promoter)
        self.assertIn("_assert_router_matches(canary, production, candidate_image, prior_image)", promoter)
        self.assertIn("--check-only", promoter)
        self.assertIn("production image changed since acceptance evidence was collected", promoter)

    def test_router_local_updater_noop_paths_do_not_use_top_level_return(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        decision_flow = executable[executable.index(":local failedImage"):]

        self.assertIn(":local skipUpdate false", decision_flow)
        self.assertIn(":if (!$skipUpdate) do={", decision_flow)
        self.assertNotIn(":return", decision_flow)
        self.assertIn("candidate is locally quarantined", decision_flow)
        self.assertIn("production already uses", decision_flow)
        self.assertIn("dry-run accepted candidate", decision_flow)

    def test_updater_supports_a_bounded_local_maintenance_window(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        self.assertIn(":local maintenanceWindowEnabled false", updater)
        self.assertIn("maintenanceStartHour", updater)
        self.assertIn("outside maintenance window", updater)
        self.assertIn("currentHour", updater)

    def test_updater_recovers_stale_global_lock_and_serializes_live_jobs(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        guard = executable[executable.index(":global vpnGuiImmutableUpdateLock"):]
        guard = guard[:guard.index(":do {")]

        self.assertIn("/system script job print count-only as-value where script=[:jobname]", guard)
        self.assertIn(":if ($activeUpdaterRuns > 1) do={", guard)
        self.assertNotIn("if ($vpnGuiImmutableUpdateLock = true)", guard)
        self.assertIn("may remain true after an interrupted\n# run", updater)

    def test_manual_rollback_helper_is_immutable_and_data_safe(self) -> None:
        helper = (ROOT / "scripts" / "routeros" / "rollback-last-good.rsc.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("last-good-image=", helper)
        self.assertIn("/container/update", helper)
        self.assertIn("persistent data was not modified", helper)
        self.assertNotIn("/file/remove", helper)

    def test_router_local_backup_helper_is_private_and_rotating(self) -> None:
        helper = (ROOT / "scripts" / "routeros" / "backup-before-update.rsc.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("/system/backup/save", helper)
        self.assertIn("/export file=", helper)
        self.assertIn("hide-sensitive=yes", helper)
        self.assertIn("slotCount 3", helper)
        self.assertIn("CHANGE-ME-IN-ROUTER", helper)
        self.assertIn("previous slots were preserved", helper)
        self.assertIn("backupPassword", helper)
        self.assertNotIn("wanted.sx", helper)
        self.assertNotIn("/file/remove [find", helper)

    def test_public_distribution_examples_use_the_canonical_repository_name(self) -> None:
        documents = (
            ROOT / "README.md",
            ROOT / "docs/DEPLOYMENT.md",
            ROOT / "docs/ROADMAP.md",
            ROOT / "docs/ROUTER_LOCAL_AUTOMATION.md",
            ROOT / "scripts/routeros/immutable-release-updater.rsc.example",
            ROOT / ".github/ISSUE_TEMPLATE/config.yml",
        )
        rendered = "\n".join(document.read_text(encoding="utf-8") for document in documents)
        self.assertNotIn("mikrotik-openvpn-gui-public", rendered)
        self.assertIn("mikrotik-openvpn-gui", rendered)

    def test_preview_assets_do_not_contain_instance_identities(self) -> None:
        assets = (
            ROOT / "docs/screenshots/dashboard-navigation.svg",
            ROOT / "docs/screenshots/dashboard-sections.svg",
        )
        prohibited = (
            "core" + ".wanted" + ".sx",
            "al" + "ex",
            "sam" + "sung s26 ultra",
        )
        rendered = "\n".join(asset.read_text(encoding="utf-8").lower() for asset in assets)
        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, rendered)

    def test_installation_documents_use_portable_examples(self) -> None:
        documents = (
            ROOT / "README.md",
            ROOT / "docs/INSTALLATION.md",
            ROOT / "docs/REPOSITORY_SETUP.md",
        )
        prohibited = (
            "wanted" + ".sx",
            "rb" + "5009upr+s+",
            "172.31." + "255.",
        )
        rendered = "\n".join(document.read_text(encoding="utf-8").lower() for document in documents)
        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, rendered)


if __name__ == "__main__":
    unittest.main()
