"""Regression checks for the public v1.0 release boundary."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseContractTests(unittest.TestCase):
    def test_runtime_diagnostic_module_is_bundled_in_the_container(self) -> None:
        containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.assertIn("exposure_doctor.py", containerfile)
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

    def test_release_sbom_and_provenance_are_detached_from_runtime_image(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        release_notes = (ROOT / "docs/RELEASES.md").read_text(encoding="utf-8")

        self.assertIn("sbom: false", publish)
        self.assertIn("provenance: false", publish)
        self.assertIn("anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610", publish)
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

    def test_router_local_updater_fetch_is_cache_fresh_and_redirect_bounded(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )

        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn("check-certificate=yes", executable)
        self.assertIn("http-max-redirect-count=2", executable)
        self.assertIn("routeros-cache-bust=", executable)
        self.assertIn("manifestRequestUrl", executable)
        self.assertIn("/system/clock/get date", executable)
        self.assertIn("/system/clock/get time", executable)
        self.assertIn(":local readinessTransport do=", executable)
        self.assertIn("mode=http", executable)
        self.assertIn(":toip $host", executable)
        self.assertIn('"http://192.168.250.2:8080/readyz"', updater)
        self.assertIn(':local canaryContainer "vpn-dashboard-canary"', updater)
        self.assertIn(':local productionContainer "vpn-dashboard-production"', updater)
        self.assertIn('"\\\"revision\\\":\\\""', updater)
        self.assertIn("productionCurrentCommit", executable)
        self.assertIn("historyFile", executable)
        self.assertIn('event=" . $event', executable)
        self.assertIn('$recordHistory "promoted"', updater)
        self.assertIn("canaryValidationSeconds", executable)
        self.assertIn("canary stability gate failed", executable)
        self.assertIn("github.com/aivanov2-godaddy/mikrotik-openvpn-gui/releases/download/routeros-stable/routeros-release.json", updater)
        self.assertIn("ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-", updater)
        self.assertNotIn("github.com/CHANGE-ME/mikrotik-openvpn-gui", updater)
        self.assertNotIn("ghcr.io/CHANGE-ME/mikrotik-openvpn-gui", updater)
        self.assertNotIn(":import", executable)
        self.assertNotIn(":parse", executable)

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
