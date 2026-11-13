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

    def test_container_removes_build_only_python_packages_before_rootfs_copy(self) -> None:
        containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.assertIn("scripts/prune_runtime_build_tools.py /tmp/prune_runtime_build_tools.py", containerfile)
        self.assertLess(
            containerfile.index("python /tmp/prune_runtime_build_tools.py"),
            containerfile.index("&& tar -C /"),
        )
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        self.assertIn('      - "scripts/prune_runtime_build_tools.py"', publish)

    def test_runtime_pruner_is_included_in_docker_build_context(self) -> None:
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("scripts", dockerignore)
        self.assertIn("!scripts/", dockerignore)
        self.assertIn("scripts/*", dockerignore)
        self.assertIn("!scripts/prune_runtime_build_tools.py", dockerignore)
        self.assertLess(dockerignore.index("!scripts/"), dockerignore.index("scripts/*"))
        self.assertLess(
            dockerignore.index("scripts/*"),
            dockerignore.index("!scripts/prune_runtime_build_tools.py"),
        )

    def test_every_local_container_copy_input_triggers_mainline_publishing(self) -> None:
        containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        self.assertIn('      - ".dockerignore"', publish)
        for line in containerfile.splitlines():
            if not line.startswith("COPY ") or "--from=" in line:
                continue
            for source in line.split()[1:-1]:
                trigger = "static/**" if source == "static" else source
                with self.subTest(container_input=source):
                    self.assertIn(f'      - "{trigger}"', publish)

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

    def test_version_tag_publish_requires_main_ancestry_and_version_match(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        verify = publish.split("  browser-verify:\n", maxsplit=1)[0]
        gate = verify.split("      - name: Validate tagged release is on main and matches VERSION\n", maxsplit=1)[1]
        gate = gate.split("      - name:", maxsplit=1)[0]

        self.assertIn("fetch-depth: 0", verify)
        self.assertIn("if: github.ref_type == 'tag'", gate)
        self.assertIn("git fetch --no-tags origin", gate)
        self.assertIn('--tag "$GITHUB_REF_NAME"', gate)
        self.assertIn('--main-ref "$main_ref"', gate)
        self.assertIn("needs: [verify, browser-verify]", publish)

        release_docs = (ROOT / "docs" / "RELEASES.md").read_text(encoding="utf-8")
        self.assertIn("commit reachable from the default branch", release_docs)
        self.assertIn("cannot retroactively protect old tag commits", release_docs)
        self.assertIn("repository-level release-tag creation rule", release_docs)

    def test_arm64_and_published_image_smokes_assert_unprivileged_runtime(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        for workflow in ("ci.yml", "container.yml"):
            source = (workflows / workflow).read_text(encoding="utf-8")
            with self.subTest(workflow=workflow):
                self.assertIn("awk '/^Uid:/ { print $2, $3, $4, $5; exit }' /proc/1/status", source)
                self.assertIn('test "$runtime_uids" = "65534 65534 65534 65534"', source)
                self.assertLess(source.index("/readyz"), source.index("runtime_uids="))

    def test_container_publish_scans_immutable_candidate_before_registry_write(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        build_job = workflow.split("  build-candidate:\n", maxsplit=1)[1].split(
            "  scan-candidate:\n", maxsplit=1
        )[0]
        scan_job = workflow.split("  scan-candidate:\n", maxsplit=1)[1].split(
            "  publish:\n", maxsplit=1
        )[0]
        publish_job = workflow.split("  publish:\n", maxsplit=1)[1].split(
            "  publish-stable-manifest:\n", maxsplit=1
        )[0]
        build = build_job.split("      - name: Build candidate image archive\n", maxsplit=1)[1].split(
            "      - name:", maxsplit=1
        )[0]

        for job in (build_job, scan_job):
            with self.subTest(job=job.splitlines()[0]):
                self.assertIn("permissions:\n      contents: read", job)
                self.assertNotIn("packages: write", job)
                self.assertNotIn("id-token: write", job)
                self.assertNotIn("attestations: write", job)
        self.assertIn("outputs: type=docker,dest=${{ github.workspace }}/candidate-image.tar", build)
        artifact = "candidate-image-${{ matrix.suffix }}-${{ github.run_id }}-${{ github.run_attempt }}"
        self.assertIn("Checksum candidate image archive before scan", build_job)
        self.assertLess(
            build_job.index("Checksum candidate image archive before scan"),
            build_job.index("Preserve candidate image archive"),
        )
        self.assertIn(f"name: {artifact}", build_job)
        self.assertIn(f"name: {artifact}", scan_job)
        self.assertIn(f"name: {artifact}", publish_job)
        self.assertIn("needs: [verify, browser-verify, build-candidate]", scan_job)
        self.assertIn("needs: [verify, browser-verify, build-candidate, scan-candidate]", publish_job)
        self.assertIn("Download candidate image archive", scan_job)
        self.assertIn("sha256sum --check candidate-image.tar.sha256", scan_job)
        self.assertIn(
            "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0",
            scan_job,
        )
        self.assertIn("input: candidate-image/candidate-image.tar", scan_job)
        self.assertIn("severity: HIGH,CRITICAL", scan_job)
        self.assertIn("vuln-type: os,library", scan_job)
        self.assertLess(
            scan_job.index("Verify candidate image archive checksum"),
            scan_job.index("Scan candidate image for OS and library vulnerabilities"),
        )
        self.assertLess(
            scan_job.index("Scan candidate image for OS and library vulnerabilities"),
            scan_job.index("Verify candidate image archive unchanged after scan"),
        )
        self.assertLess(
            publish_job.index("Verify scanned image archive checksum and load it"),
            publish_job.index("Sign in to GHCR after the candidate passes its scan"),
        )
        publish_load = publish_job.split(
            "      - name: Verify scanned image archive checksum and load it\n", maxsplit=1
        )[1].split("      - name:", maxsplit=1)[0]
        self.assertLess(
            publish_load.index('sha256sum --check "$IMAGE_ARCHIVE.sha256"'),
            publish_load.index('docker load --input "$IMAGE_ARCHIVE"'),
        )
        self.assertIn("packages: write", publish_job)
        self.assertNotIn("aquasecurity/trivy-action", publish_job)
        qemu_setup = publish_job.split(
            "      - name: Set up QEMU for ARM64 runtime smoke test\n", maxsplit=1
        )[1].split("      - name:", maxsplit=1)[0]
        self.assertIn("if: matrix.platform == 'linux/arm64'", qemu_setup)
        self.assertIn(
            "docker/setup-qemu-action@99012661954931238ded8c8b007157a8430204e1 # v4.4.0",
            qemu_setup,
        )
        self.assertLess(
            publish_job.index("Set up QEMU for ARM64 runtime smoke test"),
            publish_job.index("Smoke-test the published runtime"),
        )
        self.assertIn("docker push \"$PRIMARY_TAG\"", publish_job)
        self.assertIn("python scripts/extract_registry_digest.py", publish_job)
        self.assertIn("printf 'digest=%s", publish_job)
        self.assertIn('>> "$GITHUB_OUTPUT"', publish_job)
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("Scan ARM64 candidate image for OS and library vulnerabilities", ci)
        self.assertIn("image-ref: local/mikrotik-openvpn-gui:ci", ci)

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

    def test_stable_manifest_binds_each_architecture_to_commit_tag_and_digest(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")

        self.assertIn('"schema": 2', publish)
        self.assertIn('f"ghcr.io/{repository}:sha-{revision}-arm64@{digests[\'arm64\']}"', publish)
        self.assertIn('f"ghcr.io/{repository}:sha-{revision}-amd64@{digests[\'amd64\']}"', publish)
        self.assertIn("actions/upload-artifact@", publish)
        self.assertIn("actions/download-artifact@", publish)
        self.assertIn("retention-days: 1", publish)
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        self.assertIn(':local architectures ($manifest->"architectures")', updater)
        self.assertIn('($architectures->"arm64") != "linux/arm64"', updater)
        self.assertIn('($architectures->"amd64") != "linux/amd64"', updater)
        self.assertIn('manifest AMD64 digest does not match its image reference', updater)
        self.assertIn('canary rollback target must be digest pinned', updater)

    def test_release_sbom_and_provenance_are_detached_from_runtime_image(self) -> None:
        publish = (ROOT / ".github" / "workflows" / "container.yml").read_text(encoding="utf-8")
        release_notes = (ROOT / "docs/RELEASES.md").read_text(encoding="utf-8")

        self.assertIn("sbom: false", publish)
        self.assertIn("provenance: false", publish)
        self.assertIn("anchore/sbom-action@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3", publish)
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2", publish)
        self.assertIn("subject-digest: ${{ steps.publish_image.outputs.digest }}", publish)
        self.assertIn("image: ghcr.io/${{ github.repository }}@${{ steps.publish_image.outputs.digest }}", publish)
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

    def test_redis_acceptance_documents_acknowledged_entry_retention_boundary(self) -> None:
        operations = (ROOT / "docs/OPERATIONS.md").read_text(encoding="utf-8")
        report = (ROOT / "docs/LIVE_TELEMETRY_ACCEPTANCE_REPORT.md").read_text(encoding="utf-8")
        redis_gate = next(
            (line for line in report.splitlines() if line.startswith("| Redis/outbox |")),
            "",
        )

        self.assertIn("`REDIS_STREAM_MAXLEN`, an entry-count limit", operations)
        self.assertIn("later Redis data loss", operations)
        self.assertIn("does not make the outbox publish it again", operations)
        self.assertIn("no Redis stream consumer in this repository", operations)
        self.assertIn("maximum expected consumer lag", redis_gate)
        self.assertIn("test_acknowledged_event_is_not_reconstructed_after_stream_trim", redis_gate)
        self.assertIn("consumer-lag evidence were not collected", redis_gate)

    def test_latest_published_artifact_is_consistent_across_release_docs(self) -> None:
        documents = (
            ROOT / "docs/RELEASES.md",
            ROOT / "docs/ROADMAP.md",
            ROOT / "docs/LIVE_TELEMETRY_ACCEPTANCE_REPORT.md",
            ROOT / "docs/INSTALLATION.md",
            ROOT / "docs/SECURITY_ASSURANCE.md",
            ROOT / "docs/ROUTEROS_ACCEPTANCE.md",
            ROOT / "docs/OPERATIONS.md",
        )
        rendered = " ".join(
            "\n".join(document.read_text(encoding="utf-8") for document in documents).split()
        )
        release_record = (ROOT / "docs/RELEASES.md").read_text(encoding="utf-8")
        installation = (ROOT / "docs/INSTALLATION.md").read_text(encoding="utf-8")
        security_assurance = (ROOT / "docs/SECURITY_ASSURANCE.md").read_text(encoding="utf-8")

        self.assertIn("## Latest published mainline image — PR #965", release_record)
        self.assertIn("## Previous published mainline image — PR #935", release_record)
        self.assertIn("## Previous published mainline image — PR #926", release_record)
        self.assertIn(
            "The latest TLS-verified API point readback is a Binary API container snapshot from 11:03:50 UTC",
            release_record,
        )
        self.assertIn("A later read-only WinBox list at 11:28:59 UTC showed the canary unhealthy and production healthy", release_record)
        self.assertIn(
            "PR #966 merged documentation-only at `1d765cf7bf64aaffaf30b3937dc43790c3c09b6b`",
            release_record,
        )
        self.assertIn(
            "production's healthcheck status was `good` with a healthy field true",
            release_record,
        )
        self.assertIn(
            "The PR #965 `--check-only` preflight blocked at `baseline / canary_unhealthy`",
            release_record,
        )
        self.assertIn("sha256:fd8aa26111eefae378caf95c88909264550f8c9faf3f44dc2cca18d2fd7531bd", release_record)
        self.assertIn("sha256:4aec06e36796a1c6ea019fa8559d1ba11e4a2373615f68490e4f8a1fff6122b1", release_record)
        self.assertIn("sha256:6fb18fbbada53bceffad7418881c26a05e9481f2e2263eb954924fdcd5d195ae", release_record)
        self.assertIn("## Previous published mainline image — PR #915", release_record)
        self.assertIn("sha256:969cff69318e9abc73a047c4a09afeca1268b8d73a3eec6d13a755529404e150", release_record)
        self.assertIn("sha256:3f1085d607ed87a4c129b88360ec9d874bf3c466f7372d09ad28e3f5f03a3ca1", release_record)
        self.assertIn("sha256:d286b4decf5cf102ea32a7bcf8592ff7cd199ef8929c09117ab581899d6ff10e", release_record)
        self.assertIn("5db3a0d4a220348c2f49934db4a3263776390c6c", release_record)
        self.assertIn("sha-5db3a0d4a220348c2f49934db4a3263776390c6c-arm64", release_record)
        self.assertIn("sha-5db3a0d4a220348c2f49934db4a3263776390c6c-amd64", release_record)
        self.assertIn("sha256:8b5fed8dda70ea1db628c4d261873458086ff4b8a381c33b2f9ebaf16abda407", release_record)
        self.assertIn("sha256:5805292d6f2f72a5c91ad2128c2b6e902bca4ccd033931875e3f4199e9961a76", release_record)
        self.assertIn("sha256:cf6fdcd90162a337257dc582ddc1fb68fd4bd6ac8e7a0354e04ec2a53afead05", release_record)
        self.assertIn("## Previous published mainline image — PR #907", release_record)
        self.assertIn("## Previous published mainline image — PR #901", release_record)
        self.assertIn("## Previous published mainline image — PR #897", release_record)
        self.assertIn("## Previous published mainline image — PR #896", release_record)
        self.assertIn("## Previous published mainline image — PR #894", release_record)
        self.assertIn("## Previous published mainline image — PR #891", release_record)
        self.assertIn("## Previous published mainline image — PR #889", release_record)
        self.assertIn("## Previous published mainline image — PR #885", release_record)
        self.assertIn("## Previous published mainline image — PR #879", release_record)
        self.assertIn("## Previous published mainline image — PR #875", release_record)
        self.assertIn("## Previous published mainline image — PR #873", release_record)
        self.assertIn("## Previous published mainline image — PR #871", release_record)
        self.assertIn("## Previous published mainline image — PR #868", release_record)
        self.assertIn("## Previous published mainline image — PR #862", release_record)
        self.assertIn("## Previous published mainline image — PR #860", release_record)
        self.assertIn("## Previous published mainline image — PR #859", release_record)
        self.assertIn("## Previous published mainline image — PR #849", release_record)
        self.assertIn("## Previous published mainline image — PR #846", release_record)
        self.assertIn("## Previous published mainline image — PR #842", release_record)
        self.assertIn("## Previous published mainline image — PR #839", release_record)
        self.assertIn("## Previous published mainline image — PR #838", release_record)
        self.assertIn("## Previous published mainline image — PR #836", release_record)
        self.assertIn("## Previous published mainline image — PR #829", release_record)
        self.assertIn("## Previous published mainline image — PR #824", release_record)
        self.assertIn("## Previous published mainline image — PR #817", release_record)
        self.assertIn("sha256:fc7af0eb880bddca771bb7e73647c14f050bd674b4c0b450592ffedb2658ca4a", release_record)
        self.assertIn("sha256:ac36036b13842a7bb2ac5611705403e1165c84ac2a07115af8a192f9ccf7ba6f", release_record)
        self.assertIn("sha256:55aae2f27b0469b807c27064a339a04bbb7c938c1198f51e033440aa9f2f67f4", release_record)
        self.assertIn(
            "PR #965 has not been staged on RouterOS",
            " ".join(release_record.split()),
        )
        routeros_acceptance = (ROOT / "docs/ROUTEROS_ACCEPTANCE.md").read_text(encoding="utf-8")
        self.assertIn(
            "PR #965 (`13cae96d27ad42920ca4685116cd475eaa457408`) remains the latest published",
            " ".join(routeros_acceptance.split()),
        )
        self.assertIn("## Current checkpoint — 2026-11-13 11:29 UTC", routeros_acceptance)
        self.assertIn("A fresh read-only WinBox container-list view at 11:28:59 UTC showed the canary", routeros_acceptance)
        self.assertIn("`router_writes_may_have_started=false`", routeros_acceptance)
        self.assertNotIn("## Latest published mainline image — PR #817", release_record)
        self.assertIn("eb29581c8430ec862a8b47ee62268a74fec14518", rendered)
        self.assertIn("f31bf9e0f6bac65dc6dea7fc00af99743c3e61fb", rendered)
        self.assertIn("c0e9ac980da5694a2be9560dcbad0f9234cb9009", rendered)
        self.assertIn("bd27e608f074f357461e41fa906b87e84553a363", rendered)
        self.assertIn("e7163beebda530f16619094e9e498f3da873f980", rendered)
        self.assertIn("sha256:2016b42dac5f13ee3ac1e2ba7c07ecd4ffdd57bb1dae7aca56438249fe7a5f10", rendered)
        self.assertIn("sha256:3f92563ef0ae0c5d55a09fe81eaa950afe6a6d1d028fbebd5a4d36e229688832", rendered)
        self.assertIn("sha256:3187f302311d960042894df0e7c5262327f1c26e3d985444d0d7d9f257663a67", rendered)
        self.assertIn("sha256:a8a42789e3fc72d8402f882b63cfa8280c64cb9cf84e71f8cc6b8c0266fcbfc4", rendered)
        self.assertIn("sha256:8e47c68dcdc1bfab6643a15e7e31139e8018960b8879539ec16a452f8e8764d1", rendered)
        self.assertIn("sha256:50ad64d8f0b6f684b1025ce22d2a2ba2df9e1cc3b6531df382ef326d59193f7d", rendered)
        self.assertIn("sha256:728d22cc3543709ec29e5a0a5f93d1dd1273d654034c76eeda942273bbf0ee9c", rendered)
        self.assertIn("sha256:a71bf8b99c6819e55162c969cdd9f5687d06110ef1ad5ef6aa59b5831ded7fd7", rendered)
        self.assertIn("sha256:3f92563ef0ae0c5d55a09fe81eaa950afe6a6d1d028fbebd5a4d36e229688832", rendered)
        self.assertIn("sha256:3187f302311d960042894df0e7c5262327f1c26e3d985444d0d7d9f257663a67", rendered)
        self.assertIn("sha256:8e47c68dcdc1bfab6643a15e7e31139e8018960b8879539ec16a452f8e8764d1", rendered)
        self.assertIn("sha256:50ad64d8f0b6f684b1025ce22d2a2ba2df9e1cc3b6531df382ef326d59193f7d", rendered)
        self.assertIn("sha256:e6288dcc70eed59d29bfb697ffd5809de604463d718689e0fa9ca9d5bc615d17", rendered)
        self.assertIn("sha256:d737a8ae1c727ee7e1fb0b1da0c5ccdbeb17f035e1a611bd3242e6ee46c1976f", rendered)
        self.assertIn("sha256:02e2ec88e9591d0d7686edfeb4c5c0afbf3f4e28807dcdb9521b2035bbb2c84d", rendered)
        self.assertIn("sha256:8b5fed8dda70ea1db628c4d261873458086ff4b8a381c33b2f9ebaf16abda407", rendered)
        self.assertIn("sha256:5805292d6f2f72a5c91ad2128c2b6e902bca4ccd033931875e3f4199e9961a76", rendered)
        self.assertIn("sha256:cf6fdcd90162a337257dc582ddc1fb68fd4bd6ac8e7a0354e04ec2a53afead05", rendered)
        self.assertIn("sha256:0b3bebc396e1e2c20e61cbc0103a32d64a6bb9bf329284ea98a0c52687f2122e", rendered)
        self.assertIn("sha256:9074e637e745d51c85f8e9c60a75b528cd206d3508627d9107c723699cf28a4b", rendered)
        self.assertIn("sha256:aee2573edb8edcb1b8446b012aef408f4d2c1a3727b6dfc4c9dd66cc0fefe390", rendered)
        roadmap = (ROOT / "docs/ROADMAP.md").read_text(encoding="utf-8")
        self.assertIn("PR #889", roadmap)
        normalized_roadmap = " ".join(roadmap.split())
        self.assertIn(
            "The current #894 canary read-back and its limits are recorded in the current snapshot above",
            normalized_roadmap,
        )
        self.assertIn(
            "Historical record: PR #806 was manually staged on canary",
            normalized_roadmap,
        )
        self.assertIn(
            "That record does not describe the current canary",
            normalized_roadmap,
        )
        self.assertNotIn(
            "The installed updater still differs from reviewed source and was not run. PR #806 was manually staged",
            normalized_roadmap,
        )
        self.assertIn(
            "Candidate-specific acceptance remains open: the measured 30-minute freshness",
            normalized_roadmap,
        )
        self.assertIn("post-restart revision read-back and sustained health remain unverified", normalized_roadmap)
        self.assertIn("sha256:7c47d4a3ec3de83b2218cd3ce417017c92befeb45e967c355e9da9beb3a5b6ac", rendered)
        self.assertIn("sha256:ff75ac4878b03a329dad93247151469095ef786aea1349cca629c2a9245801d8", rendered)
        self.assertIn("sha256:24ed53e62ab73b475b0d1ab291b008c1892bd92ddfed962b2d3ae1ffa4f75238", rendered)
        self.assertIn("sha256:b555ad7f9cda65f86c3ee2694ee192e076582af12f297303952c01a97ae17459", rendered)
        self.assertIn("one active test tunnel", rendered)
        self.assertIn("sign-in request remained pending", rendered)
        self.assertIn("The 2026-10-30 read-back below is historical: it covered PR #862 only", roadmap)
        self.assertIn(
            "returned revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc`. It predates the PR #894 canary checkpoint",
            normalized_roadmap,
        )
        self.assertIn("sustained resource impact", normalized_roadmap)
        self.assertIn("Public records may include redacted candidate-bound point samples", roadmap)
        self.assertIn("c88bc730a8e75bcd89ab73dcf85d87df37db7884", rendered)
        self.assertIn("273e9ed1c3618e605c3af106a59b76dfb8686769", rendered)
        self.assertIn("f4708f519a6810ceb7d253c37c199032800ea625", rendered)
        self.assertIn("17cc88d5bf7e59752f569fb7ec253c9706e0a6ea", rendered)
        self.assertIn("d3be28625e9d3beb48e2bdf94855ac2b5f7111b1", rendered)
        self.assertIn("e7ff31b222df2229186c6c745b0917084599e4b3", rendered)
        self.assertIn("sha256:563139236aab98d524c7a829d07a975a827445d2fa023109660e96f25c7143f1", rendered)
        self.assertIn("sha256:a7bf9db0a77a48ee03435b69ee7ad907031d731c4a718fbecad9b01d659d7850", rendered)
        self.assertIn("sha256:b25c8a3fca3722a12a67b2c01cd2433aeffe9130d5c1d09dee3365492bffce46", rendered)
        self.assertIn("sha256:0c8c7c5764bd92f2dcb250474c84a07902d83972bcbe68c98bf45878d079f252", rendered)
        self.assertIn("sha256:59e304b3337d3f99bbc404a6d0866461cd13dcaca2439fe577881e0a1f2ca59b", rendered)
        self.assertIn("sha256:877ec4893c075958ee639d003e375e06d323a67396bbe05514efee98234eab76", rendered)
        self.assertIn("sha256:7236887299c7eb2f3c53768c5d8710ff4238a5ee8f354f90c6afc8048fcd8b7c", rendered)
        self.assertIn("sha256:c12743fa7c1eb4cbeaede2eac4c09ad7fe1bb75b47fc234af0703056e47f56ef", rendered)
        self.assertIn("sha256:ee4a5c35b3143e409d098b028fb90bb9f647306c68c30eeb02c498bdf30b05ac", rendered)
        self.assertIn("b68bc0cc9245991526efbfcd970e89d07000462a", rendered)
        self.assertIn("sha256:6ba391ce4a78dbdf4e54dbd8891493b3a5004fcb5e3493b15577599e541b0ab2", rendered)
        self.assertIn("sha256:003cd252a1df946b23531cb89bcb137c525949c7797b82b022ac2c2078a91dac", rendered)
        self.assertIn("sha256:fe525c7a91b572682dce6a7ea73533408013d790a0640775ff3e7f636479f437", rendered)
        self.assertIn("sha256:84a9053683a31922a1f21eb88efe62e72bdb48a301af14085f797508041a30a7", rendered)
        self.assertIn("sha256:f19586c12bf0047f3e5950f7bff365dd1024662c50e42e9bf70ab5c152bdef30", rendered)
        self.assertIn("sha256:20eb9e83c8c0a43bb4e56c613c82d3dba062c97268f788b15abb2e20679e0b4a", rendered)
        self.assertIn("sha256:53a667d8c8db22d217c38c3ff80a9a32650b1615e69e8d738104652c8fd6b326", rendered)
        self.assertIn("sha256:1009ca54c47258e00950e93de8a8bead79525e6f88b1ddf6b602862919cbef6b", rendered)
        self.assertIn("9fd85aaff7f4ed43888209d2b77663207a11a897", rendered)
        self.assertIn(
            "sha256:295040612e1541dfe92e396461b243fe8c73a5223e11ae9de6af9914ee234867",
            rendered,
        )
        self.assertIn(
            "sha256:2f71c739d2a3ea919fb9829cb44d3ddd1e777aabd5b2beb483c97d9b4d59ea14",
            rendered,
        )
        self.assertIn("060c1a247e9ba97651ff8093049161de34e57a12", rendered)
        self.assertIn(
            "sha256:29c594c7349af2b226afc38ea92cdf4d73d69ce4610a552726bc59297ca68da1",
            rendered,
        )
        self.assertIn(
            "sha256:aad12eb8d90e295c6968bddc81696836d2247e2d12d800cbf3dcffd1e870e60d",
            rendered,
        )
        self.assertIn(
            "sha256:f26a64afad79ec43ffe247d81cdf7488b84b52811af022e6d3bcce8d5d6ab2aa",
            rendered,
        )
        self.assertIn(
            "sha256:0a598defd090b8de7372f0ef9f6738f5ef76fe1dc3722bf4c9cb55bb36bc8319",
            rendered,
        )
        self.assertIn(
            "Latest published image: PR #935; not staged on RouterOS.",
            installation,
        )
        self.assertIn(
            "current canary still uses PR #894",
            installation,
        )
        self.assertIn(
            "PR #935, commit `3f8fc22ec3166b3074fb54f54c79d6dede256ed4`",
            installation,
        )
        self.assertIn("sha256:3b5f3304ded4bd0cf09855575f27a8fffa225efe4ef940a0d7e2f25734d6c581", release_record)
        self.assertIn("sha256:876abb845191359ce7a45b7f996e620d9a123efb6afb221f62fb0f19fc447709", release_record)
        self.assertIn("### Latest published authentication-denial classification — PR #849", security_assurance)
        self.assertIn("### Previous published source-level session/audit safeguard — PR #846", security_assurance)
        self.assertIn("### Previous published source-level log safeguard — PR #824", security_assurance)
        self.assertIn("### Previous published mainline security changes — PR #817", security_assurance)
        self.assertIn("The store uses WAL mode with `synchronous=NORMAL`", rendered)
        self.assertIn("a committed transaction may roll back after an operating system crash or power loss", rendered)
        self.assertIn("`synchronous=FULL` adds a WAL sync after each", rendered)
        self.assertIn("40ae1d86bbc8037172e38f1b018e71576925f201", rendered)
        self.assertIn(
            "sha256:cd96ffd32fb223abe7776c4ac2a6701cbea0c36fa5699619ead5915549cd0b3c",
            rendered,
        )
        self.assertIn(
            "sha256:d47a711056d7bc7a59b5fddfb68a3584eb0246d047fe6f9e7e1d9b44eba11253",
            rendered,
        )
        self.assertIn("42ce550652f8134f3f0e3ed4ca37c3a3df413624", rendered)
        self.assertIn(
            "sha256:d51572f37e09623cdc3e2990038f1a8ed39abc2de3dfd9beb50251c03168f4df",
            rendered,
        )
        self.assertIn(
            "sha256:1331b647c516ebab3e3ef2c69b00456c440f9fc69e9a5dd335431a7db35faef6",
            rendered,
        )
        self.assertIn("79816625e493f9581e7389b95760403ac6c9a327", rendered)
        self.assertIn(
            "sha256:dd646c8b25a5b4e24653d2268719b89513da85c7164e68e499b5ebd4cf292dce",
            rendered,
        )
        self.assertIn(
            "sha256:d36b00322a4bcc9ba0cca21af2ef0a5b18a4b6f351f989d423df5dcf1fe86f63",
            rendered,
        )
        self.assertIn(
            "No PR #806 rollback rehearsal or 30-minute soak is recorded",
            rendered,
        )
        self.assertIn("Stats view showed 0.7% CPU, 60.9 MiB memory, and 0 B swap", rendered)
        self.assertIn("Neither device has a read-back confirming PR #889 staging or acceptance", rendered)
        self.assertIn("sha256:dc5afa62f0410459ac2d48a5c53b7532d2f0a2104d46a9392874e7373fd2d0eb", rendered)
        self.assertIn("sha256:0376f9bb3ede0b018150a34107b19b53115fb0fe3ed1d80a6f71f8891b26bd23", rendered)
        self.assertIn("sha256:b84c99e539924bc08188a29b5e628a7c7ef5d62c53266596c5d09e6fc6cb2b77", rendered)
        self.assertIn("digest prefix matching the PR #862 ARM64 digest", rendered)
        self.assertIn(
            "revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc` (PR #862), not PR #885.",
            rendered,
        )
        self.assertIn("Production remains on its prior image", rendered)
        self.assertIn("This later observation supersedes an earlier inventory that reported the canary stopped", rendered)
        self.assertIn("latest read-only WinBox observation", rendered)
        self.assertIn("Stats view showed 0.7% CPU, 60.9 MiB memory, and 0 B swap", rendered)
        self.assertIn("or acceptance of PR #862", rendered)
        self.assertIn("PR #798", rendered)

    def test_operations_runbook_collects_live_evidence_before_evaluation(self) -> None:
        operations = (ROOT / "docs/OPERATIONS.md").read_text(encoding="utf-8")

        self.assertIn("### Live dashboard troubleshooting", operations)
        self.assertIn("Cloudflare Access session and the dashboard's RouterOS sign-in", operations)
        self.assertIn("before restarting\ncontainers", operations)
        self.assertIn("scripts/collect_release_acceptance.py", operations)
        self.assertIn("--phase canary-prepromotion", operations)
        self.assertIn("private-collected-evidence-prepromotion.json", operations)
        self.assertIn("private-collected-evidence-postpromotion.json", operations)
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
            "canary-container-lookup",
            "production-container-lookup",
            "canary-container-count-check",
            "production-container-count-check",
            "production-image-read",
            "production-image-validation",
            "production-noop-check",
            "canary-image-read",
            "pending-state-read",
            "state-directory-probe",
            "canary-lifecycle",
            "canary-restore-image-validation",
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

    def test_router_local_updater_labels_each_canary_lifecycle_operation(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        operations = (
            ("canary-stop", "/container/stop $canaryId"),
            ("canary-image-set", "/container/set $canaryId remote-image=$routerCandidateImage"),
            ("canary-image-update", "/container/update $canaryId"),
            ("canary-start", "/container/start $canaryId"),
            ("canary-rollback-stop", "/container/stop $canaryId"),
            ("canary-rollback-image-set", "/container/set $canaryId remote-image=$canaryRestoreImage"),
            ("canary-rollback-image-update", "/container/update $canaryId"),
            ("canary-rollback-start", "/container/start $canaryId"),
            ("canary-rollback-readiness-stop", "/container/stop $canaryId"),
            ("canary-rollback-readiness-image-set", "/container/set $canaryId remote-image=$canaryRestoreImage"),
            ("canary-rollback-readiness-image-update", "/container/update $canaryId"),
            ("canary-rollback-readiness-start", "/container/start $canaryId"),
            ("canary-rollback-soak-stop", "/container/stop $canaryId"),
            ("canary-rollback-soak-image-set", "/container/set $canaryId remote-image=$canaryRestoreImage"),
            ("canary-rollback-soak-image-update", "/container/update $canaryId"),
            ("canary-rollback-soak-start", "/container/start $canaryId"),
        )

        for step, command in operations:
            with self.subTest(step=step):
                marker = executable.index(f':set updaterStep "{step}"')
                next_marker = executable.find(":set updaterStep", marker + 1)
                command_at = executable.index(command, marker)
                self.assertTrue(next_marker < 0 or command_at < next_marker)

    def test_router_local_stage_updater_mutates_only_the_canary_container(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        container_commands = list(
            re.finditer(r"/container/([A-Za-z0-9-]+)\b([^\r\n]*)", executable)
        )
        mutating_commands = [
            command for command in container_commands if command.group(1) not in {"find", "get", "print", "export"}
        ]

        self.assertTrue(mutating_commands)
        for command in mutating_commands:
            with self.subTest(command=command.group(1)):
                self.assertIn(command.group(1), {"set", "start", "stop", "update"})
                target = re.match(r"\s+([^\s;{}]+)(.*)$", command.group(2))
                self.assertIsNotNone(target, "container mutation must name its target explicitly")
                self.assertEqual(target.group(1), "$canaryId")
                arguments = target.group(2).strip()
                if command.group(1) == "set":
                    self.assertRegex(arguments, r"^remote-image=\$(routerCandidateImage|canaryRestoreImage)$")
                else:
                    self.assertEqual(arguments, "")

    def test_router_local_rollback_verifier_checks_restored_image_and_revision(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        helper_start = executable.index(":local verifyCanaryRestore do={")
        helper_end = executable.index("\n:global vpnGuiImmutableUpdateLock", helper_start)
        verifier = executable[helper_start:helper_end]

        self.assertIn(":onerror restoreImageError,restoreImageAttributes in={", verifier)
        self.assertIn("[/container/get $canaryId remote-image]", verifier)
        self.assertIn(":if ($restoredImage != $restoreImage)", verifier)
        self.assertIn("[$fetchReady $endpoint $transport $restoreCommit]", verifier)
        self.assertIn(":for attempt from=1 to=$attempts do={", verifier)
        self.assertIn(":if (!$revisionReady) do={ :return \"readiness-failed\" }", verifier)
        self.assertIn(':return "verified"', verifier)
        self.assertEqual(
            set(re.findall(r':return "([a-z-]+)"', verifier)),
            {"image-read-failed", "image-mismatch", "readiness-failed", "verified"},
        )
        self.assertNotIn(":log", verifier)
        self.assertNotIn("$restoreImageError", verifier)
        self.assertNotIn("$restoreImageAttributes", verifier)

    def test_router_local_rollback_target_is_validated_immutable_before_canary_mutation(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        validation_at = executable.index(':set updaterStep "canary-restore-image-validation"')
        first_mutation_at = executable.index("/container/stop $canaryId")
        validation = executable[validation_at:first_mutation_at]

        self.assertLess(validation_at, first_mutation_at)
        self.assertIn('[$digestPinnedImage $canaryRestoreImage]', validation)
        self.assertIn(':for restoreIndex from=0 to=39 do={', validation)
        self.assertIn('[:find $hex $restoreCharacter] = nil', validation)

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
        self.assertIn('$recordFailure $image $updaterFailureStep $updaterRollbackOutcome', executable)
        self.assertIn('"canary readiness soak failed"', executable)

    def test_updater_failure_receipt_is_bounded_and_redacted(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )
        record_start = executable.index(":local recordFailure do={")
        record_end = executable.index("\n}", record_start)
        record_function = executable[record_start:record_end]

        self.assertIn(":local failureStep $2", record_function)
        self.assertIn(":local rollbackOutcome $3", record_function)
        self.assertIn('"\\nfailed-step=" . $failureStep', record_function)
        self.assertIn('"\\nrollback-outcome=" . $rollbackOutcome', record_function)
        self.assertIn('";step=" . $failureStep . ";rollback=" . $rollbackOutcome', record_function)
        self.assertNotIn("$updaterError", record_function)
        self.assertNotIn("$updaterErrorAttributes", record_function)

    def test_updater_rolls_back_before_best_effort_failure_journaling(self) -> None:
        updater = (ROOT / "scripts" / "routeros" / "immutable-release-updater.rsc.example").read_text(
            encoding="utf-8"
        )
        executable = "\n".join(
            line for line in updater.splitlines() if not line.lstrip().startswith("#")
        )

        cases = (
            (
                "canary lifecycle failed; step=",
                "canary-rollback-lifecycle",
                "canary lifecycle gate failed",
                "canary-rollback-lifecycle-verification",
            ),
            (
                "canary readiness failed; step=",
                "canary-rollback-readiness",
                "canary readiness gate failed",
                "canary-rollback-readiness-verification",
            ),
            (
                "canary soak failed; step=",
                "canary-rollback-soak",
                "canary readiness soak failed",
                "canary-rollback-soak-verification",
            ),
        )
        for failure_message, rollback_step, terminal_error, verification_step in cases:
            with self.subTest(rollback_step=rollback_step):
                block_start = executable.index(failure_message)
                block_end = executable.index(f'"{terminal_error}"', block_start)
                block = executable[block_start:block_end]
                failure_step_capture = executable.rfind(
                    ":set updaterFailureStep $updaterStep", 0, block_start
                )
                verification_call = block.index(
                    ":set rollbackVerification [$verifyCanaryRestore $canaryId $canaryRestoreImage $canaryRestoreCommit"
                )
                success_message = block.index(f"canary rollback verified; step={rollback_step}")
                failure_diagnostic = block.index("rollback verification failed; step=")
                journal_write = block.index(
                    ":do { $recordFailure $image $updaterFailureStep $updaterRollbackOutcome } on-error={"
                )

                self.assertGreaterEqual(failure_step_capture, 0)
                self.assertLess(failure_step_capture, block_start)
                self.assertLess(verification_call, success_message)
                self.assertLess(verification_call, failure_diagnostic)
                self.assertLess(success_message, journal_write)
                self.assertLess(failure_diagnostic, journal_write)
                self.assertIn(':if ($rollbackVerification = "verified") do={', block)
                self.assertLess(
                    block.index(f':set updaterStep "{rollback_step}"'),
                    journal_write,
                )
                self.assertIn(f':set updaterStep "{verification_step}"', block)
                self.assertIn("rollback starting; step=\" . $updaterStep", block)
                self.assertIn('rollback failed; step=" . $updaterStep . "; details redacted', block)
                self.assertIn("details redacted; operator action required", block)
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

    def test_manual_rollback_helper_is_immutable_and_uses_one_time_exact_approval(self) -> None:
        helper = (ROOT / "scripts" / "routeros" / "rollback-last-good.rsc.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("last-good-image=", helper)
        self.assertIn("previous-good-image=", helper)
        self.assertIn(':local digestMarker "@sha256:"', helper)
        self.assertIn(":local digestStart ($architectureEnd + [:len $digestMarker])", helper)
        self.assertIn(':for digestIndex from=$digestStart to=([:len $value] - 1) do={', helper)
        self.assertIn(':local hex "0123456789abcdef"', helper)
        self.assertIn('[:find $hex [:pick $value $digestIndex ($digestIndex + 1)]] = nil', helper)
        self.assertIn("/container/update", helper)
        self.assertIn(':local productionContainer "vpn-dashboard-production"\n', helper)
        self.assertNotIn(':local productionContainer "vpn-dashboard"\n', helper)
        self.assertIn(":global vpnGuiRollbackAuthorization", helper)
        self.assertIn(':local requiredAuthorization ("ROLLBACK " . $image . " TO " . $restoreImage)', helper)
        self.assertIn(':local rollbackScriptName "vpn-gui-manual-rollback"', helper)
        self.assertIn("/system/script/find where name=$rollbackScriptName", helper)
        self.assertIn(":if ([:jobname] != $rollbackScriptName) do={", helper)
        self.assertIn(":local activeRollbackRuns [/system script job print count-only as-value where script=$rollbackScriptName]", helper)
        self.assertIn(":if ($activeRollbackRuns > 1) do={", helper)
        self.assertIn(":local readinessTransport do={", helper)
        self.assertIn('"rollback readiness must use a private RFC1918 IPv4 address"', helper)
        self.assertIn(":local productionInterface [/container/get $productionId interface]", helper)
        self.assertIn(":local productionVethId [/interface/veth/find where name=$productionInterface]", helper)
        self.assertIn("$productionReadyUrl != $expectedReadyUrl", helper)
        self.assertLess(helper.index(":if ($activeRollbackRuns > 1) do={"), helper.index("/container/stop"))
        self.assertLess(helper.index(":if ([:jobname] != $rollbackScriptName) do={"), helper.index("/container/stop"))
        self.assertLess(helper.index("$productionReadyUrl != $expectedReadyUrl"), helper.index("/container/stop"))
        confirmation_guard = ":if ($vpnGuiRollbackAuthorization != $requiredAuthorization) do={"
        self.assertIn(confirmation_guard, helper)
        self.assertLess(helper.index(confirmation_guard), helper.index("/container/stop"))
        self.assertIn(":set vpnGuiRollbackAuthorization \"\"", helper)
        self.assertLess(helper.index(":set vpnGuiRollbackAuthorization \"\""), helper.index("/container/stop"))
        self.assertIn(":local expectedRevision [$imageRevision $image $imagePrefix]", helper)
        self.assertIn(":local restoreRevision [$imageRevision $restoreImage $imagePrefix]", helper)
        self.assertIn(':local journalRevision [$stateLine $state "commit="]', helper)
        self.assertIn("$journalRevision != $expectedRevision", helper)
        self.assertIn("$currentCanonical != $image", helper)
        self.assertIn(":local registryImage [:pick $restoreImage 9 [:len $restoreImage]]", helper)
        self.assertIn("/container/set $productionId remote-image=$registryImage", helper)
        self.assertIn(":set restoredImage [/container/get $productionId remote-image]", helper)
        self.assertIn(":local restoredCanonical [$canonicalImage $restoredImage]", helper)
        self.assertIn("if ($restoredCanonical != $restoreImage) do={", helper)
        self.assertIn('[:find $body $readyText] != nil', helper)
        self.assertIn('[:find $body $expectedRevisionText] != nil', helper)
        self.assertGreaterEqual(helper.count("on-error={ :set stepFailed true }"), 4)
        self.assertIn("persistent data was not restored or removed", helper)
        self.assertNotIn("/file/remove", helper)

    def test_manual_rollback_runbooks_match_single_router_production_target(self) -> None:
        helper = (ROOT / "scripts" / "routeros" / "rollback-last-good.rsc.example").read_text(
            encoding="utf-8"
        )
        runbook = (ROOT / "docs" / "ROLLBACK.md").read_text(encoding="utf-8")
        automation = (ROOT / "docs" / "ROUTER_LOCAL_AUTOMATION.md").read_text(encoding="utf-8")
        telemetry = (ROOT / "docs" / "LIVE_TELEMETRY_ROLLBACK.md").read_text(encoding="utf-8")

        self.assertIn(':local productionContainer "vpn-dashboard-production"', helper)
        self.assertNotIn(':local productionContainer "vpn-dashboard"\n', helper)
        for document in (runbook, automation, telemetry):
            self.assertIn("operator-reviewed", document.casefold())
            self.assertIn("vpnGuiRollbackAuthorization", document)
            self.assertIn("previous-good-image", document)
            self.assertIn("opaque RouterOS `image-id`", document)
            self.assertIn("VETH-IPv4", document)
            self.assertIn("running oci manifest digest", " ".join(document.casefold().split()))
        self.assertIn("overlapping jobs", runbook)
        for document in (runbook, automation, telemetry):
            self.assertIn("vpn-gui-manual-rollback", document)
        self.assertIn("active-job check", automation)
        self.assertNotIn("blue container", runbook.lower())
        self.assertNotIn("green container", runbook.lower())
        self.assertIn("vpn-dashboard-production", runbook)

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
        self.assertIn("canary-backup-receipt.txt", helper)
        self.assertIn("created-gmt-offset=", helper)
        self.assertIn("prior-canary-image=", helper)
        self.assertIn("encrypted=true", helper)
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

    def test_roadmap_tracks_connections_selection_issue_separately(self) -> None:
        roadmap = (ROOT / "docs/ROADMAP.md").read_text(encoding="utf-8")
        self.assertIn("[#190](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/190)", roadmap)
        self.assertIn("PR #907 merged on 2026-11-11. Managers can select active connections", roadmap)
        self.assertIn("PR #906 merged as b0dfe22", roadmap)
        self.assertIn("neither provides device-side inventory", roadmap)
        self.assertIn("each queued disconnect reuses the live single-session impact review", roadmap)
        self.assertNotIn("decide whether Connections bulk selection is useful", roadmap)
        closed_row = next(line for line in roadmap.splitlines() if "[#188]" in line and "## Issue status" not in line)
        self.assertNotIn("[#190]", closed_row)
    def test_updater_comparator_docs_distinguish_binding_and_scheduler_resolution(self) -> None:
        documentation = (
            ROOT / "docs/ROUTER_LOCAL_AUTOMATION.md"
        ).read_text(encoding="utf-8")
        documentation = " ".join(documentation.split())
        self.assertIn("`script_binding_references_resolved`", documentation)
        self.assertIn("`manifest_scheduler_targets_resolved`", documentation)
        self.assertIn(
            "`listed_bindings_resolved` remains `false` for schema version 2",
            documentation,
        )
        self.assertIn(
            "schema version 1, which cannot classify all scheduler entries",
            documentation,
        )
        self.assertIn('`inventory_exhaustiveness: "not_verified"`', documentation)

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
