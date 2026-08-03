import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from agentsim import __version__
from agentsim.cli import main as cli_main
from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.content.ability_loader import parse_ability_pack
from agentsim.content.campaign_loader import parse_campaign_pack
from agentsim.content.catalog import load_command_catalog
from agentsim.content.integrity import content_digest, verify_integrity
from agentsim.execution.local import host_platform_name
from agentsim.models.campaign import CampaignDefinition, CampaignStep
from agentsim.models.target import TargetProfile
from agentsim.orchestration.planner import plan_campaign
from agentsim.orchestration.runner import CampaignRunner
from agentsim.safety.authorization import AuthorizationManifest
from agentsim.safety.policy import SafetyPolicy
from agentsim.safety.resource_limits import RunLimits
from agentsim.storage import RunStore
from agentsim.telemetry.ground_truth import load_lifecycle_events


FROZEN_TIME = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


def authorization(**overrides):
    value = {
        "manifest_id": "auth-test",
        "authorized_by": "AgentSim test operator",
        "scope": "Synthetic and localhost test targets only",
        "issued_at": "2026-08-01T11:00:00Z",
        "expires_at": "2030-08-02T11:00:00Z",
        "allowed_modes": ["simulate", "emulate", "lab"],
        "allowed_targets": ["synthetic://ci", "localhost://test-host", "docker://test-container"],
        "allowed_ability_ids": ["*"],
        "allow_network": False,
        "resource_limits": {
            "max_actions": 20,
            "max_duration_seconds": 120,
            "max_processes": 50,
            "max_cloud_spend_usd": 0,
        },
    }
    value.update(overrides)
    return AuthorizationManifest.from_mapping(value)


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.abilities = load_ability_registry()
        self.campaigns = load_campaign_registry()

    def test_version_and_reviewed_content_catalogs(self):
        self.assertEqual(__version__, "1.7.0")
        self.assertEqual(len(self.abilities), 19)
        self.assertEqual(len(self.campaigns), 6)
        for ability in self.abilities.values():
            with self.subTest(ability=ability.ability_id):
                self.assertTrue(ability.execution.command_ref.startswith("catalog://"))
                self.assertFalse(ability.production_allowed)
                self.assertTrue(ability.expected_telemetry)
                self.assertTrue(ability.detection_objectives)
                self.assertTrue(ability.benign_controls)
                self.assertTrue(ability.defenses)
                if ability.execution.state_changes:
                    self.assertIsNotNone(ability.execution.cleanup_ref)

    def test_local_platform_detection_does_not_spawn_a_process(self):
        cases = (("darwin", "macOS"), ("linux", "Linux"), ("win32", "Windows"))
        for observed, expected in cases:
            with self.subTest(platform=observed), mock.patch(
                "agentsim.execution.local.sys.platform", observed
            ), mock.patch("agentsim.execution.local.subprocess.run") as run_mock:
                self.assertEqual(host_platform_name(), expected)
                run_mock.assert_not_called()

    def test_ability_pack_integrity_and_no_embedded_commands(self):
        source = Path("agentsim/content/packs/endpoint_discovery.json")
        pack = json.loads(source.read_text(encoding="utf-8"))
        pack["abilities"][0]["name"] = "tampered"
        with self.assertRaisesRegex(ValueError, "integrity checksum"):
            parse_ability_pack(pack, "tampered-pack")

        pack = json.loads(source.read_text(encoding="utf-8"))
        pack.pop("integrity")
        with self.assertRaisesRegex(ValueError, "integrity is required"):
            parse_ability_pack(pack, "unsigned-pack")

        pack = json.loads(source.read_text(encoding="utf-8"))
        pack["abilities"][0]["execution"]["command"] = "arbitrary shell text"
        pack["integrity"]["digest"] = content_digest(pack["abilities"])
        with self.assertRaisesRegex(ValueError, "signature verification"):
            parse_ability_pack(pack, "unsafe-pack")

    def test_catalog_and_campaign_content_are_strict_and_checksummed(self):
        catalog_path = Path("agentsim/content/catalogs/endpoint_commands.json")
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        self.assertTrue(load_command_catalog())
        catalog["commands"]["catalog://endpoint/discovery/current-user"]["description"] = (
            "tampered"
        )
        with self.assertRaisesRegex(ValueError, "integrity checksum"):
            verify_integrity(catalog, "commands")

        campaign_path = Path("agentsim/content/campaigns/foundation.json")
        campaign_pack = json.loads(campaign_path.read_text(encoding="utf-8"))
        campaign_pack["campaigns"][0]["steps"][0]["script"] = "embedded"
        campaign_pack["integrity"]["digest"] = content_digest(campaign_pack["campaigns"])
        with self.assertRaisesRegex(ValueError, "signature verification"):
            parse_campaign_pack(campaign_pack, "unsafe-campaign")

    def test_authorization_and_target_scope_are_enforced(self):
        ability = self.abilities["endpoint.discovery.processes"]
        manifest = authorization()
        allowed = SafetyPolicy().authorize(
            ability,
            mode="emulate",
            target=TargetProfile.from_uri("localhost://test-host"),
            manifest=manifest,
            now=FROZEN_TIME,
        )
        self.assertTrue(allowed.allowed)

        denied = SafetyPolicy().authorize(
            ability,
            mode="emulate",
            target=TargetProfile.from_uri("localhost://not-allowlisted"),
            manifest=manifest,
            now=FROZEN_TIME,
        )
        self.assertFalse(denied.allowed)
        self.assertIn("allowlist", denied.reason)

        wildcard_manifest = authorization(allowed_targets=["localhost://*"])
        wildcard_denied = SafetyPolicy().authorize(
            ability,
            mode="emulate",
            target=TargetProfile.from_uri("localhost://test-host"),
            manifest=wildcard_manifest,
            now=FROZEN_TIME,
        )
        self.assertFalse(wildcard_denied.allowed)

        cidr_manifest = authorization(allowed_targets=["cidr://192.0.2.0/24"])
        cidr_allowed = SafetyPolicy().authorize(
            ability,
            mode="simulate",
            target=TargetProfile.from_uri("ip://192.0.2.42"),
            manifest=cidr_manifest,
            now=FROZEN_TIME,
        )
        self.assertTrue(cidr_allowed.allowed)

        production_target = TargetProfile.from_uri(
            "cloud://aws/production", environment="production"
        )
        production_manifest = authorization(
            allowed_targets=["cloud://aws/production"], allow_network=True
        )
        cloud_ability = self.abilities["cloud.discovery.services"]
        denied_production = SafetyPolicy().authorize(
            cloud_ability,
            mode="simulate",
            target=production_target,
            manifest=production_manifest,
            run_allows_network=True,
            now=FROZEN_TIME,
        )
        self.assertFalse(denied_production.allowed)
        self.assertIn("production", denied_production.reason)

    def test_network_requires_run_and_manifest_approval(self):
        cloud_ability = self.abilities["cloud.discovery.services"]
        ability = replace(
            cloud_ability,
            execution=replace(
                cloud_ability.execution,
                supported_providers=("simulate", "local"),
            ),
        )
        target = TargetProfile.from_uri("localhost://test-host")
        denied = SafetyPolicy().authorize(
            ability,
            mode="emulate",
            target=target,
            manifest=authorization(),
            run_allows_network=True,
            now=FROZEN_TIME,
        )
        self.assertFalse(denied.allowed)
        approved = SafetyPolicy().authorize(
            ability,
            mode="emulate",
            target=target,
            manifest=authorization(allow_network=True),
            run_allows_network=True,
            now=FROZEN_TIME,
        )
        self.assertTrue(approved.allowed)

        simulated = SafetyPolicy().authorize(
            ability,
            mode="simulate",
            target=TargetProfile.from_uri("synthetic://ci"),
            manifest=authorization(),
            now=FROZEN_TIME,
        )
        self.assertTrue(simulated.allowed)

    def test_provider_target_compatibility_is_rejected_during_planning(self):
        ability = self.abilities["endpoint.discovery.processes"]
        decision = SafetyPolicy().authorize(
            ability,
            mode="emulate",
            target=TargetProfile.from_uri("docker://test-container"),
            manifest=authorization(),
            now=FROZEN_TIME,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("localhost", decision.reason)

        cloud = self.abilities["cloud.discovery.services"]
        cloud_decision = SafetyPolicy().authorize(
            cloud,
            mode="emulate",
            target=TargetProfile.from_uri("localhost://test-host"),
            manifest=authorization(allow_network=True),
            run_allows_network=True,
            now=FROZEN_TIME,
        )
        self.assertFalse(cloud_decision.allowed)
        self.assertIn("provider", cloud_decision.reason)

    def test_campaign_plan_explains_each_authorization_decision(self):
        campaign = self.campaigns["endpoint-discovery-baseline"]
        plan = plan_campaign(
            campaign,
            self.abilities,
            mode="simulate",
            target=TargetProfile.from_uri("synthetic://ci"),
            manifest=authorization(),
        )
        self.assertTrue(plan.authorized)
        self.assertEqual(len(plan.actions), 7)
        self.assertTrue(all(action.command_ref.startswith("catalog://") for action in plan.actions))
        self.assertTrue(all(action.expected_telemetry for action in plan.actions))

    def test_simulation_campaign_records_complete_lifecycle_and_history(self):
        campaign = self.campaigns["endpoint-discovery-baseline"]
        database = self.root / "runs.db"
        result = CampaignRunner(
            self.abilities,
            database_path=database,
            clock=lambda: FROZEN_TIME,
        ).run(
            campaign,
            mode="simulate",
            target=TargetProfile.from_uri("synthetic://ci"),
            manifest=authorization(),
            output_directory=self.root / "runs",
            run_id="foundation-test-run",
        )

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.summary["verified_actions"], 7)
        self.assertEqual(result.summary["executed_actions"], 0)
        events = load_lifecycle_events(result.timeline_path)
        states = {event["lifecycle_state"] for event in events}
        self.assertTrue(
            {"planned", "authorized", "prepared", "attempted", "simulated", "observed", "detection_pending", "cleanup_started", "cleaned", "verified"}.issubset(states)
        )
        attempted = [event for event in events if event["lifecycle_state"] == "attempted"]
        self.assertTrue(all(event["attributes"]["execution_attempted"] is False for event in attempted))
        history = RunStore(database).history()
        self.assertEqual(history[0]["run_id"], "foundation-test-run")
        self.assertEqual(history[0]["manifest_sha256"], json.loads(result.manifest_path.read_text())["manifest_sha256"])
        with zipfile.ZipFile(result.bundle_path) as bundle:
            self.assertEqual(
                set(bundle.namelist()),
                {
                    "run-manifest.json",
                    "action-lifecycle.jsonl",
                    "campaign-report.json",
                    "defense-scorecard.json",
                    "defense-runbooks.json",
                    "detection-candidates.json",
                    "attack-flow.json",
                },
            )

    def test_kill_switch_stops_campaign_and_preserves_cleanup_reserve(self):
        manifest = authorization()
        limits = RunLimits(manifest)
        limits.cancel()
        limits.before_process(cleanup=True)
        self.assertEqual(limits.cleanup_processes_started, 1)
        with self.assertRaisesRegex(RuntimeError, "kill switch"):
            limits.before_process()

        result = CampaignRunner(
            self.abilities,
            database_path=self.root / "cancelled.db",
            clock=lambda: FROZEN_TIME,
        ).run(
            self.campaigns["endpoint-discovery-baseline"],
            mode="simulate",
            target=TargetProfile.from_uri("synthetic://ci"),
            manifest=manifest,
            output_directory=self.root / "cancelled-runs",
            run_id="cancelled-foundation-run",
            limits=limits,
        )
        self.assertEqual(result.status, "cancelled")
        self.assertEqual(len(result.actions), 1)
        self.assertEqual(result.actions[0].status, "cancelled")
        states = [
            event["lifecycle_state"]
            for event in load_lifecycle_events(result.timeline_path)
        ]
        self.assertIn("cancelled", states)
        self.assertIn("cleanup_started", states)
        self.assertIn("cleaned", states)

    @mock.patch("agentsim.execution.local.subprocess.run")
    def test_local_provider_uses_static_argv_without_shell(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess([], 0, b"ok", b"")
        ability = self.abilities["endpoint.discovery.current-user"]
        campaign = CampaignDefinition(
            campaign_id="single-current-user",
            name="Single current-user ability",
            description="Test campaign",
            objective="Exercise static local provider argv",
            target_profile="localhost",
            steps=(CampaignStep("current-user", ability.ability_id),),
            required_telemetry=("process_creation",),
            stop_conditions=("authorization_denied",),
        )
        result = CampaignRunner(
            self.abilities,
            database_path=self.root / "local.db",
            clock=lambda: FROZEN_TIME,
        ).run(
            campaign,
            mode="emulate",
            target=TargetProfile.from_uri("localhost://test-host"),
            manifest=authorization(),
            output_directory=self.root / "local-runs",
            run_id="local-provider-test",
        )
        self.assertEqual(result.status, "completed")
        self.assertGreater(run_mock.call_count, 0)
        for call in run_mock.call_args_list:
            self.assertIsInstance(call.args[0], list)
            self.assertNotIn("shell", call.kwargs)

    def test_target_uri_validation_rejects_ambiguous_targets(self):
        for target in ("", "docker://", "ssh://host", "ip://not-an-ip"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    TargetProfile.from_uri(target)

    @mock.patch("sys.stdout", new_callable=io.StringIO)
    def test_foundation_cli_lists_content_and_version(self, stdout):
        self.assertEqual(cli_main(["ability", "list"]), 0)
        self.assertIn("endpoint.discovery.processes", stdout.getvalue())
        stdout.seek(0)
        stdout.truncate(0)
        self.assertEqual(cli_main(["--version"]), 0)
        self.assertIn("1.7.0", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
