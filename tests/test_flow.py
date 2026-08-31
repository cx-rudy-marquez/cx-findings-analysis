"""The re-onboarding flow, driven by a fake client.

These assert the parts that would be expensive to get wrong against a real
tenant: the ordering of the writes, the full-scan choice, and the refusal to
scan when a precondition fails.
"""

import io

import pytest

from config import FINDINGS_ANALYSIS_KEY, SAST_PARITY_FIELDS, settings
from cx.flow import (
    FlowAborted,
    build_scan_payload,
    resolve_baseline,
    run_flow,
    source_preset_name,
)
from store import COMPLETED, FAILED, Store


class FakeClient:
    """Records every call in order, so the test can assert on the sequence."""

    def __init__(self, **overrides):
        self.calls = []
        self.config = {}
        self.projects = [{"id": "p1", "name": "demo", "mainBranch": "master",
                          "repoUrl": "https://example.invalid/demo"}]
        self.source_available = overrides.get("source_available", True)
        self.config_sticks = overrides.get("config_sticks", True)
        self.scan_statuses = list(overrides.get("scan_statuses", ["Completed"]))
        self.summaries = overrides.get("summaries", {})
        self.tenant_config = overrides.get(
            "tenant_config",
            [{"key": key, "value": ""} for key, _, _ in SAST_PARITY_FIELDS],
        )

    def _record(self, name, *args):
        self.calls.append(name)

    def get_projects(self):
        return list(self.projects)

    def get_project(self, project_id):
        return dict(self.projects[0])

    def get_last_sast_scan(self, project_id, branch=None):
        if branch in (None, "master"):
            return {"id": "baseline-scan", "branch": "master", "status": "Completed"}
        return None

    def get_scan_summary(self, scan_id):
        return {"sastCounters": self.summaries.get(scan_id, {"severityCounters": []})}

    def compare_summary(self, base_scan_id, scan_id):
        return self.summaries.get("compare", {"severityStatusCounters": []})

    def compare_results(self, base_scan_id, scan_id, *, status=None, severity=None):
        return list(self.summaries.get("compare_rows", []))

    def has_source(self, scan_id):
        self._record("has_source")
        return self.source_available

    def download_code(self, scan_id, dest):
        self._record("download_code")
        dest.write(b"zip")
        return 3

    def create_project(self, name, **kwargs):
        self._record("create_project")
        # A new project has no overrides of its own, so the configuration
        # endpoint answers with the tenant's defaults - not with nothing. The
        # difference matters to the parity check, which would otherwise read
        # every unset key as a mismatch.
        self.config["fa-1"] = [dict(row) for row in self.tenant_config]
        return {"id": "fa-1", "name": name}

    def set_project_config(self, project_id, params):
        """Merge by key, as the live PATCH does - it does not replace."""
        self._record("set_project_config")
        if not self.config_sticks:
            return
        current = {row["key"]: dict(row) for row in self.config.get(project_id, [])}
        for param in params:
            current[param["key"]] = {**current.get(param["key"], {}), **param}
        self.config[project_id] = list(current.values())

    def get_project_config(self, project_id):
        self._record(f"get_project_config:{project_id}")
        return list(self.config.get(project_id, []))

    def create_upload_url(self):
        self._record("create_upload_url")
        return "https://upload.invalid/presigned"

    def put_upload(self, url, data):
        self._record("put_upload")

    def create_scan(self, payload):
        self._record("create_scan")
        self.last_payload = payload
        return {"id": "fa-scan", "status": "Queued"}

    def get_scan(self, scan_id):
        status = self.scan_statuses.pop(0) if len(self.scan_statuses) > 1 \
            else self.scan_statuses[0]
        return {"id": scan_id, "status": status}

    def cancel_scan(self, scan_id):
        self._record("cancel_scan")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("CX_DB_PATH", str(tmp_path / "test.db"))
    from config import Settings

    return Store(Settings.from_env())


def make_run(store):
    return store.create_run(
        source_project_id="p1",
        source_project_name="demo",
        baseline_scan_id=None,
        baseline_branch=None,
        minutes_per_finding=10,
    )


def test_config_is_written_before_the_scan_is_submitted(store):
    client = FakeClient()
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    assert store.get_run(run_id)["status"] == COMPLETED
    assert client.calls.index("set_project_config") < client.calls.index("create_scan")


def test_project_is_created_before_its_config_is_patched(store):
    client = FakeClient()
    run_flow(make_run(store), "p1", store, client, settings)
    assert client.calls.index("create_project") < client.calls.index("set_project_config")


def test_the_fa_scan_is_full_not_incremental(store):
    client = FakeClient()
    run_flow(make_run(store), "p1", store, client, settings)
    sast = next(c for c in client.last_payload["config"] if c["type"] == "sast")
    # Incremental would only analyse newly-introduced findings, and on a fresh
    # project that measures almost nothing.
    assert sast["value"]["incremental"] == "false"


def test_missing_source_stops_before_anything_is_created(store):
    client = FakeClient(source_available=False)
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    run = store.get_run(run_id)
    assert run["status"] == FAILED
    assert "no longer retains the source" in run["error"]
    assert "create_project" not in client.calls
    assert "create_scan" not in client.calls


def test_a_config_key_that_does_not_stick_prevents_the_scan(store):
    client = FakeClient(config_sticks=False)
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    run = store.get_run(run_id)
    assert run["status"] == FAILED
    assert FINDINGS_ANALYSIS_KEY in run["error"]
    assert "create_scan" not in client.calls


def test_an_existing_fa_project_is_reused_rather_than_duplicated(store):
    client = FakeClient()
    client.projects.append({"id": "fa-existing", "name": "demo_FA"})
    run_flow(make_run(store), "p1", store, client, settings)
    assert "create_project" not in client.calls


def test_a_failed_scan_produces_no_comparison(store):
    client = FakeClient(scan_statuses=["Failed"])
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    run = store.get_run(run_id)
    assert run["status"] == FAILED
    assert run["compare_counters"] is None


def test_resolve_baseline_refuses_a_project_with_no_sast_scan():
    class NoSast(FakeClient):
        def get_last_sast_scan(self, project_id, branch=None):
            return None

    with pytest.raises(FlowAborted, match="no completed scan that ran the SAST"):
        resolve_baseline(NoSast(), {"id": "p1", "name": "demo"})


def test_scan_payload_references_the_uploaded_archive():
    payload = build_scan_payload("fa-1", "https://upload.invalid/x", "master", "https://repo")
    assert payload["type"] == "upload"
    # The Scans spec's `upload` handler is {branch, repoUrl, uploadUrl}.
    assert payload["handler"]["uploadUrl"] == "https://upload.invalid/x"
    assert payload["handler"]["branch"] == "master"
    assert payload["project"]["id"] == "fa-1"


def test_scan_payload_omits_the_preset_when_the_project_inherits_one():
    """Regression: a hardcoded "Default" fails the scan with "Preset not found".

    No tenant is required to have a preset by that name, and WebGoatNet's own
    baseline ran with an empty presetName - i.e. inheriting - so the _FA scan
    has to inherit too or it measures a different rule set.
    """
    payload = build_scan_payload("fa-1", "https://upload.invalid/x", "master", None)
    assert "presetName" not in payload["config"][0]["value"]
    assert payload["config"][0]["value"]["incremental"] == "false"


def test_scan_payload_carries_a_pinned_preset_through():
    payload = build_scan_payload(
        "fa-1", "https://upload.invalid/x", "master", None, "Checkmarx Default"
    )
    assert payload["config"][0]["value"]["presetName"] == "Checkmarx Default"


def test_source_preset_name_reads_the_projects_pinned_value():
    class Pinned:
        def get_project_config(self, project_id):
            return [
                {"key": "scan.config.sast.presetName", "value": "CWE top 25"},
                {"key": "scan.config.sast.findingsAnalysis", "value": ""},
            ]

    class Inherited:
        def get_project_config(self, project_id):
            return [{"key": "scan.config.sast.presetName", "value": ""}]

    assert source_preset_name(Pinned(), "p1") == "CWE top 25"
    assert source_preset_name(Inherited(), "p1") is None


def test_every_write_is_journalled(store):
    client = FakeClient()
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)
    logged = {step["step"] for step in store.get_steps(run_id)}
    assert {"create-project", "set-config", "upload", "create-scan"} <= logged


# --- Phase 3a: SAST parameter parity ----------------------------------------

SAST_FAST = "scan.config.sast.fastScanMode"


def test_a_parity_report_is_stored_on_the_run(store):
    client = FakeClient()
    client.config["p1"] = [dict(row) for row in client.tenant_config]
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    report = store.get_run(run_id)["parity_report"]
    assert report["total"] == 7
    assert report["reliable"] is True
    assert any(f["key"] == FINDINGS_ANALYSIS_KEY for f in report["fields"])


def test_the_candidate_config_is_read_after_the_flag_is_written(store):
    """Read first and findingsAnalysis would be false on both sides."""
    client = FakeClient()
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    assert client.calls.index("set_project_config") < client.calls.index(
        "get_project_config:fa-1"
    )
    report = store.get_run(run_id)["parity_report"]
    flag = next(f for f in report["fields"] if f["key"] == FINDINGS_ANALYSIS_KEY)
    assert flag["candidate"] == "true"
    assert flag["expected_to_differ"] is True


def test_the_source_configuration_is_only_fetched_once(store):
    """The preset lookup and the parity check share one read."""
    client = FakeClient()
    run_flow(make_run(store), "p1", store, client, settings)

    assert client.calls.count("get_project_config:p1") == 1


def test_a_parity_mismatch_does_not_abort_the_run(store):
    """A confound makes the result unattributable, not unobtainable."""
    client = FakeClient()
    client.config["p1"] = [
        {**row, "value": "true"} if row["key"] == SAST_FAST else dict(row)
        for row in client.tenant_config
    ]
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    run = store.get_run(run_id)
    assert run["status"] == COMPLETED
    assert run["parity_report"]["reliable"] is False
    assert [f["label"] for f in run["parity_report"]["fields"] if not f["matches"]
            and not f["expected_to_differ"]] == ["Fast scan mode"]


def test_a_parity_mismatch_is_journalled_as_a_warning(store):
    client = FakeClient()
    client.config["p1"] = [
        {**row, "value": "true"} if row["key"] == SAST_FAST else dict(row)
        for row in client.tenant_config
    ]
    run_id = make_run(store)
    run_flow(run_id, "p1", store, client, settings)

    parity_steps = [s for s in store.get_steps(run_id) if s["step"] == "parity-check"]
    assert len(parity_steps) == 1
    assert parity_steps[0]["outcome"] == "warn"
    assert "Fast scan mode" in parity_steps[0]["detail"]


def test_an_unreadable_configuration_does_not_fail_the_run(store):
    """The parity check is advisory. It must not be able to abort a scan."""
    class Unreadable(FakeClient):
        def get_project_config(self, project_id):
            self._record(f"get_project_config:{project_id}")
            if project_id == "p1":
                raise CxError("configuration service unavailable")
            return list(self.config.get(project_id, []))

    from cx.errors import CxError  # noqa: F811

    run_id = make_run(store)
    run_flow(run_id, "p1", store, Unreadable(), settings)
    assert store.get_run(run_id)["status"] == COMPLETED
