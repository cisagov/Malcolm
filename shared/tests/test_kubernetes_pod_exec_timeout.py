"""Offline regressions for Kubernetes pod exec cleanup and timeout handling."""

from types import SimpleNamespace
from unittest.mock import Mock


import malcolm_kubernetes as kubernetes


class FakeApiException(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Clock:
    def __init__(self, step=0.2):
        self.now = 0
        self.step = step

    def monotonic(self):
        self.now += self.step
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeStream:
    def __init__(self, *, finish_after=1, failure=None, stdout="ok", status=""):
        self.finish_after = finish_after
        self.failure = failure
        self.stdout = stdout
        self.status = status
        self.is_running = True
        self.closed = False
        self.updates = 0
        self.stdin_writes = []

    def is_open(self):
        return self.is_running

    def update(self, timeout):
        self.updates += 1
        if self.failure is not None:
            raise self.failure
        if self.updates >= self.finish_after:
            self.is_running = False

    def peek_stdout(self):
        return bool(self.stdout)

    def read_stdout(self):
        text, self.stdout = self.stdout, ""
        return text

    def peek_stderr(self):
        return False

    def read_stderr(self):
        return ""

    def read_channel(self, channel):
        return self.status

    def write_stdin(self, value):
        self.stdin_writes.append(value)

    def close(self):
        self.closed = True


def configure(monkeypatch, *, stream=None, pending=0, read_error=None, clock=None):
    client = Mock()
    client.list_namespaced_pod.return_value = SimpleNamespace(
        items=[SimpleNamespace(metadata=SimpleNamespace(name="pod-a"))]
    )
    reads = 0

    def read_pod(**kwargs):
        nonlocal reads
        reads += 1
        if read_error is not None:
            raise read_error
        if reads <= pending:
            return SimpleNamespace(status=SimpleNamespace(phase="Pending"))
        return SimpleNamespace(status=SimpleNamespace(phase="Running"))

    client.read_namespaced_pod.side_effect = read_pod
    client.connect_get_namespaced_pod_exec = Mock()
    kube = SimpleNamespace(
        client=SimpleNamespace(
            CoreV1Api=Mock(return_value=client),
            rest=SimpleNamespace(ApiException=FakeApiException),
        ),
        stream=SimpleNamespace(
            stream=Mock(return_value=stream or FakeStream()),
            ws_client=SimpleNamespace(ERROR_CHANNEL=3),
        ),
    )
    monkeypatch.setattr(kubernetes, "KubernetesDynamic", lambda: kube)
    monkeypatch.setattr(kubernetes, "YAMLDynamic", lambda: None)
    if clock is not None:
        monkeypatch.setattr(kubernetes, "time", clock, raising=False)
    return client, kube


def test_empty_namespace_returns_no_results(monkeypatch):
    client, kube = configure(monkeypatch)
    assert kubernetes.PodExec("service", "", ["true"]) == {}
    kube.stream.stream.assert_not_called()


def test_normal_execution_reports_success_and_closes_stream(monkeypatch):
    stream = FakeStream(stdout="hello")
    client, kube = configure(monkeypatch, stream=stream)
    result = kubernetes.PodExec("service", "ns", ["echo", "hello"])
    assert result["pod-a"]["err"] == 0
    assert "hello" in result["pod-a"]["output"]
    assert stream.closed
    assert kube.stream.stream.call_args.kwargs["command"] == ["echo", "hello"]


def test_api_exception_is_one_message_not_a_list_of_characters(monkeypatch):
    client, kube = configure(monkeypatch, read_error=FakeApiException(403, "Forbidden"))
    result = kubernetes.PodExec("service", "ns", ["true"])
    assert result["pod-a"]["err"] != 0
    assert result["pod-a"]["output"] == ["Forbidden"]
    kube.stream.stream.assert_not_called()


def test_stream_is_closed_when_kubernetes_exec_fails(monkeypatch):
    stream = FakeStream(failure=FakeApiException(503, "Stream unavailable"))
    configure(monkeypatch, stream=stream)
    result = kubernetes.PodExec("service", "ns", ["true"])
    assert result["pod-a"]["err"] != 0
    assert "Stream unavailable" in result["pod-a"]["output"]
    assert stream.closed


def test_pending_pod_does_not_wait_forever(monkeypatch):
    clock = Clock()
    client, kube = configure(monkeypatch, pending=8, clock=clock)
    result = kubernetes.PodExec("service", "ns", ["true"], timeout=0.5)
    assert result["pod-a"]["err"] != 0
    assert "timed out" in " ".join(result["pod-a"]["output"]).lower()
    assert client.read_namespaced_pod.call_count < 8
    kube.stream.stream.assert_not_called()


def test_stdin_writes_are_covered_by_exec_timeout(monkeypatch):
    clock = Clock(step=0.1)
    stream = FakeStream(finish_after=80, stdout="")
    configure(monkeypatch, stream=stream, clock=clock)
    result = kubernetes.PodExec("service", "ns", ["cat"], timeout=0.6, stdin="\n".join(["data"] * 100))
    assert result["pod-a"]["err"] != 0
    assert "timed out" in " ".join(result["pod-a"]["output"]).lower()
    assert stream.updates < 80
    assert stream.closed


def test_nonzero_exit_code_is_preserved(monkeypatch):
    stream = FakeStream(
        status='{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"7"}]}}'
    )
    configure(monkeypatch, stream=stream)

    class Parser:
        @staticmethod
        def load(payload):
            import json

            return json.loads(payload)

    monkeypatch.setattr(kubernetes, "YAMLDynamic", lambda: SimpleNamespace(YAML=lambda **kwargs: Parser()))
    result = kubernetes.PodExec("service", "ns", ["false"])
    assert result["pod-a"]["err"] == 7
    assert stream.closed


def test_container_argument_is_forwarded(monkeypatch):
    client, kube = configure(monkeypatch)
    result = kubernetes.PodExec("service", "ns", ["true"], container="api")
    assert result["pod-a"]["err"] == 0
    assert kube.stream.stream.call_args.kwargs["container"] == "api"


def test_pending_pod_can_become_ready_within_deadline(monkeypatch):
    clock = Clock(step=0.01)
    stream = FakeStream(stdout="started")
    client, kube = configure(monkeypatch, pending=2, clock=clock, stream=stream)
    result = kubernetes.PodExec("service", "ns", ["echo", "started"], timeout=5)
    assert client.read_namespaced_pod.call_count == 3
    assert result["pod-a"]["err"] == 0
    assert "started" in result["pod-a"]["output"]
    assert stream.closed


def test_max_pods_limit_is_preserved(monkeypatch):
    client, kube = configure(monkeypatch)
    client.list_namespaced_pod.return_value = SimpleNamespace(
        items=[
            SimpleNamespace(metadata=SimpleNamespace(name="pod-a")),
            SimpleNamespace(metadata=SimpleNamespace(name="pod-b")),
            SimpleNamespace(metadata=SimpleNamespace(name="pod-c")),
        ]
    )
    result = kubernetes.PodExec("service", "ns", ["true"], maxPodsToExec=2)
    assert set(result) == {"pod-a", "pod-b"}
    assert all(entry["err"] == 0 for entry in result.values())
