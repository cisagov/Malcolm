# <a name="MalcolmTest"></a>`malcolm-test`: Malcolm System Tests

`malcolm-test` is a Python package for performing system tests against a Malcolm system. It serves to run an instance of Malcolm inside a virtual machine and verify the results of system tests executed against it. Please see the following repositories for installation and usage instructions and additional details:

* [idaholab/Malcolm-Test](https://github.com/idaholab/Malcolm-Test)
* [idaholab/Malcolm-Test-Artifacts](https://github.com/idaholab/Malcolm-Test-Artifacts)

# <a name="MalcolmUnitTests"></a>Malcolm Unit Tests

In addition to the [system tests](#MalcolmTest) run against a live instance by `malcolm-test`, Malcolm contains a suite of unit tests under [`shared/tests/`](shared/tests/). These tests exercise Malcolm's own Python helper modules, parsers, and service logic directly: they do **not** require a running Malcolm instance, containers, a container runtime, or network access to any Malcolm service.

## Why These Tests Live in This Repository

The unit tests are kept here rather than in [idaholab/Malcolm-Test](https://github.com/idaholab/Malcolm-Test) because of what they test and when they need to run:

* **They import Malcolm's source directly.** These tests import production modules out of the working copy (e.g., `zeek/scripts/zeek_threat_feed_utils.py`, the helpers under `shared/bin/`, the `filescan` package) and call their functions in-process. Keeping them next to the code they import means a change and its tests live in the same commit and the same pull request.
* **They have no deployment to test against.** The system tests in `malcolm-test` are integration tests: they provision a VM, start Malcolm, upload artifacts, and assert on API responses. The unit tests need none of that, so making them depend on an external project and a provisioned VM would add setup cost without adding coverage.
* **They should run before anything is built.** Because they only need a Python interpreter and the test requirements, they can run in seconds against a bare checkout, long before container images are built or pulled. That makes them the right place to catch regressions early.
* **They move with the code they cover.** A refactor of a helper module and the corresponding test update stay reviewable together, and the tests can never drift out of sync with a Malcolm release the way an externally-versioned suite can.

As a rule of thumb: if a test needs a running Malcolm, it belongs in `malcolm-test`; if it can be answered by importing a module and calling it, it belongs in `shared/tests/`.

## Running the Unit Tests

Run these from the root of your Malcolm working copy.

Install the test requirements:

```bash
python3 -m pip install -r ./shared/tests/requirements.txt
```

Generate the gRPC/protobuf bindings used by the `filescan` tests:

```bash
make -C filescan/python-filescan
```

Then run the suite:

```bash
pytest -q shared/tests/
```

Expected output resembles the following:

```
====================================== test session starts =======================================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/user/Malcolm/shared/tests
configfile: pyproject.toml
plugins: anyio-4.14.2
collected 1177 items

shared/tests/test_api_event_provenance.py ......                                           [  0%]
shared/tests/test_api_nested_mapping_fields.py .............                               [  1%]
...
shared/tests/test_watch_common_read_events.py ........                                     [ 98%]
shared/tests/test_watch_moved_paths.py ............                                        [100%]

===================================== 1177 passed in 19.49s =====================================
```

### Notes on the Setup Steps

* **The `make` step is not optional.** [`filescan/python-filescan`](filescan/python-filescan) runs `python3 -m grpc_tools.protoc` to generate `strelka_pb2.py`, `strelka_pb2.pyi`, and `strelka_pb2_grpc.py` from `strelka.proto`. These generated modules are not checked in, so the `test_filescan_*` tests fail to import until the bindings have been built. The step depends on `grpcio-tools`, which is installed by `requirements.txt`, so run the two commands in the order shown above.
* **Run `pytest` from the repository root.** Test configuration lives in `shared/tests/pyproject.toml`, and the tests resolve imports of Malcolm's own modules relative to the top of the working copy. Invoking `pytest` from elsewhere may cause import errors.
* **On Debian 13 and other distributions that mark the system Python as externally managed** ([PEP 668](https://peps.python.org/pep-0668/)), `pip install` refuses to write to system `site-packages`. Either use a virtual environment:

    ```bash
    python3 -m venv ./.venv
    source ./.venv/bin/activate
    python3 -m pip install -r ./shared/tests/requirements.txt
    ```

    or install for your user with an explicit override:

    ```bash
    python3 -m pip install --user --break-system-packages -r ./shared/tests/requirements.txt
    ```

* **`make` and a C toolchain** must be present for the build step and for any requirement without a prebuilt wheel for your platform. On Debian-family systems: `apt-get install build-essential make python3-dev python3-pip`.

## Skipped Tests

Some tests skip themselves when an optional dependency or a specific environmental condition is absent. Skips are not failures, but it is worth knowing why a test skipped rather than assuming it passed. Use `-rs` to print the reason for each skip:

```bash
pytest -rs shared/tests/
```

```
SKIPPED [23] shared/tests/test_logstash_zeek_community_id.py:196: requires ruby
SKIPPED [1] shared/tests/test_prune_files.py:63: filesystem is at 1%; need at least 2% to stay clear of the threshold boundary
```

Known conditional skips:

* **`test_logstash_zeek_community_id.py` requires `ruby`.** These tests evaluate Logstash's Ruby filter logic, so they need a `ruby` interpreter on `PATH`. Without it, 23 of the file's tests skip and the module is effectively not covered. Install `ruby` (e.g., `apt-get install ruby`) to exercise them.
* **`test_prune_files.py` requires a filesystem with some usage on it.** One test needs disk utilization at or above a small floor so that the pruning threshold logic can actually be driven; it skips on a nearly-empty filesystem. This skip is environmental and expected on fresh VMs and disposable CI runners.

If you are adding a test that needs something not guaranteed to be present, prefer `pytest.mark.skipif` with an explicit reason string over letting the test fail, and keep the reason specific enough that a reader of the CI log can tell whether the skip is benign.

## Relationship to `malcolm-test`

The two suites are complementary and are both run during automated testing:

| | Malcolm unit tests | [`malcolm-test`](#MalcolmTest) system tests |
|---|---|---|
| Location | `shared/tests/` in this repository | [idaholab/Malcolm-Test](https://github.com/idaholab/Malcolm-Test) |
| Scope | Individual modules and functions | A running Malcolm instance end to end |
| Requires a running Malcolm | No | Yes |
| Requires a VM / container runtime | No | Yes (`virter` + libvirt) |
| Requires test artifacts | No | Yes ([Malcolm-Test-Artifacts](https://github.com/idaholab/Malcolm-Test-Artifacts)) |
| Typical runtime | Seconds | Minutes to hours |

`malcolm-test` also runs this unit test suite as one of its VM provisioning steps, so a unit test failure will fail provisioning before the system tests are reached. That gives the fast-feedback benefit of unit tests inside the same pipeline that performs the slower integration run.
