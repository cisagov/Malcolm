#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import base64
import glob
import os

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from collections import defaultdict
from itertools import chain
from io import StringIO
from pathlib import Path

from malcolm_constants import (
    PROFILE_HEDGEHOG,
    PROFILE_MALCOLM,
)

from malcolm_common import (
    DotEnvDynamic,
    GetMemMegabytesFromJavaOptsLine,
    ParseK8sMemoryToMib,
    KubernetesDynamic,
    GetMalcolmPath,
    NullRepresenter,
    YAMLDynamic,
    YAML_VERSION,
)
from malcolm_utils import (
    deep_get,
    deep_set,
    deep_merge_in_place,
    dictsearch,
    get_iterable,
    file_contents,
    remove_falsy,
    remove_suffix,
    tablify,
    LoadStrIfJson,
    temporary_filename,
    val2bool,
)


###################################################################################################
MALCOLM_IMAGE_PREFIX = 'ghcr.io/idaholab/malcolm/'

MALCOLM_DOTFILE_SECRET_KEY = 'K8S_SECRET'
MALCOLM_CONFIGMAP_DIR_REPLACER = '_MALDIR_'
MALCOLM_DEFAULT_NAMESPACE = 'malcolm'

MALCOLM_CONFIGMAPS = {
    'etc-nginx': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), os.path.join('nginx', 'nginx_ldap.conf')),
        },
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('nginx', 'nginx.conf')),
        },
    ],
    'var-local-catrust': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('nginx', 'ca-trust')),
        },
    ],
    'etc-nginx-certs': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), os.path.join('nginx', 'certs')),
        },
    ],
    'etc-nginx-certs-pem': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join(os.path.join('nginx', 'certs'), 'dhparam.pem')),
        },
    ],
    'etc-nginx-auth': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), os.path.join('nginx', 'htpasswd')),
        },
    ],
    'opensearch-curlrc': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), '.opensearch.primary.curlrc'),
        },
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), '.opensearch.secondary.curlrc'),
        },
    ],
    'opensearch-keystore': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), os.path.join('opensearch', 'opensearch.keystore')),
        },
    ],
    'logstash-certs': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), os.path.join('logstash', 'certs')),
        },
    ],
    'logstash-maps': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('logstash', 'maps')),
        },
    ],
    'arkime-lua': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('arkime', 'lua')),
        },
    ],
    'arkime-rules': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('arkime', 'rules')),
        },
    ],
    'yara-rules': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('yara', 'rules')),
        },
    ],
    'suricata-rules': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('suricata', 'rules')),
        },
    ],
    'suricata-configs': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('suricata', 'include-configs')),
        },
    ],
    'filebeat-certs': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), os.path.join('filebeat', 'certs')),
        },
    ],
    'netbox-config': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('netbox', 'config')),
        },
    ],
    'netbox-custom-plugins': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('netbox', 'custom-plugins')),
        },
    ],
    'netbox-preload': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('netbox', 'preload')),
        },
    ],
    'htadmin-config': [
        {
            'secret': True,
            'path': os.path.join(GetMalcolmPath(), os.path.join('htadmin', 'metadata')),
        },
    ],
    'zeek-custom': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('zeek', 'custom')),
        },
    ],
    'zeek-intel-preseed': [
        {
            'secret': False,
            'path': os.path.join(GetMalcolmPath(), os.path.join('zeek', 'intel')),
        },
    ],
}

# the PersistentVolumes themselves aren't used directly,
#   so we only need to define the PersistentVolumeClaims
REQUIRED_VOLUME_OBJECTS = defaultdict(lambda: dict)
REQUIRED_VOLUME_OBJECTS[PROFILE_MALCOLM] = {
    'pcap-claim': 'PersistentVolumeClaim',
    'zeek-claim': 'PersistentVolumeClaim',
    'suricata-claim': 'PersistentVolumeClaim',
    'config-claim': 'PersistentVolumeClaim',
    'runtime-logs-claim': 'PersistentVolumeClaim',
    'opensearch-claim': 'PersistentVolumeClaim',
    'opensearch-backup-claim': 'PersistentVolumeClaim',
}
REQUIRED_VOLUME_OBJECTS[PROFILE_HEDGEHOG] = {
    'pcap-claim': 'PersistentVolumeClaim',
    'zeek-claim': 'PersistentVolumeClaim',
    'suricata-claim': 'PersistentVolumeClaim',
    'config-claim': 'PersistentVolumeClaim',
    'runtime-logs-claim': 'PersistentVolumeClaim',
}

MALCOLM_PROFILES_CONTAINERS = defaultdict(lambda: list)
MALCOLM_PROFILES_CONTAINERS[PROFILE_MALCOLM] = [
    'api',
    'arkime',
    'arkime-live',
    'dashboards',
    'dashboards-helper',
    'file-monitor',
    'filebeat',
    'freq',
    'htadmin',
    'keycloak',
    'logstash',
    'netbox',
    'postgres',
    'nginx-proxy',
    'opensearch',
    'pcap-capture',
    'pcap-monitor',
    'redis',
    'redis-cache',
    'suricata-live',
    'suricata-offline',
    'upload',
    'zeek-live',
    'zeek-offline',
]
MALCOLM_PROFILES_CONTAINERS[PROFILE_HEDGEHOG] = [
    'arkime',
    'arkime-live',
    'file-monitor',
    'filebeat',
    'pcap-capture',
    'pcap-monitor',
    'redis',
    'redis-cache',
    'suricata-live',
    'suricata-offline',
    'zeek-live',
    'zeek-offline',
]

CONTAINER_JAVA_OPTS_VARS = defaultdict(lambda: None)
CONTAINER_JAVA_OPTS_VARS['opensearch'] = 'OPENSEARCH_JAVA_OPTS'
CONTAINER_JAVA_OPTS_VARS['logstash'] = 'LS_JAVA_OPTS'


###################################################################################################
def replace_namespace(obj, namespace):
    def _replace(obj):
        changed = False
        if isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                if k == "namespace" and v == MALCOLM_DEFAULT_NAMESPACE:
                    new_dict[k] = namespace
                    changed = True
                else:
                    new_v, did_change = _replace(v)
                    new_dict[k] = new_v
                    changed = changed or did_change
            return new_dict, changed
        elif isinstance(obj, list):
            new_list = []
            for item in obj:
                new_item, did_change = _replace(item)
                new_list.append(new_item)
                changed = changed or did_change
            return new_list, changed
        else:
            return obj, False

    if namespace and (namespace != MALCOLM_DEFAULT_NAMESPACE):
        return _replace(obj)
    else:
        return obj, False


def update_container_image(containerImage, imageSource=None, imageTag=None):
    # Split into name and tag
    name_tag = containerImage.rsplit(':', 1)
    name = name_tag[0]
    tag = name_tag[1] if len(name_tag) == 2 else None

    # Split into source and image name
    source, image = name.rsplit('/', 1)

    # Replace as needed
    new_source = imageSource.rstrip('/') if imageSource else source
    new_tag = imageTag if imageTag else tag

    # Build new image string
    updated_image = f"{new_source}/{image}"
    if new_tag:
        updated_image += f":{new_tag}"

    return updated_image


def _nanocore_to_millicore(n):
    n = int(n[:-1])
    return str(round(n / 1000000, 2)) + 'm'


def _core_to_millicore(n):
    n = int(n)
    return str(n * 1000) + 'm'


def _percent_cpu(tcpu, ccpu):
    tcpu = float(tcpu[:-1])
    ccpu = float(ccpu[:-1])
    return str(round((ccpu / tcpu) * 100, 2)) + '%'


def _to_gibibyte_or_mebibyte(n):
    if n[-2:] == 'Ki':
        n = float(n[:-2])
        if str(round(n * 0.000000953674316, 2)).split('.')[0] == '0':
            return str(round(n * 0.0009765625, 2)) + 'Mi'
        return str(round(n * 0.000000953674316, 2)) + 'Gi'
    elif n[-2:] == 'Mi' or n[-2:] == 'Gi':
        return n


def load_node_list():
    nodes = []

    if (
        (kubeImported := KubernetesDynamic())
        and (stats_api := kubeImported.client.CustomObjectsApi())
        and (node_stats := stats_api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes"))
    ):
        for stat in node_stats['items']:
            nodes.append(stat['metadata']['name'])

    return nodes


def node_stats(node):
    node_dict = {}
    if kubeImported := KubernetesDynamic():
        k8s_api = kubeImported.client.CoreV1Api()
        api_response = k8s_api.read_node_status(node)
        stats_api = kubeImported.client.CustomObjectsApi()
        node_stats = stats_api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes/{}".format(node))
        field_selector = 'spec.nodeName=' + node
        pods = k8s_api.list_pod_for_all_namespaces(watch=False, field_selector=field_selector)
        node_dict[node] = [
            api_response.metadata.name,
            ','.join(list(set([x.address for x in api_response.status.addresses if not x.type.endswith('IP')]))),
            ','.join(list(set([x.address for x in api_response.status.addresses if x.type.endswith('IP')]))),
            api_response.spec.provider_id.split('/')[-1],
            api_response.metadata.labels['node.kubernetes.io/instance-type'],
            _core_to_millicore(api_response.status.capacity['cpu']),
            _nanocore_to_millicore(node_stats['usage']['cpu']),
            _percent_cpu(
                _core_to_millicore(api_response.status.capacity['cpu']),
                _nanocore_to_millicore(node_stats['usage']['cpu']),
            ),
            _to_gibibyte_or_mebibyte(api_response.status.capacity['memory']),
            _to_gibibyte_or_mebibyte(node_stats['usage']['memory']),
            _to_gibibyte_or_mebibyte(api_response.status.capacity['ephemeral-storage']),
            len(pods.items),
        ]

    return node_dict


def pod_stats(node, namespace):
    pod_dict = {}
    if kubeImported := KubernetesDynamic():
        k8s_api = kubeImported.client.CoreV1Api()
        stats_api = kubeImported.client.CustomObjectsApi()
        field_selector = 'spec.nodeName=' + node
        if namespace:
            pods = k8s_api.list_namespaced_pod(namespace, watch=False, field_selector=field_selector)
        else:
            pods = k8s_api.list_pod_for_all_namespaces(watch=False, field_selector=field_selector)
        for pod in pods.items:
            pod_name = pod.metadata.name
            namespace = pod.metadata.namespace
            phase = pod.status.phase
            pod_ip = pod.status.pod_ip
            if not pod.metadata.owner_references:
                pod_kind = None
            else:
                pod_kind = pod.metadata.owner_references[0].kind
            worker_node = pod.spec.node_name
            try:
                cpu = 0
                mem = 0
                cpu_mem = stats_api.get_namespaced_custom_object(
                    "metrics.k8s.io", "v1beta1", namespace, "pods", pod_name
                )
                for c in cpu_mem['containers']:
                    if c['usage']['cpu'] == '0':
                        pass
                    else:
                        cpu += int(c['usage']['cpu'][:-1])
                cpu = str(cpu) + 'n'
                cpu = _nanocore_to_millicore(cpu)
                for m in cpu_mem['containers']:
                    mem += int(m['usage']['memory'][:-2])
                mem = str(mem) + 'Ki'
                mem = _to_gibibyte_or_mebibyte(mem)
            except kubeImported.client.rest.ApiException as x:
                if x.status == 404:
                    cpu = 'Not Found'
                    mem = 'Not Found'
            container_name = []
            if not pod.status.container_statuses:
                container_name = None
                container_image = None
            else:
                for container in range(len(pod.status.container_statuses)):
                    container_name.append(
                        '{}:{}'.format(
                            pod.status.container_statuses[container].name,
                            pod.status.container_statuses[container].restart_count,
                        )
                    )
                container_image = []
                for container in range(len(pod.status.container_statuses)):
                    container_image.append(
                        pod.status.container_statuses[container].image.replace(MALCOLM_IMAGE_PREFIX, '')
                    )
            pod_dict[pod_name] = [
                pod_name,
                namespace,
                phase,
                pod_ip,
                pod_kind,
                worker_node,
                cpu,
                mem,
                ','.join(container_name),
                ','.join(container_image),
            ]
            if namespace:
                del pod_dict[pod_name][1]

    return pod_dict


def get_node_hostnames_and_ips(mastersOnly=False):
    result = {}
    result['hostname'] = list()
    result['external'] = list()
    result['internal'] = list()

    if (
        (kubeImported := KubernetesDynamic())
        and (k8s_api := kubeImported.client.CoreV1Api())
        and (
            node_stats := kubeImported.client.CustomObjectsApi().list_cluster_custom_object(
                "metrics.k8s.io", "v1beta1", "nodes"
            )
        )
    ):
        for stat in node_stats['items']:
            if (not mastersOnly) or any(
                [
                    val2bool(deep_get(stat, ['metadata', 'labels', l], default=False))
                    for l in ('node-role.kubernetes.io/control-plane', 'node-role.kubernetes.io/master')
                ]
            ):
                api_response = k8s_api.read_node_status(stat['metadata']['name'])
                result['hostname'].extend(
                    (list(set([x.address for x in api_response.status.addresses if not x.type.endswith('IP')])))
                )
                result['external'].extend(
                    (list(set([x.address for x in api_response.status.addresses if x.type.endswith('ExternalIP')])))
                )
                result['internal'].extend(
                    (list(set([x.address for x in api_response.status.addresses if x.type.endswith('InternalIP')])))
                )

    result['hostname'] = list(set(result['hostname']))
    result['external'] = list(set(result['external']))
    result['internal'] = list(set(result['internal']))

    return result


def GetPodNamesForService(service, namespace):
    podsNames = []

    if namespace and (kubeImported := KubernetesDynamic()) and (client := kubeImported.client.CoreV1Api()):
        podsNames = [
            x.metadata.name
            for x in client.list_namespaced_pod(
                namespace,
                watch=False,
                label_selector=f'name={service}-deployment',
            ).items
        ]

    return podsNames


def PodExec(
    service,
    namespace,
    command,
    stdout=True,
    stderr=True,
    stdin=None,
    timeout=180,
    maxPodsToExec=1,
    container=None,
):
    results = {}
    if namespace and (kubeImported := KubernetesDynamic()) and (client := kubeImported.client.CoreV1Api()):
        podsNames = GetPodNamesForService(service, namespace)

        for podName in podsNames[:maxPodsToExec]:
            retcode = -1
            output = []
            try:
                while True:
                    resp = client.read_namespaced_pod(
                        name=podName,
                        namespace=namespace,
                    )
                    if resp.status.phase != 'Pending':
                        break
                if container:
                    resp = kubeImported.stream.stream(
                        client.connect_get_namespaced_pod_exec,
                        podName,
                        namespace,
                        container=container,
                        command=get_iterable(command),
                        stdout=stdout,
                        stderr=stderr,
                        stdin=stdin is not None,
                        tty=False,
                        _preload_content=False,
                    )
                else:
                    resp = kubeImported.stream.stream(
                        client.connect_get_namespaced_pod_exec,
                        podName,
                        namespace,
                        command=get_iterable(command),
                        stdout=stdout,
                        stderr=stderr,
                        stdin=stdin is not None,
                        tty=False,
                        _preload_content=False,
                    )
                rawOutput = StringIO('')
                rawErrput = StringIO('')
                stdinRemaining = (
                    list(chain(*[i.split('\n') for i in list(get_iterable(stdin))])) if (stdin is not None) else []
                )
                counter = 0
                while resp.is_open() and (counter <= timeout):
                    resp.update(timeout=0 if stdinRemaining else 1)
                    counter += 0 if stdinRemaining else 1
                    if stdout and resp.peek_stdout():
                        rawOutput.write(resp.read_stdout())
                    if stderr and resp.peek_stderr():
                        rawErrput.write(resp.read_stderr())
                    if stdinRemaining:
                        resp.write_stdin(stdinRemaining.pop(0) + "\n")
                if stdout and resp.peek_stdout():
                    rawOutput.write(resp.read_stdout())
                if stderr and resp.peek_stderr():
                    rawErrput.write(resp.read_stderr())
                output.extend(rawOutput.getvalue().split('\n'))
                output.extend(rawErrput.getvalue().split('\n'))

                err = None
                if yamlImported := YAMLDynamic():
                    err = yamlImported.YAML(typ='safe', pure=True).load(
                        resp.read_channel(kubeImported.stream.ws_client.ERROR_CHANNEL)
                    )

                if not err:
                    err = {}
                    err['status'] = 'Success'

                if deep_get(err, ['status'], None) == 'Success':
                    retcode = 0
                elif deep_get(err, ['reason'], None) == 'NonZeroExitCode':
                    retcodes = [
                        int(deep_get(x, ['message'], 1))
                        for x in deep_get(err, ['details', 'causes'], [{'reason': 'ExitCode', 'message': '1'}])
                        if (deep_get(x, ['reason'], None) == 'ExitCode')
                    ]
                    retcode = retcodes[0] if len(retcodes) > 0 else 1
                else:
                    # can't parse, but it's a failure
                    retcode = 1

                resp.close()

            except kubeImported.client.rest.ApiException as x:
                if x.status != 404:
                    if retcode == 0:
                        retcode = 1
                    output.extend(str(x))

            results[podName] = {}
            results[podName]['err'] = retcode
            results[podName]['output'] = output

    return results


def PrintNodeStatus():
    node_list = load_node_list()
    with ThreadPoolExecutor() as executor:
        futures = []
        for node in node_list:
            futures.append(executor.submit(node_stats, node))
        node_summary = {}
        for future in as_completed(futures):
            a = future.result()
            node_summary.update(a)

    statusRows = [
        [
            'Node Name',
            'Hostname',
            'IP',
            'Provider ID',
            'Instance Type',
            'Total CPU',
            'CPU Usage',
            'Percent CPU',
            'Total Memory',
            'Memory Usage',
            'Total Storage',
            'Current Pods',
        ],
    ]
    for node in node_summary:
        statusRows.append([str(x) for x in node_summary[node]])

    tablify(statusRows)


def PrintPodStatus(namespace=None):
    node_list = load_node_list()
    with ThreadPoolExecutor() as executor:
        futures = []
        for node in node_list:
            futures.append(executor.submit(pod_stats, node, namespace))
        pod_summary = {}
        for future in as_completed(futures):
            a = future.result()
            pod_summary.update(a)

    statusRows = [
        [
            'Pod Name',
            'Namespace',
            'State',
            'Pod IP',
            'Pod Kind',
            'Worker Node',
            'CPU Usage',
            'Memory Usage',
            'Container Name:Restarts',
            'Container Image',
        ],
    ]
    if namespace:
        del statusRows[0][1]

    for pod in pod_summary:
        statusRows.append([str(x) for x in pod_summary[pod]])

    tablify(statusRows)


def StartMalcolm(
    namespace,
    malcolmPath,
    configPath,
    profile=PROFILE_MALCOLM,
    imageSource=None,
    imageTag=None,
    injectResources=False,
    startCapturePods=True,
    noCapabilities=False,
    dryrun=False,
):
    if not namespace:
        namespace = MALCOLM_DEFAULT_NAMESPACE

    results_dict = defaultdict(dict)

    if (
        os.path.isdir(malcolmPath)
        and os.path.isdir(configPath)
        and (kubeImported := KubernetesDynamic())
        and (dotenvImported := DotEnvDynamic())
        and (yamlImported := YAMLDynamic())
        and (client := kubeImported.client.CoreV1Api())
        and (apiClient := kubeImported.client.ApiClient())
    ):
        # create the namespace
        if not dryrun:
            try:
                results_dict['create_namespace']['result'] = client.create_namespace(
                    kubeImported.client.V1Namespace(metadata=kubeImported.client.V1ObjectMeta(name=namespace))
                ).metadata
            except kubeImported.client.rest.ApiException as x:
                if x.status != 409:
                    results_dict['create_namespace']['error'] = LoadStrIfJson(str(x))
                    if not results_dict['create_namespace']['error']:
                        results_dict['create_namespace']['error'] = str(x)

        # create configmaps from files
        # files in nested directories will be created with a name like foo_MALDIR_bar_MALDIR_baz.txt
        #   and then renamed to foo/bar/baz.txt during container start up by docker-uid-gid-setup.sh
        if not dryrun:
            results_dict['create_namespaced_config_map']['result'] = dict()
            results_dict['create_namespaced_secret']['result'] = dict()
        for configMapName, configMapFiles in MALCOLM_CONFIGMAPS.items():
            for isSecret in (True, False):
                resultsEntry = 'create_namespaced_secret' if isSecret else 'create_namespaced_config_map'
                mapFiles = [x['path'] for x in configMapFiles if (x.get('secret', False) is isSecret)]
                if mapFiles:
                    try:
                        dataMap = {}
                        binaryDataMap = {}
                        for fname in mapFiles:
                            if os.path.isfile(fname):
                                contents = file_contents(
                                    fname,
                                    binary_fallback=True,
                                )
                                if hasattr(contents, 'decode'):
                                    binaryDataMap[os.path.basename(fname)] = base64.b64encode(contents).decode('utf-8')
                                else:
                                    dataMap[os.path.basename(fname)] = contents
                            elif os.path.isdir(fname):
                                for root, dirNames, fileNames in os.walk(fname):
                                    for f in fileNames:
                                        subfname = os.path.join(root, f)
                                        relfname = str(Path(os.path.join(root, f)).relative_to(fname)).replace(
                                            os.sep, MALCOLM_CONFIGMAP_DIR_REPLACER
                                        )
                                        if os.path.isfile(subfname):
                                            contents = file_contents(
                                                subfname,
                                                binary_fallback=True,
                                            )
                                            if hasattr(contents, 'decode'):
                                                binaryDataMap[relfname] = base64.b64encode(contents).decode('utf-8')
                                            else:
                                                dataMap[relfname] = contents
                        metadata = kubeImported.client.V1ObjectMeta(
                            name=configMapName,
                            namespace=namespace,
                        )
                        if not dryrun:
                            if isSecret:
                                results_dict[resultsEntry]['result'][configMapName] = client.create_namespaced_secret(
                                    namespace=namespace,
                                    body=kubeImported.client.V1Secret(
                                        metadata=metadata,
                                        string_data=dataMap if dataMap else {},
                                        data=binaryDataMap if binaryDataMap else {},
                                    ),
                                ).metadata
                            else:
                                results_dict[resultsEntry]['result'][configMapName] = (
                                    client.create_namespaced_config_map(
                                        namespace=namespace,
                                        body=kubeImported.client.V1ConfigMap(
                                            metadata=metadata,
                                            data=dataMap if dataMap else {},
                                            binary_data=binaryDataMap if binaryDataMap else {},
                                        ),
                                    ).metadata
                                )
                    except kubeImported.client.rest.ApiException as x:
                        if x.status != 409:
                            if 'error' not in results_dict[resultsEntry]:
                                results_dict[resultsEntry]['error'] = dict()
                            results_dict[resultsEntry]['error'][os.path.basename(configMapName)] = LoadStrIfJson(str(x))
                            if not results_dict[resultsEntry]['error'][os.path.basename(configMapName)]:
                                results_dict[resultsEntry]['error'][os.path.basename(configMapName)] = str(x)

        # create configmaps (or secrets, given a K8S_SECRET key) from .env files
        namedEnvs = defaultdict(dict)
        if not dryrun:
            results_dict['create_namespaced_config_map_from_env_file']['result'] = dict()
            results_dict['create_namespaced_secret_from_env_file']['result'] = dict()
        for envFileName in glob.iglob(os.path.join(configPath, '*.env'), recursive=False):
            if os.path.isfile(envFileName):
                try:
                    values = dotenvImported.dotenv_values(envFileName)
                    isSecret = val2bool(values.pop(MALCOLM_DOTFILE_SECRET_KEY, False))
                    metadata = kubeImported.client.V1ObjectMeta(
                        name=remove_suffix(os.path.basename(envFileName), '.env') + '-env'
                    )
                    namedEnvs[metadata.name] = values if values else {}
                    if not dryrun:
                        if isSecret:
                            resultsEntry = 'create_namespaced_secret_from_env_file'
                            results_dict[resultsEntry]['result'][metadata.name] = client.create_namespaced_secret(
                                namespace=namespace,
                                body=kubeImported.client.V1Secret(
                                    metadata=metadata,
                                    string_data=values if values else {},
                                ),
                            ).metadata
                        else:
                            resultsEntry = 'create_namespaced_config_map_from_env_file'
                            results_dict[resultsEntry]['result'][metadata.name] = client.create_namespaced_config_map(
                                namespace=namespace,
                                body=kubeImported.client.V1ConfigMap(
                                    metadata=metadata,
                                    data=values if values else {},
                                ),
                            ).metadata

                except kubeImported.client.rest.ApiException as x:
                    if x.status != 409:
                        if 'error' not in results_dict[resultsEntry]:
                            results_dict[resultsEntry]['error'] = dict()
                        results_dict[resultsEntry]['error'][os.path.basename(envFileName)] = LoadStrIfJson(str(x))
                        if not results_dict[resultsEntry]['error'][os.path.basename(envFileName)]:
                            results_dict[resultsEntry]['error'][os.path.basename(envFileName)] = str(x)

        containerResources = {}
        if injectResources:
            resourcesFilePath = os.path.join(configPath, 'kubernetes-container-resources.yml')
            if os.path.isfile(resourcesFilePath):
                with open(resourcesFilePath, 'r') as resourcesFileHandle:
                    if resourcesFileContents := list(
                        yamlImported.YAML(typ='safe', pure=True).load_all(resourcesFileHandle)
                    ):
                        containerResources = (
                            resourcesFileContents[0] if isinstance(resourcesFileContents[0], dict) else {}
                        )

        # apply manifests
        if not dryrun:
            results_dict['create_from_yaml']['result'] = dict()
        yamlFiles = sorted(
            [
                f
                for f in chain.from_iterable(
                    glob.iglob(os.path.join(os.path.join(malcolmPath, 'kubernetes'), ftype), recursive=False)
                    for ftype in ['*.yml', '*.yaml']
                )
                if startCapturePods
                or not any(
                    f.endswith(suffix) for suffix in ['-live.yml', '-live.yaml', '-capture.yml', '-capture.yaml']
                )
            ]
        )
        for yamlName in yamlFiles:
            # check to make sure the container in this YAML file belongs to this profile
            containerBelongsInProfile = True
            manYamlFileContents = None
            with open(yamlName, 'r') as manYamlFile:
                if manYamlFileContents := list(yamlImported.YAML(typ='safe', pure=True).load_all(manYamlFile)):
                    for doc in manYamlFileContents:
                        if (
                            containers := [
                                remove_suffix(x.get('name', ''), '-container')
                                for x in deep_get(doc, ['spec', 'template', 'spec', 'containers'], [])
                            ]
                        ) and (not all(x in MALCOLM_PROFILES_CONTAINERS[profile] for x in containers)):
                            containerBelongsInProfile = False
                            break

            # apply the manifests in this YAML file, otherwise skip it
            if containerBelongsInProfile:

                # Some manifests need to have some modifications done to them on-the-fly:
                #
                # * Replace namespace if a custom one was passed in
                # * Remove "capabilities" under "securityContext" (for something like Fargate that doesn't support them)
                # * Massage image names (source and tag) if requested
                # * Have resource requests created for them on the fly (idaholab/Malcolm#539).
                #       For now the only ones I'm doing this for are ones that have JAVA_OPTS specified (see CONTAINER_JAVA_OPTS_VARS)
                #           which we retrieve from the container's environment variables we created earlier as configMapRefs.
                #
                modified = False
                if manYamlFileContents:
                    for docIdx, doc in enumerate(manYamlFileContents):

                        # recursively change the namespace document-wide if a different one was specified
                        namespaceChangedDoc, namespaceChanged = replace_namespace(
                            manYamlFileContents[docIdx],
                            namespace,
                        )
                        if namespaceChangedDoc and namespaceChanged:
                            manYamlFileContents[docIdx] = namespaceChangedDoc
                            modified = True

                        # modify container specs
                        if (
                            ('spec' in manYamlFileContents[docIdx])
                            and ('template' in manYamlFileContents[docIdx]['spec'])
                            and ('spec' in manYamlFileContents[docIdx]['spec']['template'])
                        ):
                            for containerType in ('containers', 'initContainers'):
                                if containerType in manYamlFileContents[docIdx]['spec']['template']['spec']:

                                    # loop over each container defined in this document (by index since we're modifying in-place)
                                    for containerIdx, container in enumerate(
                                        manYamlFileContents[docIdx]['spec']['template']['spec'][containerType]
                                    ):
                                        containerName = remove_suffix(
                                            manYamlFileContents[docIdx]['spec']['template']['spec'][containerType][
                                                containerIdx
                                            ].get('name', ''),
                                            '-container',
                                        )
                                        containerImage = manYamlFileContents[docIdx]['spec']['template']['spec'][
                                            containerType
                                        ][containerIdx].get('image', '')
                                        newContainerImage = update_container_image(
                                            containerImage, imageSource, imageTag
                                        )
                                        if newContainerImage != containerImage:
                                            manYamlFileContents[docIdx]['spec']['template']['spec'][containerType][
                                                containerIdx
                                            ]['image'] = newContainerImage
                                            modified = True

                                        # if they've asked to disable the capabilities definition (e.g., for fargate)
                                        if noCapabilities and (
                                            'securityContext'
                                            in manYamlFileContents[docIdx]['spec']['template']['spec'][containerType][
                                                containerIdx
                                            ]
                                        ):
                                            manYamlFileContents[docIdx]['spec']['template']['spec'][containerType][
                                                containerIdx
                                            ]['securityContext'].pop('capabilities', None)
                                            modified = True

                                        # for resource requests we're only concerned about containters we've defined by name in CONTAINER_JAVA_OPTS_VARS
                                        #   or that have been specified in kubernetes-container-resources.yml when injectResources is True
                                        if (containerName in CONTAINER_JAVA_OPTS_VARS) or (
                                            containerName in containerResources
                                        ):

                                            # load up a list of environment variable sets (configMapRefs) defined in the container's envFrom
                                            containerEnvs = {}
                                            if (
                                                'envFrom'
                                                in manYamlFileContents[docIdx]['spec']['template']['spec'][
                                                    containerType
                                                ][containerIdx]
                                            ):
                                                for env in manYamlFileContents[docIdx]['spec']['template']['spec'][
                                                    containerType
                                                ][containerIdx]['envFrom']:
                                                    if ('configMapRef' in env) and ('name' in env['configMapRef']):
                                                        containerEnvs.update(
                                                            namedEnvs.get(env['configMapRef']['name'], {})
                                                        )

                                            # if the memory request from the environment variable exceeds that from the inject YAML, use that instead
                                            injectedContents = containerResources.get(containerName, {})
                                            if (
                                                requestMib := GetMemMegabytesFromJavaOptsLine(
                                                    containerEnvs.get(CONTAINER_JAVA_OPTS_VARS[containerName], '')
                                                )
                                            ) > ParseK8sMemoryToMib(
                                                deep_get(injectedContents, ['resources', 'requests', 'memory'], 0)
                                            ):
                                                deep_set(
                                                    injectedContents,
                                                    ['resources', 'requests', 'memory'],
                                                    f"{requestMib}Mi",
                                                )

                                            # inject the stuff into the container manifest
                                            if injectedContents:
                                                deep_merge_in_place(
                                                    injectedContents,
                                                    manYamlFileContents[docIdx]['spec']['template']['spec'][
                                                        containerType
                                                    ][containerIdx],
                                                )
                                                modified = True

                # if we modified the manifest write out the modified YAML to a temporary file
                with temporary_filename(suffix='.yml') if modified else nullcontext() as tmpYmlFileName:
                    if modified:
                        with open(tmpYmlFileName, 'w') as tmpYmlFile:
                            outYaml = yamlImported.YAML(typ='rt')
                            outYaml.preserve_quotes = True
                            outYaml.allow_duplicate_keys = True
                            outYaml.representer.ignore_aliases = lambda *args: True
                            outYaml.representer.add_representer(type(None), NullRepresenter())
                            outYaml.boolean_representation = ['false', 'true']
                            outYaml.version = YAML_VERSION
                            outYaml.width = 4096
                            outYaml.dump_all(manYamlFileContents, tmpYmlFile)

                    if not dryrun:
                        try:
                            # load from the temporary file if we made modifications, otherwise load from the original
                            results_dict['create_from_yaml']['result'][os.path.basename(yamlName)] = (
                                kubeImported.utils.create_from_yaml(
                                    apiClient,
                                    tmpYmlFileName if modified else yamlName,
                                    namespace=namespace,
                                )
                            )
                        except kubeImported.client.rest.ApiException as x:
                            if x.status != 409:
                                if 'error' not in results_dict['create_from_yaml']:
                                    results_dict['create_from_yaml']['error'] = dict()
                                results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = LoadStrIfJson(
                                    str(x)
                                )
                                if not results_dict['create_from_yaml']['error'][os.path.basename(yamlName)]:
                                    results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = str(x)
                        except kubeImported.utils.FailToCreateError as fe:
                            if [exc for exc in fe.api_exceptions if exc.status != 409]:
                                if 'error' not in results_dict['create_from_yaml']:
                                    results_dict['create_from_yaml']['error'] = dict()
                                results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = LoadStrIfJson(
                                    str(fe)
                                )
                                if not results_dict['create_from_yaml']['error'][os.path.basename(yamlName)]:
                                    results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = str(fe)

    return results_dict


def SafeK8sDelete(
    kubeImported,
    func,
    name,
    namespace,
    results_dict,
    dryrun,
    **kwargs,
):
    try:
        if not dryrun:
            if namespace:
                func(name, namespace, **kwargs)
            else:
                func(name, **kwargs)
        if isinstance(results_dict, dict) and isinstance(results_dict.get('deleted', None), list):
            results_dict['deleted'].append(name)
    except kubeImported.client.rest.ApiException as e:
        if e.status not in [404, 403, 409]:
            if not (errVal := LoadStrIfJson(str(e))):
                errVal = str(e)
            if errVal and isinstance(results_dict, dict) and isinstance(results_dict.get('error', None), list):
                results_dict['error'].append(errVal)


def StopMalcolm(
    namespace,
    deleteNamespace=False,
    deletePVCsAndPVs=False,
    dryrun=False,
):
    results_dict = dict()
    results_dict[namespace] = dict()
    for resourceType in [
        'configmaps',
        'deployments',
        'ingresses',
        'namespace',
        'persistentvolumeclaims',
        'persistentvolumes',
        'secrets',
        'services',
    ]:
        results_dict[namespace][resourceType] = dict()
        for msgType in ['deleted', 'error']:
            results_dict[namespace][resourceType][msgType] = list()

    if kubeImported := KubernetesDynamic():
        k8s_api = kubeImported.client.CoreV1Api()
        apps_api = kubeImported.client.AppsV1Api()
        net_api = kubeImported.client.NetworkingV1Api()
        delete_opts = kubeImported.client.V1DeleteOptions(propagation_policy='Foreground')

        for resource in apps_api.list_namespaced_deployment(namespace).items:
            SafeK8sDelete(
                kubeImported,
                apps_api.delete_namespaced_deployment,
                resource.metadata.name,
                namespace,
                results_dict[namespace]['deployments'],
                dryrun=dryrun,
                body=delete_opts,
            )

        for resource in k8s_api.list_namespaced_service(namespace).items:
            if resource.metadata.name == "kubernetes":
                continue
            SafeK8sDelete(
                kubeImported,
                k8s_api.delete_namespaced_service,
                resource.metadata.name,
                namespace,
                results_dict[namespace]['services'],
                dryrun=dryrun,
            )

        for resource in net_api.list_namespaced_ingress(namespace).items:
            SafeK8sDelete(
                kubeImported,
                net_api.delete_namespaced_ingress,
                resource.metadata.name,
                namespace,
                results_dict[namespace]['ingresses'],
                dryrun=dryrun,
            )

        for resource in k8s_api.list_namespaced_config_map(namespace).items:
            if resource.metadata.name in ["kube-root-ca.crt", "istio-ca-root-cert"]:
                continue
            SafeK8sDelete(
                kubeImported,
                k8s_api.delete_namespaced_config_map,
                resource.metadata.name,
                namespace,
                results_dict[namespace]['configmaps'],
                dryrun=dryrun,
            )

        for resource in k8s_api.list_namespaced_secret(namespace).items:
            if "kubernetes.io/service-account-token" in resource.type:
                continue
            SafeK8sDelete(
                kubeImported,
                k8s_api.delete_namespaced_secret,
                resource.metadata.name,
                namespace,
                results_dict[namespace]['secrets'],
                dryrun=dryrun,
            )

        if deletePVCsAndPVs:
            for resource in k8s_api.list_namespaced_persistent_volume_claim(namespace).items:
                SafeK8sDelete(
                    kubeImported,
                    k8s_api.delete_namespaced_persistent_volume_claim,
                    resource.metadata.name,
                    namespace,
                    results_dict[namespace]['persistentvolumeclaims'],
                    dryrun=dryrun,
                )
            for resource in k8s_api.list_persistent_volume().items:
                if (claim_ref := resource.spec.claim_ref) and (claim_ref.namespace == namespace):
                    SafeK8sDelete(
                        kubeImported,
                        k8s_api.delete_persistent_volume,
                        resource.metadata.name,
                        None,
                        results_dict[namespace]['persistentvolumes'],
                        dryrun=dryrun,
                    )

        if deleteNamespace:
            SafeK8sDelete(
                kubeImported,
                k8s_api.delete_namespace,
                namespace,
                None,
                results_dict[namespace]['namespace'],
                dryrun=dryrun,
                body=delete_opts,
            )

    return remove_falsy(results_dict)


def CheckPersistentStorageDefs(
    namespace,
    malcolmPath,
    profile=PROFILE_MALCOLM,
):
    foundObjects = {k: False for (k, v) in REQUIRED_VOLUME_OBJECTS[profile].items()}

    if yamlImported := YAMLDynamic():
        allYamlContents = []
        yamlFiles = sorted(
            list(
                chain(
                    *[
                        glob.iglob(os.path.join(os.path.join(malcolmPath, 'kubernetes'), ftype), recursive=False)
                        for ftype in ['*.yml', '*.yaml']
                    ]
                )
            )
        )
        for yamlName in yamlFiles:
            with open(yamlName, 'r') as cf:
                allYamlContents.extend(list(yamlImported.YAML(typ='safe', pure=True).load_all(cf)))
        for name, kind in REQUIRED_VOLUME_OBJECTS[profile].items():
            for doc in allYamlContents:
                if (
                    (doc.get('kind', None) == kind)
                    and (deep_get(doc, ['metadata', 'namespace']) in (namespace, MALCOLM_DEFAULT_NAMESPACE))
                    and (deep_get(doc, ['metadata', 'name']) == name)
                ):
                    foundObjects[name] = True

    return all([v for k, v in foundObjects.items()])
