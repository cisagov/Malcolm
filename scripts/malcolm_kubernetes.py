#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import base64
import glob
import os

from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from itertools import chain
from io import StringIO

from malcolm_common import (
    DotEnvDynamic,
    KubernetesDynamic,
    MalcolmPath,
    YAMLDynamic,
)
from malcolm_utils import (
    deep_get,
    dictsearch,
    eprint,
    get_iterable,
    file_contents,
    remove_suffix,
    tablify,
    LoadStrIfJson,
    val2bool,
)


###################################################################################################
MALCOLM_IMAGE_PREFIX = 'ghcr.io/idaholab/malcolm/'

MALCOLM_DOTFILE_SECRET_KEY = 'K8S_SECRET'

MALCOLM_CONFIGMAPS = {
    'etc-nginx': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf')),
        },
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join('nginx', 'nginx.conf')),
        },
    ],
    'var-local-catrust': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join('nginx', 'ca-trust')),
        },
    ],
    'etc-nginx-certs': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('nginx', 'certs')),
        },
    ],
    'etc-nginx-certs-pem': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join(os.path.join('nginx', 'certs'), 'dhparam.pem')),
        },
    ],
    'etc-nginx-auth': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd')),
        },
    ],
    'opensearch-curlrc': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, '.opensearch.primary.curlrc'),
        },
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, '.opensearch.secondary.curlrc'),
        },
    ],
    'opensearch-keystore': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('opensearch', 'opensearch.keystore')),
        },
    ],
    'logstash-certs': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('logstash', 'certs')),
        },
    ],
    'logstash-maps': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join('logstash', 'maps')),
        },
    ],
    'logstash-keystore': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('logstash', 'logstash.keystore')),
        },
    ],
    'yara-rules': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join('yara', 'rules')),
        },
    ],
    'suricata-rules': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join('suricata', 'rules')),
        },
    ],
    'filebeat-certs': [
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('filebeat', 'certs')),
        },
    ],
    'netbox-netmap-json': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, 'net-map.json'),
        },
    ],
    'netbox-config': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join(os.path.join('netbox', 'config'), 'configuration')),
        },
    ],
    'netbox-reports': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join(os.path.join('netbox', 'config'), 'reports')),
        },
    ],
    'netbox-scripts': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join(os.path.join('netbox', 'config'), 'scripts')),
        },
    ],
    'htadmin-config': [
        {
            'secret': False,
            'path': os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini')),
        },
        {
            'secret': True,
            'path': os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')),
        },
    ],
}

REQUIRED_VOLUME_OBJECTS = {
    'pcap-claim': 'PersistentVolumeClaim',
    'zeek-claim': 'PersistentVolumeClaim',
    'suricata-claim': 'PersistentVolumeClaim',
    'config-claim': 'PersistentVolumeClaim',
    'runtime-logs-claim': 'PersistentVolumeClaim',
    'opensearch-claim': 'PersistentVolumeClaim',
    'opensearch-backup-claim': 'PersistentVolumeClaim',
    # the PersistentVolumes themselves aren't used directly,
    #   so we only need to define the PersistentVolumeClaims
    # 'pcap-volume': 'PersistentVolume',
    # 'zeek-volume': 'PersistentVolume',
    # 'suricata-volume': 'PersistentVolume',
    # 'config-volume': 'PersistentVolume',
    # 'runtime-logs-volume': 'PersistentVolume',
    # 'opensearch-volume': 'PersistentVolume',
    # 'opensearch-backup-volume': 'PersistentVolume',
}


###################################################################################################
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
                        cpu = +int(c['usage']['cpu'][:-1])
                cpu = str(cpu) + 'n'
                cpu = _nanocore_to_millicore(cpu)
                for m in cpu_mem['containers']:
                    mem = +int(m['usage']['memory'][:-2])
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
    timeout=60,
    maxPodsToExec=1,
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
                stdinRemaining = list(get_iterable(stdin)) if (stdin is not None) else []
                counter = 0
                while resp.is_open() and (counter <= timeout):
                    resp.update(timeout=1)
                    counter += 1
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
                    err = yamlImported.safe_load(resp.read_channel(kubeImported.stream.ws_client.ERROR_CHANNEL))

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


def DeleteNamespace(namespace, deleteRetPerVol=False):
    results_dict = defaultdict(dict)

    if namespace:
        if kubeImported := KubernetesDynamic():
            k8s_api = kubeImported.client.CoreV1Api()

            manualDeletePersistentVolumes = []
            if deleteRetPerVol:
                # If indicated, manually delete PersistentVolumes with "Retain" reclaim policy
                #   - https://kubernetes.io/docs/concepts/storage/persistent-volumes/#retain

                # get a list of PersistentVolumes to delete after the delete_namespace
                # 1. from list_namespaced_persistent_volume_claim
                # 2. from list_persistent_volume with the "namespace=XXXXXXX" label
                manualDeletePersistentVolumes = [
                    x.spec.volume_name
                    for x in k8s_api.list_namespaced_persistent_volume_claim(
                        watch=False,
                        namespace=namespace,
                    ).items
                ]
                manualDeletePersistentVolumes.extend(
                    [
                        x.metadata.name
                        for x in k8s_api.list_persistent_volume(
                            label_selector=f'namespace={namespace}',
                        ).items
                        if x.spec.persistent_volume_reclaim_policy == 'Retain'
                    ]
                )

                # filter (ensuring we only ended up with "Retain" PersistentVolumes) and dedupe
                manualDeletePersistentVolumes = list(
                    chain(
                        *[
                            [
                                x.metadata.name
                                for x in k8s_api.list_persistent_volume(
                                    field_selector=f'metadata.name={name}',
                                ).items
                                if x.spec.persistent_volume_reclaim_policy == 'Retain'
                            ]
                            for name in set(manualDeletePersistentVolumes)
                        ]
                    )
                )

            # delete the namespace, which should delete the resources belonging to it
            try:
                results_dict[namespace]['delete_namespace'] = k8s_api.delete_namespace(
                    namespace,
                    propagation_policy='Foreground',
                )
            except kubeImported.client.rest.ApiException as x:
                if x.status != 404:
                    results_dict[namespace]['error'] = LoadStrIfJson(str(x))
                    if not results_dict[namespace]['error']:
                        results_dict[namespace]['error'] = str(x)

            # If indicated, manually delete each PersistentVolume with "Retain" reclaim policy identified above
            if manualDeletePersistentVolumes:
                results_dict[namespace]['delete_persistent_volume'] = dict()
                for name in manualDeletePersistentVolumes:
                    try:
                        results_dict[namespace]['delete_persistent_volume'][name] = k8s_api.delete_persistent_volume(
                            name=name
                        )
                    except kubeImported.client.rest.ApiException as x:
                        if x.status != 404:
                            if 'error' not in results_dict[namespace]['delete_persistent_volume']:
                                results_dict[namespace]['delete_persistent_volume']['error'] = dict()
                            results_dict[namespace]['delete_persistent_volume']['error'][name] = LoadStrIfJson(str(x))
                            if not results_dict[namespace]['delete_persistent_volume']['error'][name]:
                                results_dict[namespace]['delete_persistent_volume']['error'][name] = str(x)

    return results_dict


def StartMalcolm(namespace, malcolmPath, configPath):
    if not namespace:
        namespace = 'malcolm'

    results_dict = defaultdict(dict)

    if (
        os.path.isdir(malcolmPath)
        and os.path.isdir(configPath)
        and (kubeImported := KubernetesDynamic())
        and (dotenvImported := DotEnvDynamic())
        and (client := kubeImported.client.CoreV1Api())
        and (apiClient := kubeImported.client.ApiClient())
    ):
        # create the namespace
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
                                for subfname in glob.iglob(
                                    os.path.join(os.path.join(fname, '**'), '*'), recursive=True
                                ):
                                    if os.path.isfile(subfname):
                                        contents = file_contents(
                                            subfname,
                                            binary_fallback=True,
                                        )
                                        if hasattr(contents, 'decode'):
                                            binaryDataMap[os.path.basename(subfname)] = base64.b64encode(
                                                contents
                                            ).decode('utf-8')
                                        else:
                                            dataMap[os.path.basename(subfname)] = contents
                        metadata = kubeImported.client.V1ObjectMeta(
                            name=configMapName,
                            namespace=namespace,
                        )
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
                            results_dict[resultsEntry]['result'][configMapName] = client.create_namespaced_config_map(
                                namespace=namespace,
                                body=kubeImported.client.V1ConfigMap(
                                    metadata=metadata,
                                    data=dataMap if dataMap else {},
                                    binary_data=binaryDataMap if binaryDataMap else {},
                                ),
                            ).metadata
                    except kubeImported.client.rest.ApiException as x:
                        if x.status != 409:
                            if 'error' not in results_dict[resultsEntry]:
                                results_dict[resultsEntry]['error'] = dict()
                            results_dict[resultsEntry]['error'][os.path.basename(configMapName)] = LoadStrIfJson(str(x))
                            if not results_dict[resultsEntry]['error'][os.path.basename(configMapName)]:
                                results_dict[resultsEntry]['error'][os.path.basename(configMapName)] = str(x)

        # create configmaps (or secrets, given a K8S_SECRET key) from .env files
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

        # apply manifests
        results_dict['create_from_yaml']['result'] = dict()
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
            try:
                results_dict['create_from_yaml']['result'][
                    os.path.basename(yamlName)
                ] = kubeImported.utils.create_from_yaml(
                    apiClient,
                    yamlName,
                    namespace=namespace,
                )
            except kubeImported.client.rest.ApiException as x:
                if x.status != 409:
                    if 'error' not in results_dict['create_from_yaml']:
                        results_dict['create_from_yaml']['error'] = dict()
                    results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = LoadStrIfJson(str(x))
                    if not results_dict['create_from_yaml']['error'][os.path.basename(yamlName)]:
                        results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = str(x)
            except kubeImported.utils.FailToCreateError as fe:
                if [exc for exc in fe.api_exceptions if exc.status != 409]:
                    if 'error' not in results_dict['create_from_yaml']:
                        results_dict['create_from_yaml']['error'] = dict()
                    results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = LoadStrIfJson(str(fe))
                    if not results_dict['create_from_yaml']['error'][os.path.basename(yamlName)]:
                        results_dict['create_from_yaml']['error'][os.path.basename(yamlName)] = str(fe)

    return results_dict


def CheckPersistentStorageDefs(namespace, malcolmPath):
    foundObjects = {k: False for (k, v) in REQUIRED_VOLUME_OBJECTS.items()}

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
                allYamlContents.extend(list(yamlImported.safe_load_all(cf)))
        for name, kind in REQUIRED_VOLUME_OBJECTS.items():
            for doc in allYamlContents:
                if (
                    (doc.get('kind', None) == kind)
                    and (deep_get(doc, ['metadata', 'namespace']) == namespace)
                    and (deep_get(doc, ['metadata', 'name']) == name)
                ):
                    foundObjects[name] = True

    return all([v for k, v in foundObjects.items()])
