#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

from concurrent.futures import ThreadPoolExecutor, as_completed

from malcolm_common import (
    KubernetesDynamic,
)
from malcolm_utils import (
    eprint,
    tablify,
    LoadStrIfJson,
)


###################################################################################################
MALCOLM_IMAGE_PREFIX = 'ghcr.io/idaholab/malcolm/'


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


def DeleteNamespace(namespace):
    results_dict = {}
    if namespace:
        if kubeImported := KubernetesDynamic():
            try:
                results_dict[namespace] = kubeImported.client.CoreV1Api().delete_namespace(
                    namespace,
                    propagation_policy='Foreground',
                )
            except kubeImported.client.rest.ApiException as x:
                results_dict[namespace] = LoadStrIfJson(str(x))
                if not results_dict[namespace]:
                    results_dict[namespace] = str(x)

    return results_dict
