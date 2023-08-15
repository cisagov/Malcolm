# <a name="KubernetesAzure"></a>Deploying Malcolm on Microsoft Azure Kubernetes Service (AKS)

* [Deploying Malcolm on Microsoft Azure Kubernetes Service (AKS)](#KubernetesAzure)
    - [Prerequisites](#Prerequisites)
    - [Procedure](#Procedure)
* [Attribution](#AzureAttribution)

This document outlines the process of setting up a cluster on Microsoft [Azure Kubernetes Service (AKS)](https://azure.microsoft.com/en-us/products/kubernetes-service) using [Azure](https://azure.microsoft.com/en-us/) in preparation for [**Deploying Malcolm with Kubernetes**](kubernetes.md).

This is a work-in-progress document that is still a bit rough around the edges. Any feedback is welcome in the [relevant issue](https://github.com/idaholab/Malcolm/issues/231) on GitHub.

This document assumes good working knowledge of Azure and Azure Kubernetes Service (AKS). Good documentation resources can be found in the [Azure documentation](https://learn.microsoft.com/en-us/azure/), the [AKS documentation](https://learn.microsoft.com/en-us/azure/aks/), [Kubernetes core concepts for Azure Kubernetes Service (AKS)](https://learn.microsoft.com/en-us/azure/aks/concepts-clusters-workloads), and the [AKS Workshop](https://www.microsoft.com/azure/partners/news/article/azure-kubernetes-service-workshop).

## <a name="Prerequisites"></a> Prerequisites

* [az cli](https://learn.microsoft.com/en-us/cli/azure/) - the Azure Command Line Interface with functioning access to the Azure infrastructure

## <a name="Procedure"></a> Procedure

## <a name="AzureAttribution"></a> Attribution

Microsoft Azure, the Microsoft Azure logo, Azure, and any other Microsoft Azure Marks used in these materials are trademarks of Microsoft Corporation or its affiliates in the United States and/or other countries. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation.
