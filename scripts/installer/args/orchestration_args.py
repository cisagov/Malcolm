#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Configuration files arguments for Malcolm installer
"""

import os


def add_orchestration_args(parser):
    """
    Add configuration files arguments to the parser

    Args:
        parser: ArgumentParser to add arguments to
    """
    orchestration_arg_group = parser.add_argument_group("Configuration File Options")

    orchestration_arg_group.add_argument(
        "--compose-file",
        "--configure-file",
        "--kube-file",
        "-f",
        required=False,
        dest="malcolmOrchestrationFile",
        metavar="<string>",
        type=str,
        default=os.getenv("MALCOLM_COMPOSE_FILE", ""),
        help="Path to docker-compose.yml (for compose) or kubeconfig (for Kubernetes)",
    )
