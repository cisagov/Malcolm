#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Malcolm MVC Views
=================

This package contains all view classes used in the Malcolm installer GUI.
Views represent the user interface components of the application.
"""

from .auth_view import AuthView
from .network_view import NetworkView
from .system_view import SystemView
from .welcome_view import WelcomeView
from .analysis_view import AnalysisView
from .installation_view import InstallationView

__all__ = [
    "SystemView",
    "AuthView",
    "NetworkView",
    "WelcomeView",
    "AnalysisView",
    "InstallationView",
]
