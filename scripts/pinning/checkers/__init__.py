# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

from .binaries import Binaries
from .docker_images import DockerImages
from .github_actions import GithubActions
from .other import Other
from .python_reqs import PythonRequirements
from .source_pins import SourcePins
from .zeek_packages import ZeekPackages

# report order
CHECKERS = [DockerImages, GithubActions, Binaries, SourcePins, ZeekPackages, PythonRequirements, Other]
