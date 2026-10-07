#   BROADCOM CONFIDENTIAL
#   _____________________
#
#   Copyright (C) 2015-2024 Broadcom. All Rights Reserved. The term “Broadcom”
#   refers to Broadcom Inc. and/or its subsidiaries.

'''The pytest wrapper for running security scripts unit tests with coverage.'''

import os
from pathlib import PurePath
import sys

import pytest


# Executing `pytest` from here cause the path of this file (which is the `test`
# dir.) is at front in the `sys.path`. This cause issue if the `test` dir.
# having the same structure like the `src` dir.
# Ex:
#   src/
#    |- pkg/
#    |   |- __init__.py
#    |   |- mod.py
#    |- __init__.py
#    |- main.py
#   test/
#    |- pkg/
#    |   |- __init__.py
#    |   |- test_mod.py
#    |- __init__.py
#    |- test_main.py
# A statement like `import pkg.mod` will cause `test/pkg/` is searched.
# In order to be able to keep the same naming structure in `test` dir., we need
# to manipulate the `sys.path`.
sys.path.insert(0, str(PurePath(sys.path.pop(0)).parent))


def main():
    # Inside `bazel`, the __file__ is
    #   `${PWD}/path/to/module/test/module_test_suite.py`.
    try:
        src_dir = PurePath(os.readlink(__file__)).parents[1]
    except OSError:
        src_dir = PurePath(__file__).relative_to(os.getcwd()).parents[1]

    pytest_args = [
        '-v',
        '-p',
        'no:cacheprovider',
        '--cov-config',
        'tools/common/pytest-cov/.coveragerc',
        '--cov-report',
        'term-missing',
        '--cov',
        src_dir,
        '--cov-fail-under',
        '44',
        'security/test',
    ]

    sys.exit(pytest.main(pytest_args))


if __name__ == '__main__':
    main()
