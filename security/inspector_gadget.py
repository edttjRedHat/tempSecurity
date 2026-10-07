#!/usr/bin/env python3

'''Helper tool for interacting with OSSPI Security Scan results.'''
# pylint: disable=too-many-lines

import argparse
from collections import defaultdict, namedtuple
import copy
import csv
import dataclasses
from http.client import HTTPConnection
import json
import logging
import pathlib
import re
import subprocess
import sys
import time
import urllib.parse
import yaml

import jinja2
import requests

from py_libs.decorators import static_func_vars
from py_libs import utils

# Generic product labels and identifiers
MAIN_VER = '0.0.0'
MAIN_VER_RE = r'^0\.0\.0$'
ANY_VER_RE = r'^(?:[0-9*?]+.)*[0-9*?]+$'
#   Platforms
TCX = 'TCx'
TCX_MAIN_VER = '*.*.*'
TPS = 'TPS'
TPS_MAIN_VER = '*.*.*'
#   Containers
TCX_DEPLOYMENT_CONTAINER = 'TCx Deployment Container'
TCX_DEPLOYMENT_CONTAINER_MAIN_VER = '*.*.*'
#   Products
TCX_K8S_INSTALLER = 'TCx K8s Installer'
TCX_K8S_INSTALLER_MAIN_VER = '*.*.*'
TCA = 'TCA'
TCA_CNVA = 'CNVA'
TCA_MAIN_VER = '*.*.*'
TCA_RELEASE_VER_RE = r'^3\.[0-4]\.[0-9]$'
TCSA = 'TCSA'
TCSA_MAIN_VER = '*.*.?'
TCSA_RELEASE_VER_RE = r'^2\.[1-4]\.[0-9]$'
RIC = 'RIC'
RIC_INSTALLER = 'RIC Installer'
CRIC = 'cRIC'
CRIC_SDK = 'cRIC SDK'
CRIC_RAPP_ES = 'cRIC rApp Energy Saving'
CRIC_RAPP_RAN_KPI = 'cRIC rApp RAN KPI'
DRIC = 'dRIC'
DRIC_SDK = 'dRIC SDK'
DRIC_SDK_MPP = 'dRIC SDK MPP'
DRIC_XAPP_VONR = 'dRIC xApp VoNR'
RMS = 'RMS'
RIC_MAIN_VER = '0.0.0'
RIC_RELEASE_VER_RE = r'^2\.[0-1]\.[0-9]$'
SDM = 'Smarts-DM'
SDM_MAIN_VER = '*.*.*'
UHANA = 'UHANA'
UHANA_RELEASE_0_52_4_RE = r'^0\.52\.4$'
UHANA_RELEASE_0_52_3_RE = r'^0\.52\.3$'
UHANA_RELEASE_0_52_2_RE = r'^0\.52\.2$'
UHANA_RELEASE_0_52_1_RE = r'^0\.52\.1$'
UHANA_RELEASE_0_52_0_RE = r'^0\.52\.0$'
# Product Release data
QUERY_BUILD_URL_ARTIFACTORY = QUERY_REPO_URL_ARTIFACTORY = \
    QUERY_RELEASE_URL_ARTIFACTORY = \
    'https://usw1.packages.broadcom.com/api/search/aql'
QUERY_BUILD_BODY_ARTIFACTORY_AQL = '''items.find(
    {{{{"repo": "{repoName}"}}}},
    {{{{"path": {{{{"$match": "{filePath}"}}}}}}}},
    {{{{"name": {{{{"$match": "{fileName}"}}}}}}}},
    {{{{"type": "{itemType}"}}}}
)'''
QUERY_BUILD_BODY_ARTIFACTORY = QUERY_BUILD_BODY_ARTIFACTORY_AQL + '''.sort(
    {{{{"$desc": ["created"]}}}}
).limit(1)
'''
QUERY_REPO_BODY_ARTIFACTORY = QUERY_BUILD_BODY_ARTIFACTORY_AQL + '''.limit(2)
'''
QUERY_RELEASE_BODY_ARTIFACTORY = QUERY_BUILD_BODY_ARTIFACTORY_AQL + '''.sort(
    {{{{"$desc": ["name"]}}}}
).limit(1)
'''
QUERY_BUILD_URL_BUILDWEB = \
    'http://buildapi.eng.vmware.com/{{buildMode}}/build/?' \
    'product={prodName}&branch={{branchName}}{extraQpars}' \
    '&_order_by=-id&_limit=1&buildstate=succeeded&ondisk=true'
QUERY_REPO_URL_BUILDWEB = \
    'http://buildweb.eng.vmware.com/{{buildMode}}/api/{{buildNo}}/' \
    'deliverable/?file=publish/{fullPath}'
QUERY_RELEASE_URL_HARBOR = QUERY_BUILD_URL_HARBOR = QUERY_REPO_URL_HARBOR = \
    'https://projects.registry.vmware.com/api/v2.0/' \
    'projects/{projName}/repositories/{repoPath}/artifacts?' \
    'sort=-id&{qPar}page=1&page_size=1&with_tag=true'
# pylint: disable=line-too-long
PRODUCT_ARTIFACTS = {
    TCX: {None: {}},
    TPS: {None: {}},
    TCX_DEPLOYMENT_CONTAINER: {None: {}},
    TCX_K8S_INSTALLER: {None: {}},
    TCA: {
        TCA_CNVA: {'prodName': 'tca-cnva', 'filePfx': 'VMware-Telco-Cloud-Automation', 'buildTarget': ''},  # noqa: E501
    },
    TCSA: {None: {}},
    RIC: {
        RIC_INSTALLER: {'prodName': 'ric-installer', 'filePfx': 'vmware-ric-installer'},        # noqa: E501
        CRIC: {'prodName': 'cric', 'filePfx': 'vmware-cric-bundle'},                            # noqa: E501
        CRIC_SDK: {'prodName': 'cric-sdk', 'filePfx': 'vmware-cric-sdk'},                       # noqa: E501
        CRIC_RAPP_ES: {'prodName': 'energy-saving', 'filePfx': 'vmware-energy-saving-bundle'},  # noqa: E501
        CRIC_RAPP_RAN_KPI: {'prodName': 'ran-kpi', 'filePfx': 'vmware-ran-kpi-bundle'},         # noqa: E501
        DRIC: {'prodName': 'dric', 'filePfx': 'vmware-dric-bundle'},                            # noqa: E501
        DRIC_SDK: {'prodName': 'dric-sdk', 'filePfx': 'vmware-dric-sdk'},                       # noqa: E501
        DRIC_SDK_MPP: {'prodName': 'dric-sdk-mpp', 'filePfx': 'vmware-dric-sdk-mpp'},           # noqa: E501
        DRIC_XAPP_VONR: {'prodName': 'xapp-vonr', 'filePfx': 'vmware-xapp-vonr-bundle'},        # noqa: E501
        RMS: {'prodName': 'rms', 'filePfx': 'vmware-rms-bundle'},                               # noqa: E501
    },
    SDM: {None: {}},
    UHANA: {None: {}},
}
# pylint: enable=line-too-long
PRODUCT_BUILD_REPO = {
    # The `url` will be finalized using `str.format()` method, with arguments
    # `relVer`, `buildNo` (for querying `repo`) and all parameters under
    # 'urlParams`. Similarly with `body`.
    # The `queryFunc` is the name of this module level function that has the
    # following signature (the `queryFuncParams` will be passed as `kwargs`):
    #   def _query_build_XXX(api_info, params, **kwargs):
    #       '''_query_build_XXX gets the latest build no. from `XXX`.
    #
    #       Args:
    #           api_info (dict):    PRODUCT_BUILD_REPO[product]['build'][...]
    #           params (dict):      Dictionary containing the following keys:
    #                                   'relVer': str
    #                                   Any parameters for `str.format()` to
    #                                       construct `url` and/or `body`.
    #           **kwargs:           Any parameters required by this function.
    #       Returns:
    #           (int): The latest build no.
    #       '''
    #
    #
    #   def _query_repo_XXX(api_info, params, **kwargs):
    #       '''_query_repo_XXX verifies that a specific artifact is available
    #       from `XXX`.
    #
    #       Args:
    #           api_info (dict):    PRODUCT_BUILD_REPO[product]['repo'][...]
    #           params (dict):      Dictionary containing the following keys:
    #                                   'relVer': str
    #                                   'buildNo': str
    #                                   Any parameters for `str.format()` to
    #                                       construct `url` and/or `body`.
    #           **kwargs:           Any parameters required by this function.
    #       Returns:
    #           (tuple): Tuple of `(url, auth)`
    #               Where:
    #                   url (urllib.parse.ParseResult):
    #                       The URL to fetch a specific artifact.
    #                   auth (tuple):
    #                       The URL Authentication Method (see
    #                       `_url_exists()`).
    #   '''
    #
    #
    #   OPTIONAL:
    #   def _query_release_XXX(api_info, params, **kwargs):
    #       '''_query_release_XXX gets the latest release ver. from `XXX`.
    #
    #       Args:
    #           api_info (dict):    PRODUCT_BUILD_REPO[product]['repo'][...]
    #           params (dict):      Dictionary containing the following keys:
    #                                   Any parameters for `str.format()` to
    #                                       construct `url` and/or `body`.
    #           **kwargs:           Any parameters required by this function.
    #       Returns:
    #           (str): The latest release version.
    #   '''
    TCX: {
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='release/packages/tcx-services',
                fileName='BOM-tcx-services-{relVer}-*.yaml',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': TCX_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'-(\d+)\.yaml$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_REPO_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='release/packages/tcx-services',
                fileName='BOM-tcx-services-{relVer}-{buildNo}.yaml',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': TCX_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
    TPS: {
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='release/packages/tcx-platform-services',
                fileName='BOM-tcx-platform-services-{relVer}-*.yaml',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': TPS_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'-(\d+)\.yaml$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_REPO_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='release/packages/tcx-platform-services',
                fileName='BOM-tcx-platform-services-{relVer}-{buildNo}.yaml',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': TPS_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
    TCX_DEPLOYMENT_CONTAINER: {
        'release': {
            'url': QUERY_RELEASE_URL_ARTIFACTORY.format(
                projName='tcx',
                repoPath='deployment',
                qPar='',
            ),
            'urlParams': {
                MAIN_VER_RE: {},
            },
            'body': QUERY_RELEASE_BODY_ARTIFACTORY.format(
                repoName='tcx-docker-local',
                filePath='{buildTypeDir}/images/deployment',
                fileName='{relVer}-*',
                itemType='folder',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'buildTypeDir': 'release',
                    'relVer': TCX_DEPLOYMENT_CONTAINER_MAIN_VER,
                },
            },
            'queryFunc': '_query_release_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                MAIN_VER_RE: {
                    'releaseCaptureRE': r'(\d+\.\d+\.\d+)-\d+$',
                },
            },
        },
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='tcx-docker-local',
                filePath='{buildTypeDir}/images/deployment',
                fileName='{relVer}-*',
                itemType='folder',
            ),
            'bodyParams': {
                ANY_VER_RE: {
                    'buildTypeDir': 'release',
                },
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'-(\d+)$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_REPO_BODY_ARTIFACTORY.format(
                repoName='tcx-docker-local',
                filePath='{buildTypeDir}/images/deployment',
                fileName='{relVer}-{buildNo}',
                itemType='folder',
            ),
            'bodyParams': {
                ANY_VER_RE: {
                    'buildTypeDir': 'release',
                },
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {'getRegistryURL': True},
            'queryFuncData': {},
        },
    },
    TCX_K8S_INSTALLER: {
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='release/packages/VMware-K8s-Installer',
                fileName='VMware-K8s-Installer-{relVer}-*.tar.gz',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': TCX_K8S_INSTALLER_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'-(\d+)\.tar.gz$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_REPO_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='release/packages/VMware-K8s-Installer',
                fileName='VMware-K8s-Installer-{relVer}-{buildNo}.tar.gz',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': TCX_K8S_INSTALLER_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
    TCA: {
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                MAIN_VER_RE: {},
                TCA_RELEASE_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='sp-tcabuild-generic-dev-local',
                filePath='{buildType}/{prodName}{buildTarget}/{relVer}/*/'
                         'publish/generic/ova',
                fileName='{filePfx}-*.ova',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'buildType': 'official',
                    'relVer': 'main',
                },
                TCA_RELEASE_VER_RE: {
                    'buildType': 'official',
                },
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'_(\d+)\.ova$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                MAIN_VER_RE: {},
                TCA_RELEASE_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='sp-tcabuild-generic-dev-local',
                filePath='{buildType}/{prodName}{buildTarget}/{relVer}/*/'
                         'publish/generic/ova',
                fileName='{filePfx}-*_{buildNo}.ova',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'buildType': 'official',
                    'relVer': 'main',
                },
                TCA_RELEASE_VER_RE: {
                    'buildType': 'official',
                },
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
    TCSA: {
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                MAIN_VER_RE: {},
                TCSA_RELEASE_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='tcx-deployer',
                fileName='VMware-TCSA-Deployer{relType}-{relVer}{buildType}-'
                         '*.tar.gz',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relType': '-develop',
                    'relVer': TCSA_MAIN_VER,
                    'buildType': '-SNAPSHOT',
                },
                TCSA_RELEASE_VER_RE: {
                    'relType': '',
                    'buildType': '',
                },
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'-(\d+)\.tar.gz$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                MAIN_VER_RE: {},
                TCSA_RELEASE_VER_RE: {},
            },
            'body': QUERY_REPO_BODY_ARTIFACTORY.format(
                repoName='tcx-generic-local',
                filePath='tcx-deployer',
                fileName='VMware-TCSA-Deployer{relType}-{relVer}{buildType}-'
                         '{buildNo}.tar.gz',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relType': '-develop',
                    'relVer': TCSA_MAIN_VER,
                    'buildType': '-SNAPSHOT',
                },
                TCSA_RELEASE_VER_RE: {
                    'relType': '',
                    'buildType': '',
                },
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
    RIC: {
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                MAIN_VER_RE: {},
                RIC_RELEASE_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='sp-ric-generic-dev-local',
                filePath='bundles/{buildType}/{prodName}',
                fileName='{filePfx}-{relVer}_*.tar.gz',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'buildType': 'snapshot',
                    'relVer': RIC_MAIN_VER,
                },
                RIC_RELEASE_VER_RE: {
                    'buildType': 'release',
                },
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'_(\d+)\.tar.gz$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                MAIN_VER_RE: {},
                RIC_RELEASE_VER_RE: {},
            },
            'body': QUERY_REPO_BODY_ARTIFACTORY.format(
                repoName='sp-ric-generic-dev-local',
                filePath='bundles/{buildType}/{prodName}',
                fileName='{filePfx}-{relVer}_{buildNo}.tar.gz',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'buildType': 'snapshot',
                    'relVer': RIC_MAIN_VER,
                },
                RIC_RELEASE_VER_RE: {
                    'buildType': 'release',
                },
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
    SDM: {
        'build': {
            'url': QUERY_BUILD_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_BUILD_BODY_ARTIFACTORY.format(
                repoName='vsa-tcsa-dms-release-maven-local',
                filePath='work/distr/CDROMS/test-versions/Smarts-DM',
                fileName='VMware-Smarts-DM-{relVer}.*_metadata.yaml',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': SDM_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_build_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {
                ANY_VER_RE: {
                    'buildCaptureRE': r'.(\d+)_metadata\.yaml$',
                },
            },
        },
        'repo': {
            'url': QUERY_REPO_URL_ARTIFACTORY,
            'urlParams': {
                ANY_VER_RE: {},
            },
            'body': QUERY_REPO_BODY_ARTIFACTORY.format(
                repoName='vsa-tcsa-dms-release-maven-local',
                filePath='work/distr/CDROMS/test-versions/Smarts-DM',
                fileName='VMware-Smarts-DM-{relVer}.{buildNo}_metadata.yaml',
                itemType='file',
            ),
            'bodyParams': {
                MAIN_VER_RE: {
                    'relVer': SDM_MAIN_VER,
                },
                ANY_VER_RE: {},
            },
            'queryFunc': '_query_repo_artifactory',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
    UHANA: {
        'build': {
            'url': QUERY_BUILD_URL_BUILDWEB.format(
                prodName='uhana',
                extraQpars='',
            ),
            'urlParams': {
                MAIN_VER_RE: {
                    'buildMode': 'sb',
                    'branchName': 'uhana-main',
                },
                UHANA_RELEASE_0_52_4_RE: {
                    'buildMode': 'ob',
                    'branchName': 'releaseSimba',
                },
                UHANA_RELEASE_0_52_3_RE: {
                    'buildMode': 'ob',
                    'branchName': 'releaseRapunzel',
                },
                UHANA_RELEASE_0_52_2_RE: {
                    'buildMode': 'ob',
                    'branchName': 'releasePinocchio',
                },
                UHANA_RELEASE_0_52_1_RE: {
                    'buildMode': 'ob',
                    'branchName': 'releaseNeo',
                },
                UHANA_RELEASE_0_52_0_RE: {
                    'buildMode': 'ob',
                    'branchName': 'releaseLupin',
                },
            },
            'body': '',
            'bodyParams': {
                MAIN_VER_RE: {},
                UHANA_RELEASE_0_52_4_RE: {},
                UHANA_RELEASE_0_52_3_RE: {},
                UHANA_RELEASE_0_52_2_RE: {},
                UHANA_RELEASE_0_52_1_RE: {},
                UHANA_RELEASE_0_52_0_RE: {},
            },
            'queryFunc': '_query_build_buildapi',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
        'repo': {
            'url': QUERY_REPO_URL_BUILDWEB.format(
                fullPath='release/uhana-bundle-{buildNo}.tar.gz',
            ),
            'urlParams': {
                MAIN_VER_RE: {
                    'buildMode': 'sb',
                },
                UHANA_RELEASE_0_52_4_RE: {
                    'buildMode': 'ob',
                },
                UHANA_RELEASE_0_52_3_RE: {
                    'buildMode': 'ob',
                },
                UHANA_RELEASE_0_52_2_RE: {
                    'buildMode': 'ob',
                },
                UHANA_RELEASE_0_52_1_RE: {
                    'buildMode': 'ob',
                },
                UHANA_RELEASE_0_52_0_RE: {
                    'buildMode': 'ob',
                },
            },
            'body': '',
            'bodyParams': {
                MAIN_VER_RE: {},
                UHANA_RELEASE_0_52_4_RE: {},
                UHANA_RELEASE_0_52_3_RE: {},
                UHANA_RELEASE_0_52_2_RE: {},
                UHANA_RELEASE_0_52_1_RE: {},
                UHANA_RELEASE_0_52_0_RE: {},
            },
            'queryFunc': '_query_repo_buildweb',
            'queryFuncParams': {},
            'queryFuncData': {},
        },
    },
}
# OSSPI Dashboard
OSSPI_BASE_URL = 'https://osspi.eng.vmware.com/api/v3'
DEFAULT_OSSPI_SCAN_TIMEOUT_M = 60
# Project in OSSPI Dashboard
TCX_MAIN_OSSPI = 'TCx-Mainline'
TPS_MAIN_OSSPI = 'TPS-Mainline'
TCX_DEPLOYMENT_CONTAINER_MAIN_OSSPI = 'TCx-Deployment-Container-Mainline'
TCX_K8S_INSTALLER_MAIN_OSSPI = 'TCx-K8s-Installer-Mainline'
TCX_K8S_INSTALLER_2_3_X_OSSPI = 'TCx-K8s-Installer-Release-2.3.x'
TCX_K8S_INSTALLER_2_1_X_OSSPI = 'TCx-K8s-Installer-Release-2.1.x'
TCX_K8S_INSTALLER_2_0_X_OSSPI = 'TCx-K8s-Installer-Release-2.0.x'
TCX_K8S_INSTALLER_1_0_0_OSSPI = 'TCx-K8s-Installer-Release-1.0.0'
TCA_MAIN_OSSPI = 'tca-cnva'
TCSA_MAIN_OSSPI = 'TCSA-Deployer-Mainline'
TCSA_2_4_0_OSSPI = 'TCSA-Deployer-Release-2.4.0'
TCSA_2_3_1_OSSPI = 'TCSA-Deployer-Release-2.3.1'
TCSA_2_3_0_OSSPI = 'TCSA-Deployer-Release-2.3.0'
TCSA_2_2_0_OSSPI = 'TCSA-Deployer-Release-2.2.0'
TCSA_2_1_0_OSSPI = 'TCSA-Deployer-Release-2.1.0'
RIC_INSTALLER_MAIN_OSSPI = 'RIC-Mainline-RIC-Installer'
CRIC_MAIN_OSSPI = 'RIC-Mainline-cRIC'
CRIC_SDK_MAIN_OSSPI = 'RIC-Mainline-cRIC-SDK'
CRIC_RAPP_ES_MAIN_OSSPI = 'RIC-Mainline-cRIC-rApp-ES'
CRIC_RAPP_RAN_KPI_MAIN_OSSPI = 'RIC-Mainline-cRIC-rApp-RAN-KPI'
DRIC_MAIN_OSSPI = 'RIC-Mainline-dRIC'
DRIC_SDK_MAIN_OSSPI = 'RIC-Mainline-dRIC-SDK'
DRIC_SDK_MPP_MAIN_OSSPI = 'RIC-Mainline-dRIC-SDK-MPP'
DRIC_XAPP_VONR_MAIN_OSSPI = 'RIC-Mainline-dRIC-xApp-VoNR'
RMS_MAIN_OSSPI = 'RIC-Mainline-RMS'
RIC_INSTALLER_2_1_0_OSSPI = 'RIC-Release-2.1.0-RIC-Installer'
CRIC_2_1_0_OSSPI = 'RIC-Release-2.1.0-cRIC'
CRIC_SDK_2_1_0_OSSPI = 'RIC-Release-2.1.0-cRIC-SDK'
CRIC_RAPP_ES_2_1_0_OSSPI = 'RIC-Release-2.1.0-cRIC-rApp-ES'
CRIC_RAPP_RAN_KPI_2_1_0_OSSPI = 'RIC-Release-2.1.0-cRIC-rApp-RAN-KPI'
DRIC_2_1_0_OSSPI = 'RIC-Release-2.1.0-dRIC'
DRIC_SDK_2_1_0_OSSPI = 'RIC-Release-2.1.0-dRIC-SDK'
DRIC_SDK_MPP_2_1_0_OSSPI = 'RIC-Release-2.1.0-dRIC-SDK-MPP'
DRIC_XAPP_VONR_2_1_0_OSSPI = 'RIC-Release-2.1.0-dRIC-xApp-VoNR'
RMS_2_1_0_OSSPI = 'RIC-Release-2.1.0-RMS'
RIC_INSTALLER_2_0_4_OSSPI = 'RIC-Release-2.0.4-RIC-Installer'
CRIC_2_0_4_OSSPI = 'RIC-Release-2.0.4-cRIC'
CRIC_SDK_2_0_4_OSSPI = 'RIC-Release-2.0.4-cRIC-SDK'
CRIC_RAPP_ES_2_0_4_OSSPI = 'RIC-Release-2.0.4-cRIC-rApp-ES'
CRIC_RAPP_RAN_KPI_2_0_4_OSSPI = 'RIC-Release-2.0.4-cRIC-rApp-RAN-KPI'
DRIC_2_0_4_OSSPI = 'RIC-Release-2.0.4-dRIC'
DRIC_SDK_2_0_4_OSSPI = 'RIC-Release-2.0.4-dRIC-SDK'
DRIC_SDK_MPP_2_0_4_OSSPI = 'RIC-Release-2.0.4-dRIC-SDK-MPP'
DRIC_XAPP_VONR_2_0_4_OSSPI = 'RIC-Release-2.0.4-dRIC-xApp-VoNR'
RMS_2_0_4_OSSPI = 'RIC-Release-2.0.4-RMS'
RIC_INSTALLER_2_0_3_OSSPI = 'RIC-Release-2.0.3-RIC-Installer'
CRIC_2_0_3_OSSPI = 'RIC-Release-2.0.3-cRIC'
CRIC_SDK_2_0_3_OSSPI = 'RIC-Release-2.0.3-cRIC-SDK'
CRIC_RAPP_ES_2_0_3_OSSPI = 'RIC-Release-2.0.3-cRIC-rApp-ES'
CRIC_RAPP_RAN_KPI_2_0_3_OSSPI = 'RIC-Release-2.0.3-cRIC-rApp-RAN-KPI'
DRIC_2_0_3_OSSPI = 'RIC-Release-2.0.3-dRIC'
DRIC_SDK_2_0_3_OSSPI = 'RIC-Release-2.0.3-dRIC-SDK'
DRIC_SDK_MPP_2_0_3_OSSPI = 'RIC-Release-2.0.3-dRIC-SDK-MPP'
DRIC_XAPP_VONR_2_0_3_OSSPI = 'RIC-Release-2.0.3-dRIC-xApp-VoNR'
RMS_2_0_3_OSSPI = 'RIC-Release-2.0.3-RMS'
UHANA_MAIN_OSSPI = 'Uhana-Mainline'
UHANA_0_52_4_OSSPI = 'Uhana-Release-0.52.4'
UHANA_0_52_3_OSSPI = 'Uhana-Release-0.52.3'
UHANA_0_52_2_OSSPI = 'Uhana-Release-0.52.2'
UHANA_0_52_1_OSSPI = 'Uhana-Release-0.52.1'
UHANA_0_52_0_OSSPI = 'Uhana-Release-0.52.0'
# Note: List released version in descending order (newer on top), below the
#       mainline version, for faster scanning of the list.
OSSPI_PROJECTS = {
    TCX: (TCX_MAIN_OSSPI,),
    TPS: (TPS_MAIN_OSSPI,),
    TCX_DEPLOYMENT_CONTAINER: (TCX_DEPLOYMENT_CONTAINER_MAIN_OSSPI,),
    TCX_K8S_INSTALLER: (
        TCX_K8S_INSTALLER_MAIN_OSSPI,
        TCX_K8S_INSTALLER_2_3_X_OSSPI,
        TCX_K8S_INSTALLER_2_1_X_OSSPI,
        TCX_K8S_INSTALLER_2_0_X_OSSPI,
        TCX_K8S_INSTALLER_1_0_0_OSSPI,
    ),
    TCA: (TCA_MAIN_OSSPI,),
    TCSA: (
        TCSA_MAIN_OSSPI,
        TCSA_2_4_0_OSSPI,
        TCSA_2_3_1_OSSPI,
        TCSA_2_3_0_OSSPI,
        TCSA_2_2_0_OSSPI,
        TCSA_2_1_0_OSSPI,
    ),
    RIC_INSTALLER: (
        RIC_INSTALLER_MAIN_OSSPI,
        RIC_INSTALLER_2_1_0_OSSPI,
        RIC_INSTALLER_2_0_4_OSSPI,
        RIC_INSTALLER_2_0_3_OSSPI,
    ),
    CRIC: (
        CRIC_MAIN_OSSPI,
        CRIC_2_1_0_OSSPI,
        CRIC_2_0_4_OSSPI,
        CRIC_2_0_3_OSSPI,
    ),
    CRIC_SDK: (
        CRIC_SDK_MAIN_OSSPI,
        CRIC_SDK_2_1_0_OSSPI,
        CRIC_SDK_2_0_4_OSSPI,
        CRIC_SDK_2_0_3_OSSPI,
    ),
    CRIC_RAPP_ES: (
        CRIC_RAPP_ES_MAIN_OSSPI,
        CRIC_RAPP_ES_2_1_0_OSSPI,
        CRIC_RAPP_ES_2_0_4_OSSPI,
        CRIC_RAPP_ES_2_0_3_OSSPI,
    ),
    CRIC_RAPP_RAN_KPI: (
        CRIC_RAPP_RAN_KPI_MAIN_OSSPI,
        CRIC_RAPP_RAN_KPI_2_1_0_OSSPI,
        CRIC_RAPP_RAN_KPI_2_0_4_OSSPI,
        CRIC_RAPP_RAN_KPI_2_0_3_OSSPI,
    ),
    DRIC: (
        DRIC_MAIN_OSSPI,
        DRIC_2_1_0_OSSPI,
        DRIC_2_0_4_OSSPI,
        DRIC_2_0_3_OSSPI,
    ),
    DRIC_SDK: (
        DRIC_SDK_MAIN_OSSPI,
        DRIC_SDK_2_1_0_OSSPI,
        DRIC_SDK_2_0_4_OSSPI,
        DRIC_SDK_2_0_3_OSSPI,
    ),
    DRIC_SDK_MPP: (
        DRIC_SDK_MPP_MAIN_OSSPI,
        DRIC_SDK_MPP_2_1_0_OSSPI,
        DRIC_SDK_MPP_2_0_4_OSSPI,
        DRIC_SDK_MPP_2_0_3_OSSPI,
    ),
    DRIC_XAPP_VONR: (
        DRIC_XAPP_VONR_MAIN_OSSPI,
        DRIC_XAPP_VONR_2_1_0_OSSPI,
        DRIC_XAPP_VONR_2_0_4_OSSPI,
        DRIC_XAPP_VONR_2_0_3_OSSPI,
    ),
    RMS: (
        RMS_MAIN_OSSPI,
        RMS_2_1_0_OSSPI,
        RMS_2_0_4_OSSPI,
        RMS_2_0_3_OSSPI,
    ),
    UHANA: (
        UHANA_MAIN_OSSPI,
        UHANA_0_52_4_OSSPI,
        UHANA_0_52_3_OSSPI,
        UHANA_0_52_2_OSSPI,
        UHANA_0_52_1_OSSPI,
        UHANA_0_52_0_OSSPI,
    ),
}
ALL_OSSPI_PROJECTS = [i for v in OSSPI_PROJECTS.values() for i in v]
# OSSPI Package `blackduck_paths` RegEx patterns.
# The `blackduck_paths` is `#`-delimited string, with the following component
# groups:
#   * Top level package zipped tar filename.
#   * Zero or one imgpkg-bundle tar (Service) filename.
#   * Zero or one layer-hash.
#   * Zero or more of interim paths (may be Container Image Layer and/or
#     (sub-)archive in the Container FS), followed by full path of detected
#     file.
# We are capturing some information from the `blackduck_paths` using RegEx:
#   * Package `version` and `build` no. from the 1st component.
#   * The `service_name` either from the 2nd or 4th (via layer-hash mapping).
#   * The `image_name` either from the 3rd or 4th (via layer-hash mapping).
#   * The layer-hash, if any, from 4th component, to be used to obtain
#   * `service_name` and/or `image_name` via layer-hash mapping.
#   * The `file_path` from the 4th component. If the detected file is inside
#     an archive, it will contain `#`-delimited string.
# Due to the `blackduck_paths` a totally free pattern, it is not easy (if not
# even impossible) sometimes to come up with RegEx pattern that is reliable.
# For ex. if there are 2 possible sequence between pattern `A`, `B`, `C` & `D`:
#   * A_B
#   * C_D
# The possibility to come up with RegEx pattern like r'(A|C)_(B|D)', in such
# that if pattern `A` is captured then it is guaranteed pattern `B` is also
# captured, can be extremely challenging, if not even impossible on certain
# cases. There is possibility that when pattern `A` is captured, inadvertently
# the pattern `D` is getting captured instead.
# Since human mind is easier to follow thing like decition tree, it is much
# easier to come up with RegEx pattern r'(A)_(B)|(C)_(D)' instead. But this
# means the no. of groups captured may vary.
# The RegEx pattern in here should be design in such that:
#   * Package `version` is captured by `match.group(1)`.
#   * Package `build` no. is capture by `match.group(2)`.
#   * The `service_name`, `image_name`, layer-hash, and `file_path` is captured
#     by the rest of `match.group()`, so filter out the `None`. However it is
#     possible that the `service_name`, `image_name`, and/or layer-hash, can
#     not be retrieved, i.e. we are forced to use `r'()'` pattern, hence will
#     have value `''`. So in this case we may need to use `MAPPER.svcName` of
#     the appropriate product, with `''` as `key `. In some cases, if the
#     layer-hash can not be retrieved, it may be desired to make it identical
#     with either `service_name` and/or `image_name`, i.e. use `r'((...))'`
#     pattern.
#     NOTE: If layer-hash can be retrieved and the layer-hash mapping data is
#           available, then it is preferred to get the `service_name` via this
#           mapping, so `image_name` information can also be derived.
# NOTE:
#   When OVA (Open Virtual Appliance) file is scanned, the last element of
#   `blackduck_paths` contains the OVA file name itself.
#       ...
#       "blackduck_paths": [
#           "ovaContainerFile#filesInsideOVA...",
#           ...
#           "ovaContainerFile"
#       ],
#       ...
#       To avoid warning non-matching warning printout on the
#       `ovaContainerFile`:
#       XXX:
#           '(?:)'
#           #   OVA File - Inner OVA.
#           #   Product-Name-0.0.0-000000.ova#
#           ''  r'Product-Name-([\d.]+)-(\d+)[^#]+#'
#           ...
#           '|'
#           #   OVA File - Container.
#           #   Product-Name-0.0.0-000000.ova
#           ''  r'[^#]+?\.ova'
#           ')',
# pylint: disable=line-too-long
BLACKDUCK_PATH_RE = {
    TCX:
        # Local scan of OSSPI CLI Scanner Audit Report.
        # NOTE:
        #   The below information is inserted by `osspi_scan()` during local
        #   scan.
        # tcx-services-3.8.0-2607#
        #   tcx-strimzi-kafka-operator%3.1.1-2486#
        #   tcx-docker-local.usw1.packages.broadcom.com/{release,snapshot,tcxtest}/images/
        #     operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#
        #   operator#
        r'(?:.*?)-([\d.]+)-(\d+)#'
        r'([^%]*)%(?:[^#]+)#'
        r'(?:[^#]+#){2}()'
        # 0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#
        r'([0-9a-f]{64})#'
        # /opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar
        r'(.+)',
    TPS:
        # Local scan of OSSPI CLI Scanner Audit Report.
        # NOTE:
        #   The below information is inserted by `osspi_scan()` during local
        #   scan.
        # tcx-platform-services-3.8.0-2607#
        #   tcx-strimzi-kafka-operator%3.1.1-2486#
        #   tcx-docker-local.usw1.packages.broadcom.com/{release,snapshot,tcxtest}/images/
        #     operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#
        #   operator#
        r'(?:.*?)-([\d.]+)-(\d+)#'
        r'([^%]*)%(?:[^#]+)#'
        r'(?:[^#]+#){2}()'
        # 0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#
        r'([0-9a-f]{64})#'
        # /opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar
        r'(.+)',
    TCX_DEPLOYMENT_CONTAINER:
        # Local scan of OSSPI CLI Scanner Audit Report.
        # NOTE:
        #   The below information is inserted by `osspi_scan()` during local
        #   scan.
        # tcx-docker-local.usw1.packages.broadcom.com
        #   release/images/deployment%2.4.2-451#
        #   deployment%2.4.2-451#
        # tcx-docker-local.usw1.packages.broadcom.com/
        #   snapshots/images/deployment%TCX-5302-2.4.2-SNAPSHOT-13#
        #   deployment%TCX-5302-2.4.2-SNAPSHOT-13#
        r'(?:[^%]*)%(?:.+-)??([\d.]+)(?:-[^-]+)?-(\d+)#'
        r'()([^#]+)#'
        # 63118abbc74650e8ed1192edb2c2c1837ec39c320fecd5d931503a042c641af2#
        r'([0-9a-f]{64})#'
        # /usr/lib/python3.11/site-packages/pip/_vendor/packaging/
        r'(.+)',
    TCX_K8S_INSTALLER:
        # VMware-K8s-Installer-1.0.0-92.tar.gz#
        r'VMware-K8s-Installer-([\d.]+)-(\d+)[^#]+#'
        '(?:'
        #   Variant 1
        #   k8s-installer/cluster/pkg/infra/
        ''  r'(?:[^/#]+/)+pkg/([^/]+)(())/'
        #   kubelet
        #   cni-plugins-linux-amd64-v0.9.1.tgz#bandwidth
        #   etcd-v3.5.0-linux-amd64.tar.gz#etcd-v3.5.0-linux-amd64/etcd
        ''  r'(?:.+#)?([^#]+)'
        '|'
        #   Variant 2
        #   k8s-installer/cluster/docker/infra/docker-k8s-dns-node-cache_1.17.1.tar.gz#
        #   k8s-installer/cluster/docker/infra/doc65335473ker-postgresql_11.15.0-photon-3-r14.tar.gz#
        #   k8s-installer/cluster/docker/infra/docker-kube-controllers_v3.19.2.tar.gz
        #   k8s-installer/cluster/docker/infra/node-v3.25.1.tar.gz#
        #   k8s-installer/cluster/docker/infra/harbor-core-2.8.2-photon-3-r55.tar.gz#
        ''  r'(?:[^/#]+/)+()([^#]+?)[_-]v?[\d.]+[^#]+#'
        #   3afdf90870c0700d48a0cb32f14380ab1f935c21a6fc430f2aeadd15479e7528/layer.tar#
        ''  r'([0-9a-f]{64})/layer\.tar#'
        #   usr/lib/x86_64-linux-gnu/libtasn1.so.6.5.5
        ''  r'(.+)'
        ')',
    TCA:
        '(?:'
        #   OVA File - Inner OVA.
        #   VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#
        ''  r'VMware-Telco-Cloud-Automation-([\d.]+)-(\d+)[^#]+#'
        ''  '(?:'
        #       Variant 1
        #       VMware-Telco-Cloud-Automation-3.1.0-23448769-disk1.vmdk#
        ''      r'.+?-disk1\.vmdk#'
        ''      '(?:'
        #           Variant 1.1
        #           partition-2/initrd.img-5.10.201-1.ph4#
        ''          r'()(([^#]+))#'
        ''      '|'
        #           Variant 1.2
        ''          r'((()))'
        ''      ')'
        ''  '|'
        #       Variant 2
        #       VMware-Telco-Cloud-Automation-3.1.0-23448769-disk3.vmdk#
        ''      r'.+?-disk3\.vmdk#'
        ''      '(?:'
        #           Variant 2.1
        #           containerd/data/
        #             io.containerd.snapshotter.v1.overlayfs/
        #             snapshots/132/fs/
        ''          r'(containerd)/data/'
        ''          r'io\.containerd\.((snapshotter))\.v1\.overlayfs/'
        ''          r'(?:[^/]+/){3}'
        ''      '|'
        #           Variant 2.2
        #           containerd/data/io.containerd.content.v1.content/blobs/
        #             sha256/5b39652bbe70f6c8b54ebbf80f30085c802973cf84acce236d68daa37c19fa3c#
        #           opt/vmware/registry/docker/registry/v2/blobs/
        #             sha256/fe/fea43f71b0b0e24e9f10fc13902b90f6640005a677f28cd0d0c8f3cc617c2537/data#
        ''          r'(?:containerd|opt/vmware/registry)/(?:[^/]+/)+blobs/'
        ''          r'sha256(?:/[^/]{2})?/()(([0-9a-f]{64}))(?:/data)?#'
        ''      ')'
        ''  ')'
        #   Variant 1
        #       Variant 1.1
        #           usr/lib/liblzma.so.5.2.5
        #       Variant 1.2
        #           opt/vmware/lib/libz.so
        #           etc/vmware/cap/capengine/support/ph4-UpdateDepRpms.tar.gz#zchunk-libs-1.1.7-2.ph4.x86_64.rpm#usr/lib/libzck.so.1.1.7
        #   Variant 2
        #       Variant 2.1
        #           lib/libz.so.1.2.13
        #           root/.cache/pip/http-v2/3/b/d/5/3/3bd53b300a0bc174e69474ff28b696ba271b5dd4cd2ae328c0a8ba92.body#urllib3/__init__.py
        #       Variant 2.2
        #           opt/cruise-control/libs/zookeeper-3.6.3.jar#org/apache/zookeeper
        #           lib/x86_64-linux-gnu/libz.so.1.2.11
        ''  r'(.+)'
        '|'
        #   OVA File - Container.
        #   publish/cap-builder/ova/VMware-Telco-Cloud-Automation-3.0.0-21758171.ova
        ''  r'[^#]+?\.ova'
        ')',
    TCSA:
        # VMware-TCOps-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#
        # VMware-TCSA-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#
        # VMware-TCSA-Deployer-2.1.0-10.tar.gz#
        r'VMware-(?:(?:TCOps)|(?:TCSA))-Deployer-'
        r'((?:develop-)?[\d.]+)(?:-SNAPSHOT)?-(\d+)[^#]+#'
        '(?:'
        #   Variant 1
        #   tcx-deployer/clis/
        ''  r'(?:[^/#]+/)+([^/#]+)(())/'
        #   tcxctl
        ''  r'([^#]+)'
        '|'
        #   Variant 2
        #   tcx-deployer/images/kafka.tar#
        #   tcx-deployer/imgpkg/services/istio_3.0.0-304.tar#
        #   tcx-deployer/imgpkg/services/collector-manager_latest.tar#
        ''  r'(?:[^/#]+/)+([^#]+?)(?:(?:_(?:[\d.]+-\d+|latest))?\.tar)?()#'
        #   sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#
        ''  r'sha256-([0-9a-f]{64})\.tar\.gz#'
        #     usr/bin/ncat
        ''  r'(.+)'
        ')',
    RIC_INSTALLER:
        # vmware-ric-installer-0.0.0_62851256.tar.gz#
        r'vmware-ric-installer-([\d.]+)_(\d+)[^#]+#'
        # installer/installer.tar#
        r'(?:[^/#]+/)+()(.+?)\.tar#'
        # fd8ced994c330a1dd02bc54ccc32b06617513bb713d5ccb440eb1240787a9beb/layer.tar#
        r'([0-9a-f]{64})/layer\.tar#'
        # usr/bin/vim
        r'(.+)',
    CRIC:
        # vmware-cric-bundle-0.0.0_62810041.tar.gz#
        r'vmware-cric-bundle-([\d.]+)_(\d+)[^#]+#'
        # imgpkgs/hoggerflink_0.0.0_62810041.tar#
        # imgpkgs/istio-custom_0.0.0_62810041.tar#
        # devkit/devkit.tgz#rapp-devkit/cric/docker/devkitrunner.tar#
        r'(?:[^#]+\.tgz#)?(?:[^/#]+/)+([^#]+?)(?:(?:-custom)?_[\d.]+_\d+)?'
        r'\.tar()#'
        # sha256-ceb46a86f1aab78c6dab7a6e7c9eb0e7485aea933427c1a46805830bc2497f48.tar.gz#
        # 92ab736eee018f3ec14a77003a6a687997ff546ac5f9eb008ea7e06bba9ea892/layer.tar#
        r'(?:sha256-)?([0-9a-f]{64})(?:\.tar\.gz|/layer\.tar)#'
        # usr/bin/lua
        r'(.+)',
    CRIC_SDK:
        # vmware-cric-sdk-0.0.0_63756515.tar.gz#
        r'vmware-cric-sdk-([\d.]+)_(\d+)[^#]+#'
        # devkit/devkit.tgz#rapp-devkit/cric/docker/devkitrunner.tar#
        # cric/docker/devkitrunner.tar#
        r'(?:[^#]+\.tgz#)?(?:[^/#]+/)+()(.+?)\.tar#'
        # 3b653e99282c4c625654230e88f93fc6171637caa7abc4f27745ee1d4aa593e5/layer.tar#
        r'([0-9a-f]{64})/layer\.tar#'
        # bootstrapper
        r'(.+)',
    CRIC_RAPP_ES:
        # vmware-energy-saving-bundle-0.0.0_64327753.tar.gz#
        r'vmware-energy-saving-bundle-([\d.]+)_(\d+)[^#]+#'
        # imgpkgs/energy-saving_0.0.0_64327753.tar#
        r'(?:[^/#]+/)+([^#]+?)(?:_[\d.]+_\d+)?\.tar()#'
        # sha256-791e6f6c30629e8cc0e6b708c86ad7f9734005bb1ca5be4016691d340f2005d7.tar.gz#
        r'sha256-([0-9a-f]{64})\.tar\.gz#'
        # usr/bin/lua
        r'(.+)',
    CRIC_RAPP_RAN_KPI:
        # vmware-ran-kpi-bundle-0.0.0_64327753.tar.gz#
        r'vmware-ran-kpi-bundle-([\d.]+)_(\d+)[^#]+#'
        # imgpkgs/ran-kpi_0.0.0_64327753.tar#
        r'(?:[^/#]+/)+([^#]+?)(?:_[\d.]+_\d+)?\.tar()#'
        # sha256-ee433f69a9e58dceae7b9ba096c3cc0192b2ba2d10188b5d268f14ed38f2341a.tar.gz#
        r'sha256-([0-9a-f]{64})\.tar\.gz#'
        # ran-kpi
        r'(.+)',
    DRIC:
        # vmware-dric-bundle-0.0.0_64327750.tar.gz#
        r'vmware-dric-bundle-([\d.]+)_(\d+)[^#]+#'
        # imgpkgs/dric_0.0.0_64327750.tar#
        # imgpkgs/cert-manager-custom_0.0.0_64327750.tar#
        r'(?:[^/#]+/)+([^#]+?)(?:(?:-custom)?_[\d.]+_\d+)?\.tar()#'
        # sha256-0286978b7af7a7f77a5f1e1cb36ff6d7e7eda08bfc9e3733a550caf7577d4d03.tar.gz#
        r'sha256-([0-9a-f]{64})\.tar\.gz#'
        # usr/bin/wget
        r'(.+)',
    DRIC_SDK:
        # vmware-dric-sdk-0.0.0_64327748.tar.gz#
        r'vmware-dric-sdk-([\d.]+)_(\d+)[^#]+#'
        # sdk/third_party/com_github_cares_cares.a
        r'([^/]+)(())/[^/]+/(.+)',
    DRIC_SDK_MPP:
        # vmware-dric-sdk-mpp-0.0.0_64327748.tar.gz#
        r'vmware-dric-sdk-mpp-([\d.]+)_(\d+)[^#]+#'
        # sdk/third_party/com_github_redis_hiredis.a
        r'([^/]+)(())/[^/]+/(.+)',
    DRIC_XAPP_VONR:
        # vmware-xapp-vonr-bundle-0.0.0_64327750.tar.gz#
        r'vmware-xapp-vonr-bundle-([\d.]+)_(\d+)[^#]+#'
        # imgpkgs/xapp-vonr_0.0.0_64327750.tar#
        r'(?:[^/#]+/)+([^#]+?)(?:_[\d.]+_\d+)?\.tar()#'
        # sha256-7846449c5eddebd867bcb7538162469a7605115a253495592e586ee77cfc65af.tar.gz#
        r'sha256-([0-9a-f]{64})\.tar\.gz#'
        # usr/bin/systemd-analyze
        r'(.+)',
    RMS:
        # vmware-rms-bundle-0.0.0_62855608.tar.gz#
        r'vmware-rms-bundle-([\d.]+)_(\d+)[^#]+#'
        # imgpkgs/es-operator_0.0.0_62855608.tar#
        # imgpkgs/logstash-custom_0.0.0_62855608.tar#
        r'(?:[^/#]+/)+([^#]+?)(?:(?:-custom)?_[\d.]+_\d+)?\.tar()#'
        # sha256-6b44875008a92252fdfd13c6c2e6462cae456cf114dbe26e465df97f6a5280af.tar.gz#
        r'sha256-([0-9a-f]{64})\.tar\.gz#'
        # usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/rack-2.2.3/rack.gemspec
        r'(.+)',
    UHANA:
        # uhana-bundle-65335473.tar.gz#
        r'uhana-bundle-()(\d+)\.[^#]+#'
        '(?:'
        #   Variant 1
        #   docker/docker-ambassador-auth-service_2.0.0.tar.gz#
        #   docker/docker-collector_0.0.0+65335473.tar.gz#
        #   docker/docker-ambassador-auth-httpbasic_0.1.1_20240104.tar.gz##/
        #   docker/docker-curator_5.8.1.tar.gz#
        #   docker/docker-minideb_stretch.tar.gz#
        #   cluster/cluster-bundle-65312685.tar.gz#
        #     docker/infra/docker-hadoop-datanode_2.7.2.tar.gz#
        ''  r'(?:cluster/[^#]+#)?'
        ''  r'(?:[^/#]+/)+()docker-([^#]+?)_(?:[-+_\d.]+|[^.]+)[^#]+#(?:#/)?'
        #   ambassador-auth-service_2.0.0.tar#
        #     8965d0b1e10d1036675c35bd8ea3aa0a23ebb9819a9aa956a1e2d69a298ec735/layer.tar#
        #     lib/libz.so.1.2.11
        #   docker/collector.tar#
        #     5c173a4c0563d369b9e1644f663bc22015b5efa438fb5520e61b6625515c1fde/layer.tar#
        #     ctrserver/src/java/io/uhana/collector/collector_5g_main_deploy.jar#
        #     org/apache
        #   docker/docker-ambassador-auth-httpbasic_0.1.1_20240104.tar#
        #     1ebf16d2458dca0e2e94520a563b1c9713315ad65c79194f814e906f63f4397f/layer.tar#
        #     usr/local/lib/python3.6/distutils/command/wininst-6.0.exe
        #   uhana/uhana_piran/curator/docker/docker-curator_5.8.1.tar#
        #     1799dbbd3f3f5e4a2336866e06a2993d47a41883e104c362bb2a2ed54f75f4ae/layer.tar#
        #     curator/lib/distutils/command/wininst-6.0.exe
        #   tmp/piran/docker/docker-minideb_stretch.tar#
        #     ccac04f8f22ac16316615f5c2c5ecac2bb1aec6254424a3c9c35ecef95df3bb0/layer.tar#
        #     lib/x86_64-linux-gnu/libz.so.1.2.8
        #   82abc25ad9cb20adadf08c9376364676812d1baeeacb2ae8c0e1c445c2c98a35/layer.tar#
        #     opt/hadoop-2.7.2/share/hadoop/yarn/lib/zookeeper-3.4.6-tests.jar
        ''  r'(?:[^#]+#)?([0-9a-f]{64})/layer\.tar#(.+)'
        '|'
        #     Variant 2
        #     cluster/cluster-bundle-65312685.tar.gz#
        #       pkg/infra/cni-plugins-linux-amd64-v0.8.5.tgz#
        #     cluster/cluster-bundle-65312685.tar.gz#
        #       pkg/infra/
        ''  r'(cluster)/[^#]+#((pkg/infra/(?:[^#]+)??))(?:-v[\d.]+[^#]+#)?'
        #     bandwidth
        #     kubelet
        ''  r'([^#]+)'
        '|'
        #   Variant 3
        #   installer/k8s-launcher.tar.gz#
        ''  r'(installer)/(([^.]+))[^#]+#'
        #   j2skaffold.zip#runfiles/third_party_py_deps/pypi__pyyaml/yaml/__init__.py
        ''  r'(.+)'
        ')',
}
# pylint: enable=line-too-long
MAPPER = namedtuple('MAPPER', 'svcName getSvcAndCtrImgNameFunc')(
    {
        TCA: {
            '': 'UNKNOWN',
        },
    },
    # The `getSvcAndCtrImgNameFunc` is the name of this module level function
    # that has the following signature:
    #   @static_func_vars([map={}])
    #   def _get_svc_and_ctr_img_name<[__XXX]>(
    #       self, cmd_args, def_svc_name, def_img_name, *args, **kwargs,
    #   ):
    #       '''_get_svc_and_ctr_img_name<[__XXX]> returns Service Name and
    #       Container Image Names from the given data.
    #
    #       Args:
    #           self (func):    Self ref. (easy access to static func. var.).
    #           cmd_args (argparse.Namespace):  Command line arguments.
    #               The attributes of interest:
    #                   layer_map (str):    File (YAML) containing Layer
    #                                       Mapping data.
    #           def_svc_name (str):    Default Service Name to use the function
    #                                       failed to construct the proper
    #                                       name.
    #           def_img_name (str):    Default Container Image Name to use if
    #                                       the function failed to construct
    #                                       the proper name.
    #           *args:      Any pos. parameters required by this function.
    #               Position order:
    #                   img_lyr_hash (str): Image Layer Hash string.
    #           **kwargs:   Any keyword parameters required by this function.
    #               Mapping:
    #                   <attrName> (<type>):    <attrDesc>.
    #       Returns:
    #           (tuple): A `((ctrImgNameTag, [svcNameTag]),)` tuple.
    #               Where:
    #                   ctrImgNameTag (tuple):
    #                       A `(ctrImgName, ctrImgTag)` tuple.
    #                       Where:
    #                           ctrImgName (str):   Container Image Name.
    #                           ctrImgTag (str):    Container Image Tag `{'' |
    #                                               ':...' | '@sha256:...'}`.
    #                   svcNameTag (tuple):
    #                       A `(svcName, svcTag)` tuple.
    #                       Where:
    #                           svcName (str):  Service Name.
    #                           svcTag (str):   Container Image Tag `{'' |
    #                                           ':...' | '@sha256:...'}`.
    #               Note:   When there is no match, it should return
    #                       `((('def_img_name', ''), [(def_svc_name, '')]),)`.
    #       '''
    {
        TCA: '_get_svc_and_ctr_img_name__img_lyr_sha_2_map',
        TCSA: '_get_svc_and_ctr_img_name__img_lyr_sha_2_map',
        TCX_DEPLOYMENT_CONTAINER: '_get_svc_and_ctr_img_name__percent_sep',
    },
)
# Impact Summary
KNOWN_VULN_IMPACT_SUMMARY = '''\
impact:
    summary:
        FalsePositive: False Positive
        LowImpact: Low Impact
        NoImpact: No Impact
        NotExploitable: Not Exploitable
        ReAnalyzed_NIST: Being re-analyzed by NIST
'''
# Confluence Publishing
CONFLUENCE_API_BASE_URL = 'https://confluence.eng.vmware.com/rest/api'
# Jira Ticket Creation
JIRA_BASE_URL = 'https://jira.eng.vmware.com'
JIRA_PID = {
    TCX: 0,
    TPS: 0,
    TCX_DEPLOYMENT_CONTAINER: 36719,
    TCX_K8S_INSTALLER: 36719,
    TCA: 30010,
    TCSA: 36719,
    RIC_INSTALLER: 44410,
    CRIC: 40411,
    CRIC_SDK: 40411,
    CRIC_RAPP_ES: 40411,
    CRIC_RAPP_RAN_KPI: 40411,
    DRIC: 40611,
    DRIC_SDK: 40611,
    DRIC_SDK_MPP: 40611,
    DRIC_XAPP_VONR: 40611,
    RMS: 44410,
    UHANA: 28514,
}
JIRA_EXTRAS = {
    TCX: '',
    TPS: '',
    TCX_DEPLOYMENT_CONTAINER: '',
    TCX_K8S_INSTALLER: '&customfield_21832=24309',      # Customer Bug = No
    TCA: '',
    TCSA: '&customfield_21832=24309',                   # Customer Bug = No
    RIC_INSTALLER: '',
    CRIC: '',
    CRIC_SDK: '',
    CRIC_RAPP_ES: '',
    CRIC_RAPP_RAN_KPI: '',
    DRIC: '',
    DRIC_SDK: '',
    DRIC_SDK_MPP: '',
    DRIC_XAPP_VONR: '',
    RMS: '',
    UHANA: '',
}

# Allowed summary statements for known vulnerability records.
IMPACT_SUMMARIES = [
    'False positive',
    'No impact',
    'Low impact',
    'Being re-analyzed by NIST',
]


# Product configuration data.
PROD_CFG = {}


@dataclasses.dataclass
class KnownVulnerability:
    '''Class for keeping track of a known vulnerability record.'''
    service_name: str
    image_name: str
    package_name: str
    cve: str
    impact_summary: str = ""
    impact_analysis: str = ""
    custom: dict = dataclasses.field(default_factory=lambda: {})


# pylint: disable=too-many-instance-attributes
@dataclasses.dataclass
class OsspiVulnerability:
    '''Class for keeping track of OSSPI vulnerabiltiy record.'''
    build_num: int
    service_name: str
    image_name: str
    package_name: str
    cvssv3: float
    cve: str
    cve_link: str
    cve_desc: str
    file_paths: str


def cmd_install_osspi(args, **kwargs):
    '''cmd_install_osspi runs the OSSPI scan tool installer from the
    given path. Local installers and via http(s) are supported.
    '''
    _ = kwargs
    if not args.installer:
        return
    cmd = args.installer
    shell = None
    if cmd.startswith('http'):
        cmd = f'eval "$(curl -fsSL \'{cmd}\' || echo false)"'
        shell = '/usr/bin/bash'
    logging.info(f"Install OSSPI scan tool: {cmd}")
    if args.dry_run:
        logging.debug("Dry Run: OSSPI scan tool install skipped")
    else:
        try:
            out = subprocess.check_output(cmd, shell=True, executable=shell)
        except subprocess.CalledProcessError as exc:
            logging.error("OSSPI tool install failed")
            logging.debug(f"{exc.stdout.decode()}")
            sys.exit(exc.returncode)
        logging.debug(f"OSSPI tool installed:\n{out.decode()}")


def cmd_get_build_url(args, **kwargs):
    '''cmd_get_build_url gets the build URL for a product.'''
    _ = kwargs
    get_build_url(args)


def cmd_get_osspi_scan(args, **kwargs):
    '''cmd_get_osspi_scan fetch the result of OSSPI scan.'''
    _ = kwargs
    audit_id = args.audit_id
    packages = {}
    if not audit_id:
        logging.info("OSSPI fetching latest successful audit ID for "
                     f"project: {args.project}")
        audit_id = osspi_fetch_latest_success_audit_id(args)
    logging.info("OSSPI fetching packages vulnerabilities for audit ID: "
                 f"{audit_id}")
    if args.dry_run:
        logging.debug("Dry Run: fetching packages vulnerabiltiies skipped")
    else:
        packages = osspi_fetch_vulnerable_packages(args, audit_id)
        with open(args.output, 'w') as file:
            json.dump(packages, file, indent=4)


def cmd_osspi_scan(args, **kwargs):
    '''cmd_osspi_scan requests OSSPI scan of the given artifact'''
    _ = kwargs
    try:
        osspi_scan(args)
    except subprocess.CalledProcessError as exc:
        logging.error("OSSPI scan failed")
        if exc.stdout is not None:
            logging.debug(f"{exc.stdout.decode()}")
        sys.exit(exc.returncode)


def cmd_dev_report(args):
    '''cmd_dev_report reads an audit result from JSON file, merges it with
    known vulnerabilities data, and publishes the resulting Release audit
    report.
    '''
    known_vuln = {}
    if args.known_vulnerabilities:
        known_vuln = load_known_vulnerabilities(args)
    merged_vuln = read_merge_audit_result(args, known_vuln=known_vuln)
    if args.output:
        if args.dry_run:
            logging.debug("Dry Run: Write developer vulnerability report: "
                          f"{args.output}")
        else:
            logging.info("Writing developer vulnerability report: "
                         f"{args.output}")
            write_dev_report_csv(args, merged_vuln)


def cmd_post_report(args, **kwargs):
    '''cmd_post_report posts a vulnerability report to a Confluence page as
    an attachment.
    '''
    _ = kwargs
    if args.dry_run:
        logging.debug("Dry Run: Publish report to Confluence: "
                      f"report={args.report}, "
                      f"page content id={args.page_id}, user={args.user}")
    else:
        logging.info("Posting vulnerability report to Confluence")
        post_report(args.report, args.page_id, args.user, args.password)


def cmd_rel_report(args):
    '''cmd_rel_report reads an audit result from JSON file, merges it with
    known vulnerabilities data, and publishes the resulting Release audit
    report.
    '''
    known_vuln = {}
    if args.known_vulnerabilities:
        known_vuln = load_known_vulnerabilities(args)
    merged_vuln = read_merge_audit_result(args, known_vuln=known_vuln)
    if args.output:
        if args.dry_run:
            logging.debug("Dry Run: Write release vulnerability report: "
                          f"{args.output}")
        else:
            logging.info("Writing release vulnerability report: "
                         f"{args.output}")
            write_rel_report_csv(args, merged_vuln)


def get_build_url(cmd_args):
    '''get_build_url gets the build URL for a product.
    Args:
        cmd_args (argparse.Namespace): Command line arguments.
            The attributes of interest:
                sub-product (str): Name of the sub-product (some product may
                    deliver several deliverable artifacts).
                release (str): Release ID of the product. If `None` it will be
                    set to main's release version.
                build_id (int): ID of the build to be scanned.
                product (str): Product name, to get the build URL.
    Returns:
        (int): OSSPI scan ID
    '''
    build_id = cmd_args.build_id

    if cmd_args.release is None:
        api_info = PRODUCT_BUILD_REPO.get(cmd_args.product, {}).get('release')
        if api_info:
            logging.debug('Getting latest release version for '
                          f'product={cmd_args.product}.')
            q_params = {**PRODUCT_ARTIFACTS[cmd_args.product]
                        [cmd_args.sub_product]}
            query = globals()[api_info['queryFunc']]
            f_params = api_info['queryFuncParams']
            cmd_args.release = query(
                api_info, q_params, cmd_args=cmd_args, **f_params)
        else:
            cmd_args.release = MAIN_VER

    if not build_id:
        build_id = get_latest_build_id(cmd_args)
    url = identify_build_url(cmd_args, build_id)
    logging.info(f"Identified build URL: {url}")

    return url


def get_latest_build_id(cmd_args):
    '''get_latest_build_id fetches the latest build ID for the product for the
    given release.

    Args:
        cmd_args (argparse.Namespace): Command line arguments.
            The attributes of interest:
                sub-product (str): Name of the sub-product (some product may
                    deliver several deliverable artifacts).
                release (str): Release ID of the product. If `None` it will be
                    set to main's release version.
                product (str): Product name, to get the build URL.
    Returns:
        (int): ID of the build.
    '''
    sub_product = cmd_args.sub_product
    release = cmd_args.release
    product = cmd_args.product
    logging.debug(f'Getting latest build ID for product={product}, '
                  f'release={release}.')
    if product in PRODUCT_BUILD_REPO:
        api_info = PRODUCT_BUILD_REPO[product]['build']
        q_params = {
            'relVer': release,
            **PRODUCT_ARTIFACTS[product][sub_product],
        }
        query = globals()[api_info['queryFunc']]
        f_params = api_info['queryFuncParams']
        build = query(api_info, q_params, cmd_args=cmd_args, **f_params)
        if build != -1:
            logging.debug(f'Latest build ID for product={product}, '
                          f'release={release}: {build}')
            return int(build)
        raise Exception('Failed to get latest build ID.')
    raise ValueError(f'Unknown product: {product}')


def identify_build_url(cmd_args, build_id):
    '''identify_build_url returns a URL path for a product build.

    Args:
        cmd_args (argparse.Namespace): Command line arguments.
            The attributes of interest:
                sub-product (str): Name of the sub-product (some product may
                    deliver several deliverable artifacts).
                release (str): Release ID of the product. If `None` it will be
                    set to main's release version.
                product (str): Product name, to get the build URL.
        build_id (int): ID of the build.
    Returns:
        (str): URL path for the product build.
    '''
    sub_product = cmd_args.sub_product
    release = cmd_args.release
    product = cmd_args.product
    logging.debug(
        f'Identifying build URL for product={product}, '
        f'release={release}, build={build_id}.'
    )
    if product in PRODUCT_BUILD_REPO:
        api_info = PRODUCT_BUILD_REPO[product]['repo']
        q_params = {
            'relVer': release,
            'buildNo': build_id,
            **PRODUCT_ARTIFACTS[product][sub_product],
        }
        query = globals()[api_info['queryFunc']]
        f_params = api_info['queryFuncParams']
        (url, auth) = query(api_info, q_params, cmd_args=cmd_args, **f_params)
        url_str = _url_exists(url, auth)
        if url_str:
            logging.debug(
                f'Identified build URL for product={product}, '
                f'release={release}, build={build_id}: {url.geturl()}'
            )
            return url.geturl()
        raise Exception(f'Build URL identification failed: {url.geturl()}')
    raise ValueError(f'Unknown product: {product}')


def load_known_vulnerabilities(cmd_args):
    '''load_known_vulnerabilities loads a collection of known vulnerabilities
    descriptions from JSON files or directories of JSON files and returns the
    loaded data.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                known_vulnerabilities (list):
                    List of `path` tuples of the files or directories
                    containing known vulnerabilities data.
                    Where:
                        path:   (jinja_context, json_file)
                            jinja_context:  None | str
                            json_file:      str
                                            If `jinja_context` is `str` then
                                            this is the jinja template.
                ignore_pkg_ver (bool):  Ignore package version in the Vuln.
                                        Report.
                sub_charted_sfx (str):
                    Sub-charted Service Name's suffix.
                use_other_sub_charted_svcs (str):
                    List (comma-delimited) of other sub-charted Service Name's
                    suffixes that their `known-vulnerabilities` information
                    will be used.
    Returns:
        (dict): Known vulnerabilities map of (service_name, image_name,
            package_name, cve) to KnownVulnerability record.
    '''
    # pylint: disable=too-many-statements
    json_paths = []
    jinja_paths = []
    vuln = {}

    def _func(file, vuln, jinja_context=None):
        # pylint: disable=too-many-branches
        try:
            with open(file) as handle:
                if jinja_context is None:
                    records = json.load(handle)
                else:
                    context = yaml.safe_load(KNOWN_VULN_IMPACT_SUMMARY)
                    if pathlib.Path(jinja_context).is_file():
                        user_context = yaml.safe_load(open(jinja_context))
                        if not isinstance(user_context, dict):
                            raise Exception('Jinja Context file (YAML) Top '
                                            'Level must be Map: '
                                            f'{jinja_context}')
                        utils.nested_update(context, user_context)
                        template = jinja2.Environment(
                            undefined=jinja2.StrictUndefined
                        ).from_string(handle.read())
                        records = json.loads(template.render(context))
                    else:
                        raise Exception('Invalid Jinja Context file: '
                                        f'{jinja_context}')
        except FileNotFoundError:
            logging.error(f"Known vulnerabilities file not found: {file}")
            raise
        except json.decoder.JSONDecodeError:
            logging.error(f"Known vulnerabilities file JSON error: {file}")
            raise
        for rec in records:
            if 'imgpkg' in rec:
                rec['service_name'] = rec['imgpkg']
                del rec['imgpkg']
            if 'image_name' not in rec:     # The `image_name` is optional.
                rec['image_name'] = ''
            if 'third_party_library' in rec:
                rec['package_name'] = rec['third_party_library']
                del rec['third_party_library']
            if 'cve_id' in rec:
                rec['cve'] = rec['cve_id']
                del rec['cve_id']
            if cmd_args.ignore_pkg_ver:
                rec['package_name'] = _drop_pkg_ver(rec['package_name'])
            for sc_name in (
                [cmd_args.sub_charted_sfx] +
                cmd_args.use_other_sub_charted_svcs.split(',')
            ):
                rec['service_name'] = rec['service_name'].removesuffix(sc_name)
            key = (rec['service_name'], rec['image_name'], rec['package_name'],
                   rec['cve'])
            if key in vuln:
                logging.warning("Duplicate vulnerability statement: "
                                f"{key}")
                continue
            primary = ['service_name', 'image_name', 'package_name', 'cve',
                       'impact_summary', 'impact_analysis']
            args = [rec[key] for key in primary]
            custom = {key: rec[key] for key in rec.keys()
                      if key not in primary}
            vuln[key] = KnownVulnerability(*args, custom=custom)

    for (jinja_context, json_file) in cmd_args.known_vulnerabilities:
        if jinja_context is None:
            json_paths.append(json_file)
        else:
            jinja_paths.append((jinja_context, [json_file]))

    if json_paths:
        _load_from_paths(json_paths, 'known vulnerabilities',
                         ('json', 'JSON'), (_func, (vuln,), {}))
    for (context, template) in jinja_paths:
        _load_from_paths(template, 'known vulnerabilities',
                         ('json-jinja', 'JSON with Jinja Templating'),
                         (_func, (vuln, context), {}))

    logging.debug(f"Loaded {len(vuln)} known vulnerability records")

    return vuln


def osspi_fetch_latest_success_audit_id(cmd_args):
    '''osspi_fetch_latest_success_audit_id inspects the given product on the
    OSSPI Dashboard and retried the ID of the latest successful audit.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                project (str):  OSSPI Project name for fetching scan results.
                branch (str):  OSSPI Project Branch name.
    Returns:
        (int):  ID of the audit.
    '''
    req = _requests_osspi(
        cmd_args,
        requests.get,
        (
            f'{OSSPI_BASE_URL}/projects/?product={cmd_args.project}'
            f"{f'&branch={cmd_args.branch}' if cmd_args.branch else ''}",
        ),
    )
    if req.status_code == 200:
        response = req.json()
        logging.debug(f"# of matching projects={len(response['results'])}")
        for result in response['results']:
            logging.debug(
                f"id={result['id']}, project={result['product']}, "
                f"branch={result['branch']}, "
                f"latest_success_audit={result['latest_success_audit']}")
            return int(result['latest_success_audit'])
    return -1


def osspi_fetch_package(cmd_args, pkg_id, pkg_url):
    '''osspi_fetch_package fetches package information from OSSPI for the given
    package ID.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
        pkg_id (str):   ID of the package to fetch.
        pkg_url (str):  URL of the package to fetch.
    Returns:
        (object):   The package information from JSON-encoded response.
    '''
    req = _requests_osspi(cmd_args, requests.get, (pkg_url,))
    req.raise_for_status()
    if req.status_code == 200:
        return req.json()
    raise Exception(f'Unexpected response when fetching package {pkg_id}: '
                    f'status {req.status_code}')


def osspi_fetch_vulnerable_packages(cmd_args, audit_id):
    '''osspi_fetch_vulnerable_packages fetches the OSSPI vulnerabilities for
    a given audit ID.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
        audit_id (int): The ID of the OSSPI audit to inspect.
    Returns:
        (dict): Map of package ID to a dict of package vulnerability data.
    '''
    packages = {}
    vulns = _fetch_multi_pages_osspi(
        cmd_args,
        f'{OSSPI_BASE_URL}/vulnerabilities/?audit_id={audit_id}',
        ('results',),
    )
    logging.debug(f'# of package vulnerabilities={len(vulns)}')
    for vuln in vulns:
        package_url = vuln['links']['package']
        cve = vuln['uid']
        package_id = package_url.split('/')[-2]
        if package_id not in packages:
            logging.debug(f"{cve} fetching package: {package_id}")
            package = osspi_fetch_package(cmd_args, package_id, package_url)
            packages[package_id] = package
    return packages


def osspi_merge_vuln_with_known(cmd_args, osspi, known):
    '''osspi_merge_vuln_with_known merges together impact statements from known
    vulnerabiltiies with a collection of OSSPI package vulnerabilities.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                project (str):      OSSPI Project name.
                sub_charted_sfx (str):
                    Sub-charted Service Name's suffix.
        osspi (dict): Map of (service_name, image_name, package_name, cve) to
            OsspiVulnerability.
        known (dict): Map of (service_name, image_name, package_name, cve) to
            KnownVulnerability.
    Returns:
        (dict): A new dictionary with all records from the OSSPI collection and
            any impact statements from the known vulnerabilities collection.
    '''
    project = cmd_args.project
    sc_sfx = cmd_args.sub_charted_sfx
    if known is None:
        known = {}

    merged = {}
    for vuln, _osspi in osspi.items():
        if sc_sfx:
            k_v = (vuln[0].removesuffix(sc_sfx),) + vuln[1:]
        else:
            k_v = vuln
        merged[vuln] = dataclasses.asdict(_osspi)
        if k_v not in known:    # The `image_name` is optional in `known`.
            k_v = (k_v[0], '') + k_v[2:]
        if k_v not in known:
            merged[vuln]['impact_summary'] = ''
            # Link to help create Jira ticket includes information from the
            # OSSPI scan report.
            linkname = 'Create Jira'
            summary = (
                f'Security Scan: {_osspi.service_name}: '
                f'{_osspi.package_name}: {_osspi.cve}'
            )
            _files = '\n'.join([s.strip()
                                for s in _osspi.file_paths.split(',')])
            description = (
                'OSSPI Security Scan Finding\n\n'
                f'Project: {project}\n'
                f'Service: {_osspi.service_name}\n'
                f'Image: {_osspi.image_name}\n\n'
                f'Package: {_osspi.package_name}\n\n'
                f'CVE: {_osspi.cve}\n'
                f'CVSSV3: {_osspi.cvssv3}\n'
                f'CVE Link: {_osspi.cve_link}\n'
                f'CVE Description: {_osspi.cve_desc}\n\n'
                f'File Paths:\n{_files}'
            )
            url = _jira_create_issue_link(cmd_args, summary, description)
            merged[vuln]['impact_analysis'] = f'[{linkname}|{url}]'
            merged[vuln]['custom'] = ''
            continue
        merged[vuln]['impact_summary'] = known[k_v].impact_summary
        merged[vuln]['impact_analysis'] = known[k_v].impact_analysis
        merged[vuln]['custom'] = '\n'.join([
            f'{label}: {value}' for label, value in known[k_v].custom.items()
        ])

    return merged


def osspi_packages_vulnerabilities(cmd_args, packages, product_id,
                                   min_cvssv3=0.0):
    '''osspi_packages_vulnerabilities returns a map of
    (service_name, package_name, cve) to a OsspiVulnerability record of the
    scan result.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                ignore_pkg_ver (bool):  Ignore package version in the Vuln.
                                        Report.
        packages (dict):    Map of OSSPI package ID to the package info record.
        product_id (str):   Product ID selector.
        min_cvssv3 (float): Filter returned vulnerabilities by this minimum
                            CVSSv3 score.
    Returns:
        (tuple):    Tuple of dict of (service_name, image_name, package_name,
                    cve) to OsspiVulnerability, version number, build number.
    '''
    # pylint: disable=too-many-branches
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-nested-blocks
    version = None
    build = None
    vuln = {}

    override = PROD_CFG.get('ProductDataOverrides', {}).\
        get('BLACKDUCK_PATH_RE', {}).get(product_id, {})
    if override:
        # pylint: disable=eval-used
        BLACKDUCK_PATH_RE.update(eval(f"{{'{product_id}': {override}}}"))

    for package in packages.values():
        package_name = package['package']
        if cmd_args.ignore_pkg_ver:
            package_name = _drop_pkg_ver(package_name)
        logging.debug(f'Evaluating OSSPI package_name={package_name}')
        services = {}
        for path in package['blackduck_paths']:
            # See comment in `BLACKDUCK_PATH_RE` definition for details in
            # `blackduck_paths`.
            match = re.fullmatch(BLACKDUCK_PATH_RE[product_id], path)
            if match:
                match = [i for i in match.groups() if i is not None]
                if match:
                    if version is None:
                        version = match[0]
                        logging.debug(f'Got Product version={version}')
                    if build is None:
                        build = match[1]
                        logging.debug(f'Got Build number={build}')
                    if MAPPER.getSvcAndCtrImgNameFunc.get(product_id):
                        mapped_names = globals()[
                            MAPPER.getSvcAndCtrImgNameFunc[product_id]
                        ](cmd_args, match[2], match[3], match[4])
                    else:
                        mapped_names = (((match[3], ''), [(match[2], '')]),)
                    for ((img_name, img_tag), svc_owns) in mapped_names:
                        # If the `file_path` contains `#`-delimited string, it
                        # means the detected file is inside (sub-)archives.
                        # Replace the delimiter with `:` for clarity.
                        file_path = match[5].replace('#', ':')
                        for (svc_name, svc_tag) in svc_owns:
                            key = (
                                img_name, img_tag,
                                MAPPER.svcName.get(product_id, {}).get(
                                    svc_name, svc_name), svc_tag,
                            )
                            if key not in services:
                                services[key] = set()
                            services[key].add(file_path)
            else:
                logging.warning(f'Non-matching path={path}')
        for vulnerability in package['vulnerabilities']:
            cve = vulnerability['uid']
            cvssv3 = vulnerability['cvss3_basescore']
            cve_link = vulnerability['json'].get('link', '')
            cve_desc = vulnerability['json'].get('description', '')
            if cvssv3 is not None and cvssv3 > min_cvssv3:
                for ((img_name, img_tag, svc_name, svc_tag), file_paths) in \
                        services.items():
                    key = (svc_name, img_name, package_name, cve)
                    if key in vuln:
                        logging.warning(f'DUPLICATE package vulnerability: '
                                        f'{key}')
                    _file_paths_str = ', '.join(sorted(file_paths))
                    vuln[key] = OsspiVulnerability(
                        build, f'{svc_name}{svc_tag}', f'{img_name}{img_tag}',
                        package_name, cvssv3, cve, cve_link, cve_desc,
                        _file_paths_str,
                    )

    return (vuln, version, build)


def osspi_scan(cmd_args):
    '''osspi_scan requests OSSPI scan of the given artifact.

    Args:
        cmd_args (argparse.Namespace): Command line arguments.
            The attributes of interest:
                dry_run (bool): Perform a dry run of the operations, skip
                    actions which result in permanent side-effects.
                sub_cmd_osspi_scan (str): Sub-Command of `osspi-scan`.
                scanner (str): OSSPI scanner to use.
                artifact_url (str): URL of the artifact to scan.
                release (str): Release ID of the product. If `None` it will be
                    set to main's release version.
                build_id (int): ID of the build to be scanned.
                wait_timeout (int): Scan waiting timeout in min.
                no_osspi_dashboard (bool): Do not upload the Scan Result to
                    OSSPI Dashboard.
                oci_img_tag (str): Tag of the OCI Image.
                toolpath (str): Path to OSSPI tool.
                project (str): OSSPI Project name for storing scan results.
                api_key (str): OSSPI API Key for Dashboard interactions.
                output (str): Report file name.
    Returns:
        (int): OSSPI scan ID
    '''
    # pylint: disable=too-many-branches
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-statements
    # pylint: disable=too-many-return-statements
    dry_run = cmd_args.dry_run
    sub_cmd = cmd_args.sub_cmd_osspi_scan
    scanner = cmd_args.scanner
    artifact_url = cmd_args.artifact_url
    release = cmd_args.release
    build_id = cmd_args.build_id
    timeout = cmd_args.wait_timeout
    no_osspi_dashboard = cmd_args.no_osspi_dashboard
    oci_img_tag = cmd_args.oci_img_tag
    toolpath = cmd_args.toolpath
    if sub_cmd == 'vuln':
        project = cmd_args.project
        api_key = cmd_args.api_key
    else:
        output = cmd_args.output

    if artifact_url:
        if release or build_id:
            logging.warning('Scan request with both artifact and release or '
                            'build given, preferring artifact URL.')
    else:
        artifact_url = get_build_url(cmd_args)

    scanner_args = []
    image = urllib.parse.urlparse(artifact_url)
    if image.scheme in ('file', ''):
        image = urllib.parse.urlparse(urllib.parse.quote(artifact_url))
    if scanner == 'binary':
        if image.scheme in ('http', 'https'):
            scanner_args.append(f"--fetch-file '{artifact_url}'")
        elif image.scheme in ('file', ''):
            if image.netloc:
                logging.warning(
                    f'Can not support non-local file: {artifact_url}')
                return -1
            scanner_args.append('--upload-file '
                                f"'{urllib.parse.unquote(image.path)}'")
        else:
            logging.warning(f'Not supported URL scheme: {artifact_url}')
            return -1
    elif scanner == 'docker':
        if image.scheme == 'docker':
            scanner_args.append(f"--image '{image.netloc}{image.path}'")
        elif image.scheme in ('file', ''):
            if image.netloc:
                logging.warning(
                    f'Can not support non-local file: {artifact_url}')
                return -1
            scanner_args.append('--image-tar '
                                f"'{urllib.parse.unquote(image.path)}'")
        else:
            logging.warning(f'Not supported URL scheme: {artifact_url}')
            return -1
    elif scanner == 'signature':
        if image.scheme in ('file', ''):
            if image.netloc:
                logging.warning(
                    f'Can not support non-local file: {artifact_url}')
                return -1
            scanner_args.append('--work-dir '
                                f"'{urllib.parse.unquote(image.path)}'")
        else:
            logging.warning(f'Not supported URL scheme: {artifact_url}')
            return -1

    cmds = [f'{toolpath}']
    cmds.append('-d')   # Temporary workaround until hb print is ready.
    cmds.append('scan')
    if timeout:
        cmds.append(f'--timeout {timeout}')
    cmds.append(scanner)
    cmds.extend(scanner_args)
    if sub_cmd == 'vuln':
        # URL: [schema:[//[usr[:pwd]@]host[:port]]path]
        output = re.sub(r'^(?:[^:]+(?::.*)?@)?', '', image.netloc) + image.path
        output = output.replace('/', '#').replace(':', '%')
        if scanner == 'binary':
            if not no_osspi_dashboard:
                cmds.append('--to-dashboard')
                cmds.append(f"--osspi-apikey '{api_key}'")
                cmds.append(f"--osspi-product '{project}'")
                cmds.append('--osspi-nowait')
        elif scanner == 'docker':
            # Registry path: [namespace]/repository(:tag|@digest)
            cmds.append(f"--report '{output}';")
            # Add the container name so later `blackduck_paths` contains
            # the information.
            # The BaseOS scan report, put the file path in `.detected_paths`
            #   key, with the top-level archives listed on top in a
            #   `#`-delimited string.
            # The non-BaseOS scan report, put the file path is
            #   `bd_metadata.paths` key, but with the top-level archives listed
            #   on bottom (reversed order) of `#`-delimited string. The last
            #   part is layer information inside the Container Image:
            #   `<localImgName>.tar!/<sha256LyrHash>/layer.tar
            #   [!<optionalInterimArchiveStartWithSlash>...]!/`. Only the
            #   layer's SHA-256 and optional interim archives, if any, may be
            #   of interest, the rest are insignificant.
            #   Re-arrange the `#`-delimited string to look like the BaseOS
            #   scan report's `.detected_paths`.
            #   NOTE:
            #       In some cases the `bd_metadata.paths` may contains the
            #       Container Image Layer jar file as a whole, in form of
            #       `/<sha256LyrHash>/layer.tar#<localImgName>.tar!/`.
            img_name, img_sep, img_tag = re.split(
                r'((?:@sha256)?:)',
                image.path.rsplit('/', 1)[-1],
            )
            if oci_img_tag:
                img_name = f'{img_name}%{oci_img_tag}'
            elif img_sep == ':':
                img_name = f'{img_name}%{img_tag}'
            cmds.append(
                f'jq --arg pfx '
                f"'{output.replace('#', '/')}#{img_name}#' '"
                '.packages |= ('
                '  .[] |='
                '    if has("detected_paths")'
                '    then (.detected_paths[] |= $pfx+.)'
                '    else ('
                '      .bd_metadata.paths[] |= $pfx+('
                '        split("#") | reverse |'
                '        if ('
                '          (length == 2) and'
                '          ((.[0] | split("/") | length) == 2)'
                '        ) then ('
                '          [(.[1] + .[0][1:]), "/"]'
                '        ) else . end |'
                '        ('
                '          .[0] | split("!/") | ('
                '            [(.[1] | split("/")[0])] +'
                '            (.[2:-1] | .[] |= "/"+.)'
                '          )'
                '        ) + [.[1]] | join("#")'
                '      )'
                '    ) end'
                ')'
                f"' '{output}.json' 1> '_{output}.json';"
            )
            if not no_osspi_dashboard:
                cmds.append(f'{cmds[0]} -d upload '
                            f"{f'--timeout {timeout} ' if timeout else ''}"
                            f"--apikey '{api_key}' --product '{project}' "
                            f"--source '_{output}.json' --allow-empty;")
                cmds.append(f"rm -rf {{_,}}'{output}'.json;")
            cmds.insert(0, '{')
            cmds.append('}')
        logging.debug(f'Request OSSPI vulnerability scan: '
                      f'artifact={artifact_url} project={project}')
    else:
        cmds.append('--format manifest')
        if output:
            cmds.append(f"--report '{output}'")
        logging.debug(f'Request OSSPI inventory profile scan: '
                      f'artifact={artifact_url}')
    cmd = ' '.join(cmds)
    if dry_run:
        logging.debug(f'Dry Run: OSSPI scan: {cmd}')
    else:
        out = './stdout.txt'
        logging.info(f'OSSPI scan: {cmd}')
        subprocess.run(
            f"set -ex; set -o pipefail; {cmd} |& tee '{out}'",
            shell=True, check=True, executable='/usr/bin/bash')
        if sub_cmd == 'vuln':
            # The `toybox sed` can not match newline.
            out = subprocess.check_output(
                'echo -n "$(sed -nE '
                f"'s/^.* - Upload report can be found at (.+)/\\1/p' '{out}'"
                f')"; rm -rf \'{out}\' 1> /dev/null 2>&1',
                shell=True,
            ).decode()
            if out:
                with open(out) as handle:
                    audit_id = json.load(handle)['scan_id']
                logging.debug(f'OSSPI scan created: {audit_id}')
                return int(audit_id)
            logging.warning('OSSPI scan not created, ID unknown.')
    return -1


def post_report(filename, confluence_page_id,
                confluence_username, confluence_password):
    '''post_report publishes a file to a Confluence page as an attachment.

    Args:
        filename (str): Name of the file to attach into Confluence.
        confluence_page_id (str): Page ID of the Confluence page for file
            attachment.
        confluence_username (str): Auth credential username for Confluence.
        confluence_password (str): Auth credential password for Confluence.
    '''
    basic_auth = requests.auth.HTTPBasicAuth(confluence_username,
                                             confluence_password)
    confluence_url = (f"{CONFLUENCE_API_BASE_URL}/content"
                      f"/{confluence_page_id}/child/attachment")
    headers = {'X-Atlassian-Token': 'nocheck'}
    req = requests.get(confluence_url, headers=headers, auth=basic_auth)
    logging.debug(f"status code={req.status_code}")
    _id = None
    if req.status_code == 200:
        response = req.json()
        for result in response['results']:
            if result['title'] == pathlib.PurePath(filename).name:
                _id = result['id']
    if _id is None:
        url = (f"{CONFLUENCE_API_BASE_URL}/content/{confluence_page_id}"
               f"/child/attachment")
    else:
        url = (f"{CONFLUENCE_API_BASE_URL}/content/{confluence_page_id}"
               f"/child/attachment/{_id}/data")
    with open(filename, 'rb') as csv_file:
        req = requests.post(url,
                            files={'file': (filename,
                                            csv_file)},
                            headers=headers, auth=basic_auth)
        req.raise_for_status()
        if req.status_code == 200:
            logging.debug(f"Posted {filename} to Confluence "
                          f"page {confluence_page_id}")
        else:
            logging.debug(f"Error posting {filename} to "
                          f"Confluence page {confluence_page_id}: "
                          f"{req.status_code}")


def read_merge_audit_result(cmd_args, known_vuln=None):
    '''read_merge_audit_result reads an audit result from JSON file, merges it
    with known vulberabilities data, and returns the resulting merged data.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                project (str):      OSSPI Project name for posting scan
                                    results.
                input (list):       Input filenames (JSON) or directories
                                    (containing JSON files) that contains the
                                    vulnerability data.
                product (str):      Product name, to support arbitrary
                                    `project`.
                min_cvssv3 (float): Include results in the scan report with
                                    CVSSv3 results meeting this minimum value.
        known_vuln (dict):  Map of (service_name, image_name, package_name,
                            cve) to KnownVulnerability.
    '''
    project = cmd_args.project
    product = cmd_args.product

    merged_vuln = {}
    osspi_vuln = {}
    packages = {}

    def _func(file, packages):
        try:
            with open(file) as handle:
                packages.update(json.load(handle))
        except FileNotFoundError:
            logging.error(f'OSSPI scan results file not found: {file}')
            raise
        except json.decoder.JSONDecodeError:
            logging.error(f'OSSPI scale results file JSON error: {file}')
            raise

    _load_from_paths(cmd_args.input, 'audit result', ('json', 'JSON'),
                     (_func, (packages,), {}))

    if product or (project in ALL_OSSPI_PROJECTS):
        if product:
            prod_id = product
        else:
            prod_id = _osspi_project_to_prod_id(project)
        logging.info(f'Creating {prod_id} known vulnerabilities map from OSSPI'
                     'packages vulnerabilities')
        (osspi_vuln, _, _) = osspi_packages_vulnerabilities(
            cmd_args, packages, prod_id, min_cvssv3=cmd_args.min_cvssv3)
    else:
        raise Exception('Unsupported project for packages vulnerabilities '
                        f'inspection: {project}')
    merged_vuln = osspi_merge_vuln_with_known(cmd_args, osspi_vuln, known_vuln)

    return merged_vuln


def write_dev_report_csv(cmd_args, vulnerabilities):
    '''write_dev_report_csv reads a dict of vulnerabiltieies and writes a CSV
    rendering of the data to a file.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                output: Filename to write report in CSV format.
        vulnerabilities (dict): A map of (service_name, image_name,
            package_name, cve) to a dictionary with the OSSPI description of
            the package and its detected vulnerability.
    '''
    filename = cmd_args.output

    if not filename:
        logging.error('A valid file path is required for option `--output`.')
        return
    with open(filename, 'w') as csv_file:
        vuln_data = vulnerabilities.values()
        if len(vuln_data) == 0:
            # pylint: disable=no-member
            # The `csv.DictWriter()` need header. The header is taken from the
            # `dict` keys. So we need at least a model `dict` containing the
            # appropriate keys to be used as header.
            field_names = OsspiVulnerability.__dataclass_fields__.keys()
        else:
            field_names = next(iter(vuln_data)).keys()
        csv_writer = csv.DictWriter(csv_file, delimiter=',',
                                    fieldnames=field_names)
        logging.debug(f'Writing CSV header: {filename}: {field_names}')
        csv_writer.writeheader()
        logging.debug(f'Writing {len(vulnerabilities)} rows: {filename}')
        for vuln in vuln_data:
            csv_writer.writerow(_osspi_confluence_wikisafe(vuln))


def write_rel_report_csv(cmd_args, vulnerabilities, create_grouped=True):
    # pylint: disable=too-many-branches
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-statements
    '''write_rel_report_csv reads a dict of vulnerabiltieies and writes a CSV
    rendering of the data to a file.

    Data is denormalized records of impact summary, impact analysis, CVE,
    package, and service.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                output (str):           Filename to write report in CSV format.
                no_col_service (bool):  Omit `service` column.
        vulnerabilities (dict): A map of (service_name, image_name,
            package_name, cve) to a dictionary with the OSSPI description of
            the package and its detected vulnerability.
        create_grouped (bool): When True, creates additional CSV file with
            data grouped by impact summary, impact analysis, and package with
            aggregations of CVEs and services.
    '''
    filename = cmd_args.output
    no_col_service = cmd_args.no_col_service

    if not filename:
        logging.error('A valid file path is required for option `--output`.')
        return
    # Create de-normalized CSV output.
    with open(filename, 'w') as csv_file:
        logging.debug(f'Writing CSV output: {filename}')
        field_names = ['Summary', 'Analysis', 'CVE', 'Package']
        if not no_col_service:
            field_names.append('Service')
        csv_writer = csv.DictWriter(csv_file, delimiter=',',
                                    fieldnames=field_names)
        logging.debug(f'Writing CSV header: {filename}: {field_names}')
        csv_writer.writeheader()
        logging.debug(f'Writing {len(vulnerabilities)} rows: {filename}')
        for rec in vulnerabilities.values():
            summary = rec['impact_summary'] or 'Missing'
            analysis = rec['impact_analysis'] or 'Missing'
            if 'Create Jira' in analysis:
                analysis = 'Missing'
            package = rec['package_name']
            service = rec['service_name']
            cve = rec['cve']
            record = {
                'Summary': summary,
                'Analysis': analysis,
                'CVE': cve,
                'Package': package,
            }
            if not no_col_service:
                record['Service'] = service
            csv_writer.writerow(_osspi_confluence_wikisafe(record))
    # Optional, create a grouped field CSV output.
    if create_grouped:
        filename = _append_str_to_filename(filename, '-grouped')
        logging.debug(f'Writing CVS grouped output: {filename}')
        data = defaultdict(                   # summary
            lambda: defaultdict(              # analysis
                lambda: defaultdict(set)))    # cve[], service[], package[]
        for rec in vulnerabilities.values():
            summary = rec['impact_summary'] or 'Missing'
            analysis = rec['impact_analysis'] or 'Missing'
            if 'Create Jira' in analysis:
                analysis = 'Missing'
            data[summary][analysis]['cve'].add(rec['cve'])
            data[summary][analysis]['package'].add(rec['package_name'])
            if not no_col_service:
                data[summary][analysis]['service_name'].add(
                    rec['service_name'])
        with open(filename, 'w') as csv_file:
            field_names = ['Summary', 'Analysis', 'CVE', 'Package']
            if not no_col_service:
                field_names.append('Service')
            csv_writer = csv.DictWriter(csv_file, delimiter=',',
                                        fieldnames=field_names)
            logging.debug(f'Writing CSV header: {filename}: {field_names}')
            csv_writer.writeheader()
            logging.debug(f'Writing {len(vulnerabilities)} rows: {filename}')
            for summary, analyses in data.items():
                for analysis, details in analyses.items():
                    record = {
                        'Summary': summary,
                        'Analysis': analysis,
                        'CVE': '\n'.join(sorted(details['cve'])),
                        'Package': '\n'.join(sorted(details['package'])),
                    }
                    if not no_col_service:
                        record['Service'] = '\n'.join(sorted(
                            details['service_name']))
                    csv_writer.writerow(_osspi_confluence_wikisafe(record))


def main():
    '''main is the primary entry point for executing this helper tool. Command
    line arguments are parsed and the requested action evaluated.'''
    global PROD_CFG     # pylint: disable=global-statement

    args = _parse_args()
    utils.setup_logging(None, *args.log_level)

    if args.verbose_http:
        HTTPConnection.debuglevel = 1
    if args.prod_cfg:
        prod_cfg_file = args.prod_cfg
        if pathlib.Path(prod_cfg_file).is_file():
            PROD_CFG = yaml.safe_load(open(prod_cfg_file))
        else:
            raise Exception(f'Invalid Product Config file: {prod_cfg_file}')

    # Run the sub-command.
    # pylint: disable=eval-used
    if args.sub_cmd:
        funcname = f"cmd_{args.sub_cmd.replace('-', '_')}"
        eval(funcname)(args)


def _append_str_to_filename(filepath, append_str):
    '''_append_str_to_filename parses a file path, identifies the stem of the
    filename (without any of multiple extensions, if any), appends the given
    string, creates the full path, and returns the result.

    Args:
        filepath (str): The filepath to be adjusted.
        append_str (str): The string to be appended to file stem name.
    '''
    path = pathlib.Path(filepath)
    stem = f"{path.parts[-1].split('.')[0]}{append_str}"
    out_path = path.parent / ''.join([stem, *path.suffixes])
    return out_path


def _drop_pkg_ver(pkg_name):
    '''_drop_pkg_ver removes version from `pkg_name`, if any.

    Args:
        pkg_name (str): Package name.
    Returns:
        (str):  Package name with its version removed, if any.
    '''
    match = re.fullmatch(
        # https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
        # Some package has `v` (or maybe even `V`) as start of its version.
        r'(.*?)(?:-[vV]?(?:\d+:)?\d+[-.+~A-Za-z0-9]*)?',
        pkg_name,
    )
    return match[1] if match else pkg_name


def _fetch_multi_pages_osspi(cmd_args, url, keys):
    '''_fetch_multi_pages_osspi fetches collection of object identified by key
    tree that may need to be retrieved via multiple OSSPI REST API calls due to
    pagination.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
        url (str):      The fetcher URL.
        keys (tuple):   Key tree structure inside the REST API response that
                        its value will be collated as list.
    Returns:
        (list): List of collated objects those are value of specified key
                structure.
    '''
    wanted_objs = []
    while url:
        rsp = _requests_osspi(cmd_args, requests.get, (url,))
        rsp.raise_for_status()
        if rsp.status_code == 200:
            rsp_payload = rsp.json()
            data = rsp_payload
            for key in keys:
                data = data[key]
            wanted_objs += data
            url = rsp_payload['next']
        else:
            raise Exception('Unexpected response when fetching multi-page '
                            f'data: status {rsp.status_code}')
    return wanted_objs


def _jira_create_issue_link(cmd_args, summary, description):
    '''_jira_create_issue_link synthesizes a link for creating a Jira ticket.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                project (str):      OSSPI Project name.
                product (str):      Product name, to support arbitrary
                                    `project`.
        summary (str): Summary string to be used in the Jira ticket.
        description (str): Description string to be used in the Jira ticket.
    '''
    project = cmd_args.project
    product = cmd_args.product

    if product or (project in ALL_OSSPI_PROJECTS):
        if product:
            prod_id = product
        else:
            prod_id = _osspi_project_to_prod_id(project)
        pid = JIRA_PID[prod_id]
        extra = JIRA_EXTRAS[prod_id]
    else:
        logging.warning(f'Unrecognized project, skipping Jira link: {project}')
        return ''
    issuetype = 1  # Bug
    priority = 2  # Critical = P1
    summary = urllib.parse.quote(summary)
    description = urllib.parse.quote(description)
    _url = (f'{JIRA_BASE_URL}/secure/CreateIssueDetails!init.jspa?pid={pid}'
            f'&issuetype={issuetype}&summary={summary}'
            f'&description={description}&priority={priority}{extra}')
    return _url


def _load_from_paths(path_list, kind, file_spec, func_spec):
    '''_load_from_paths load files (or searched for files under directoryies)
    from the given list and call the requested function for each found files.

    Args:
        path_list (list):       List of `str` as path to file or directory.
        kind (str):             A description of what we are processing. For
                                logging purposes.
        file_spec (tuple):      A `tuple` of (ext, type).
                                Where:
                                    ext (str):  File Extension.
                                    type (str): File Type.
        func_spec (tuple):      A `tuple` of (func, args, kwargs).
                                The function `func` that will be called to
                                process each found file.
                                This function should take a `str` argument, as
                                the full path of the found file, as its first
                                argument, followed by `args` and `kwargs`,
                                respectively.
                                The `args` and/or `kwargs` may contains mutable
                                object(s), so the caller of this function can
                                get the processing result of `func` call.
    '''
    file_ext, file_type = file_spec
    func_name, func_args, func_kwargs = func_spec
    for path_str in path_list:
        path = pathlib.Path(path_str)
        logging.info(f'Processing path for {kind} content: {path}')
        if path.is_dir():
            files = sorted(path.glob(f'**/*.{file_ext}'))
            if not files:
                logging.warning(f'No {file_type} (.{file_ext}) file found'
                                f' under: {path}{pathlib.os.sep}')
            logging.debug(f'Found {len(files)} {kind} files.')
        elif path.is_file():
            if path.suffix != f'.{file_ext}':
                logging.warning(f'Not a {file_type} (.{file_ext}) file: '
                                f'{path}')
                files = []
            else:
                files = [path]
        else:
            logging.warning(f'Invalid {kind} path: {path}')
            continue
        for file in files:
            logging.debug(f'Loading {kind}: {file}')
            func_name(file, *func_args, **func_kwargs)


@static_func_vars()
def _get_svc_and_ctr_img_name__percent_sep(
    self, cmd_args, def_svc_name, def_img_name, *args, **kwargs,
):
    '''_get_svc_and_ctr_img_name__percent_sep returns Service Names and
    Container Image Name from `def_svc_name` and `def_img_name` (in format of
    `<name>[%<tag>]`), respectively.

    See `MAPPER.getSvcAndCtrImgNameFunc` for details on `Args` and `Return`.
    '''
    _ = (self, cmd_args, args, kwargs)

    svc_name = def_svc_name.rsplit('%', 1)
    if len(svc_name) == 2:
        svc_name[1] = f':{svc_name[1]}'
    else:
        svc_name = [def_svc_name, '']
    img_name = def_img_name.rsplit('%', 1)
    if len(img_name) == 2:
        img_name[1] = f':{img_name[1]}'
    else:
        img_name = [def_img_name, '']

    return (((img_name[0], img_name[1]), [(svc_name[0], svc_name[1])]),)


@static_func_vars(map=defaultdict(lambda: defaultdict(lambda: None)))
def _get_svc_and_ctr_img_name__img_lyr_sha_2_map(
    self, cmd_args, def_svc_name, def_img_name, *args, **kwargs,
):
    '''_get_svc_and_ctr_img_name__img_lyr_sha_2_map returns Service Name and
    Container Image Names from an Image Layer Hash.

    See `MAPPER.getSvcAndCtrImgNameFunc` for details on `Args` and `Return`.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            Used:   layer_map
        **args:
            Used:   img_lyr_hash

    Note:   It is possible that multiple Services contain the same exact
            Container Images or share the same Container Image Bases, hence
            will share several same Image Layers.

    Schema of `layer_map`:
        LayerMappings:
          ImgpkgBundles:
            - URL: <imgpkgURLwithSHA>           # URL that works for `imgpkg describe -b ...`.
              Tag: <imgpkgTag>                  # Set to `null` is can't be determined.
              ContainerImgs:
                - URL: <containerImgURLwithSHA> # URL that works for `docker manifest inspect ...`.
                  Tag: <containerImgTag>        # Set to `null` is can't be determined.
                  ImgLayers:
                    - <imgLayerSHA>
          ContainerImgs:
            - URL: <containerImgURLwithSHA>     # URL that works for `docker manifest inspect ...`.
              Tag: <containerImgTag>            # Set to `null` is can't be determined.
              ImgLayers:
                - <imgLayerSHA>
    With:
        imgpkgURLwithSHA, containerImgURLwithSHA:   <host>[:<port>]/[<imgNameSpace>]/<imgName>@<imgDigest>
        imgpkgTag, containerImgTag:                 <imgTag>
        imgLayerSHA:                                sha256:<sha256Val>
    '''     # pylint: disable=line-too-long # noqa: E501
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-nested-blocks
    _ = kwargs
    (img_lyr_hash,) = args

    if cmd_args.layer_map is not None:
        lyr_map = yaml.safe_load(open(cmd_args.layer_map)).get(
            'LayerMappings', {})
        cmd_args.layer_map = None
        lyr_map['ImgpkgBundles'] = lyr_map.get('ImgpkgBundles', [])
        lyr_map['ImgpkgBundles'].append(
            dict(URL=None, Tag=None,
                 ContainerImgs=lyr_map.get('ContainerImgs', [])))
        del lyr_map['ContainerImgs']
        for imgpkg in lyr_map['ImgpkgBundles']:
            ip_url = imgpkg['URL']
            if ip_url is None:
                (ip_name, ip_tag) = ('', '')
            else:
                ip_tag = imgpkg['Tag']
                ip_name = re.split(r'((?:@sha256)?:)', ip_url)
                if ip_tag is None:
                    ip_tag = ''.join(ip_name[-2:])
                else:
                    ip_tag = f":{ip_tag}"
                ip_name = ''.join(ip_name[:-2]).rsplit('/', 1)[-1]

            for ctr_img in imgpkg['ContainerImgs']:
                ci_url = ctr_img['URL']
                ci_tag = ctr_img['Tag']
                ci_name = re.split(r'((?:@sha256)?:)', ci_url)
                ci_sha = ci_name[-1]
                if ci_tag is None:
                    ci_tag = ''.join(ci_name[-2:])
                else:
                    ci_tag = f":{ci_tag}"
                ci_name = ''.join(ci_name[:-2]).rsplit('/', 1)[-1]
                for img_lyr in ctr_img['ImgLayers']:
                    il_map = self.map[img_lyr]
                    if not il_map[ci_sha]:
                        il_map[ci_sha] = ((ci_name, ci_tag), [])
                    il_map[ci_sha][1].append((ip_name, ip_tag))
        self.map = {key: (*(el for el in val.values()),)
                    for (key, val) in self.map.items()}

    return self.map.get(
        img_lyr_hash,
        (((def_img_name, ''), [(def_svc_name, '')]),),
    )


def _match_regex_key(dict_object, key_string):
    '''_match_regex_key returns dictionary value that its key matches as RegEx
    pattern to the given `key_string`.

    Args:
        dict_object (dict): The dictionary to search.
        key_string (str): String to match with `dict_object`'s keys.
    Returns:
        (object): The value of the `dict_object` that its key matches the
            `key_string`.
    '''
    for key in dict_object:
        if re.search(key, key_string):
            return dict_object[key]
    raise Exception('No dictionary key can match the given `key_string`:'
                    f'{key_string}')


def _osspi_confluence_wikisafe(vuln_record):
    '''_osspi_confluence_wikisafe performs adjustments to vulnerability record
    data to provide increased data safety for Confluence wiki publishing.

    Args:
        vuln_record (dict): OSSPI description of a package and its detected
            vulnerability
    Returns:
        (dict): In-place modification of certain dictionary values for wiki
            markup safety.
    '''
    mod = copy.deepcopy(vuln_record)
    if 'cve_desc' in mod:
        # Escape special characters.
        mod['cve_desc'] = re.sub(r'([{}|])', r'\\\1', mod['cve_desc'])
        # Remove multi-newlines.
        mod['cve_desc'] = re.sub(r'(?:(\r\n)|\r|\n){2,}', r'\n',
                                 mod['cve_desc'])
    if 'impact_analysis' in mod:
        mod['impact_analysis'] = re.sub(r'(?:(\r\n)|\r|\n){2,}', r'\n',
                                        mod['impact_analysis'])
    return mod


def _osspi_project_to_prod_id(project):
    '''_osspi_project_to_prod_id returns Product ID selector of an OSSPI
    Dashboard Project.

    Args:
        project (str): Name of the OSSPI Dashboard Project.
    Returns:
        (str): Product ID selector.
    '''
    prod_id = ''
    for (key, val) in OSSPI_PROJECTS.items():
        if project in val:
            prod_id = key
            break
    if not prod_id:
        raise Exception(f'Unsupported OSSPI Dashboard Project: {project}')
    return prod_id


def _parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    utils.parse_args__log_level(parser)
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Execute a dry run and skip invoking actual commands and making '
             'API calls.')
    parser.add_argument(
        '-v', '--verbose-http',
        action='store_true',
        help='Enable verbose logging for HTTP transaction.')

    parser.add_argument(
        '--prod-cfg', type=str,
        help='Product config file (YAML).')

    subparsers = parser.add_subparsers(
        title='sub-commands',
        dest='sub_cmd', help='Sub-Command Help')

    subparser = subparsers.add_parser(
        'install-osspi', help='Run the OSSPI scan tool installer.')
    # https://usw1.packages.broadcom.com/osspicli-local/beta/osspicli/install.sh
    subparser.add_argument(
        'installer', type=str,
        help='Path of the OSSPI scan tool installer, `http(s)` or local path '
             'supported. If `http(s)` is used, then the downloaded the '
             'installer must be a `bash` compatible script.')

    subparser = subparsers.add_parser(
        'get-build-url',
        help='Get the build URL for a product.')
    _parse_args_get_build_url(subparser)
    subparser.add_argument(
        'product', type=str,
        help='Product name for the build URL to get.')

    subparser = subparsers.add_parser(
        'osspi-scan',
        help='Run a scan by OSSPI.')
    opt_osspi_scan_common = argparse.ArgumentParser(add_help=False)
    _parse_args_scan(opt_osspi_scan_common)
    subparsers_osspi_scan = subparser.add_subparsers(
        title='sub-commands',
        dest='sub_cmd_osspi_scan',
        help='Sub-Command for `ossspi-scan` Sub-Command Help')

    subparser = subparsers_osspi_scan.add_parser(
        'vuln',
        help='Scan for vulnerability then store the report to the OSSPI '
             'Dashboard.',
        parents=[opt_osspi_scan_common])
    subparser.add_argument(
        'project', type=str,
        help='OSSPI Project name for storing scan results.')
    subparser.add_argument(
        'api_key', type=str,
        help='OSSPI API Key for Dashboard interactions.')

    subparser = subparsers_osspi_scan.add_parser(
        'osm',
        help='Scan for OSM inventory profile.',
        parents=[opt_osspi_scan_common])
    subparser.add_argument(
        '--output', type=str,
        help='Report file name (file extention depends on the `SCANNER`).')

    subparser = subparsers.add_parser(
        'get-osspi-scan',
        help='Fetch scan result from OSSPI Dashboard.')
    subparser.add_argument(
        '--branch', type=str,
        help='OSSPI Project Branch name, when there are multiple OSSPI '
             'Projects with the same name for different Product Releases '
             '(Build Branches).')
    subparser.add_argument(
        '--audit-id', type=int,
        help='OSSPI Audit ID of the report to process, take the latest report '
             'if no ID is given.')
    subparser.add_argument(
        'project', type=str,
        help='OSSPI Project name for fetching scan results.')
    subparser.add_argument(
        'api_key', type=str,
        help='OSSPI API Key for Dashboard interactions.')
    subparser.add_argument(
        'output', type=str,
        help='Filename (JSON) to store the fetched data.')

    opt_report_common = argparse.ArgumentParser(add_help=False)
    _parse_args_report(opt_report_common)

    subparser = subparsers.add_parser(
        'dev-report',
        help='Create a security vulnerability report for developers.',
        parents=[opt_report_common])

    subparser = subparsers.add_parser(
        'rel-report',
        help='Create a security vulnerability report for developers.',
        parents=[opt_report_common])
    subparser.add_argument(
        '--no-col-service', action='store_true',
        help='Omit `service` column.')

    subparser = subparsers.add_parser(
        'post-report',
        help='Post a report to a Confluence page as an attachment.')
    subparser.add_argument(
        'report', type=str, help='Filename to attach to Confluence page.')
    subparser.add_argument(
        'page_id', type=str,
        help='Confluence page ID for uploading known vulnerabilities.')
    subparser.add_argument(
        'user', type=str,
        help='Confluence username for upload ''authentication.')
    subparser.add_argument(
        'password', type=str,
        help='Confluence password for upload authentication.')

    return parser.parse_args()


def _parse_args_get_build_url(parser):
    parser.add_argument(
        '--sub-product', type=str,
        help='Name of the sub-product (some product may deliver several '
             'deliverable artifacts).')
    parser.add_argument(
        '--auth', type=str,
        help='Authentication parameter for querying artifact. Depending on '
             'the artifact storage type and/or location, it may not be '
             'needed. If needed, the format of the authentication depends on '
             'the server used for query. For basic authentication, use '
             '`<username>:<password>` format. For token, use `<token>` '
             'format.')
    parser.add_argument(
        '--release', type=str,
        help='Release identifier for the product, example "2.0.1". Use '
             f'"{MAIN_VER}" or omit this parameter to indicate that the '
             '"main" branch version is wanted. If omitted and the product '
             'supports automatic query, it will be used to obtain the latest '
             f'release version, otherwise the "{MAIN_VER}" will be assumed.')
    parser.add_argument(
        '--extra-q-pars', action='append', default=[],
        type=_parse_args_get_build_url_extra_q_pars,
        help='Extra query parameters, in form of "<qParName>=<qParVal>". Can '
             'be specified multiple times, as needed.')
    parser.add_argument(
        '--build-id', type=int,
        help='Build ID of the artifact to scan.')


def _parse_args_get_build_url_extra_q_pars(value):
    q_par_pair = value.split('=')
    if len(q_par_pair) != 2:
        raise ValueError(value)
    return tuple(q_par_pair)


def _parse_args_scan(parser):
    # Standard location: ${HOME}/.osspicli/osspi/osspi
    parser.add_argument(
        'toolpath', type=str, help='Path to the OSSPI scan tool binary.')
    parser.add_argument(
        'product', type=str,
        help='Product name, example "RIC" or "TCSA", to get the build URL '
             '(ignored if `--artifact-url` is given).')
    parser.add_argument(
        '--scanner', type=_parse_args_scan_scanner, default='binary',
        help='OSSPI scanner to use ['
             '"binary"(default), "docker", "signature"'
             ']. ')
    parser.add_argument(
        '--artifact-url', type=str,
        help='URL of the artifact to scan. For '
             '`SCANNER=="binary"`, the following: '
             '"http[s]://<server>[:<port>]/<path>", '
             '"file:///<path>" or "[/]<path>"; are supported. '
             'For `SCANNER=="docker"`, the following: '
             '"docker://<repoPaths>[(:<tag>|@<digest>)]", '
             '"file:///<path>" or "[/]<path>"; are supported. '
             'For `SCANNER=="signature"`, the following: '
             '"file:///<path>" or "[/]<path>"; are supported.')
    _parse_args_get_build_url(parser)
    parser.add_argument(
        '--wait-timeout', type=int, default=DEFAULT_OSSPI_SCAN_TIMEOUT_M,
        help='Scanning wait timeout in min.')
    parser.add_argument(
        '--no-osspi-dashboard', action='store_true',
        help='Do not upload the Scan Result to OSSPI Dashboard (ignored '
             'when `--scanner` is NOT set to `binary`).')
    parser.add_argument(
        '--oci-img-tag', type=str,
        help='Tag of the OCI Image. Used in `vuln` scan when `--scanner` is '
             'set to `docker` as extra information embedded in the '
             '`blackduct_path`.')


def _parse_args_scan_scanner(value):
    if value not in ('binary', 'docker', 'signature'):
        raise ValueError(value)
    return value


def _parse_args_report(parser):
    parser.add_argument(
        'project', type=str,
        help='OSSPI Project name for posting scan results.')
    parser.add_argument(
        'input', type=str, nargs='+',
        help='Input filenames (JSON) or directories (containing JSON files) '
             'that contains the vulnerability data.')
    parser.add_argument(
        '--known-vulnerabilities', nargs='+',
        type=_parse_args_report_known_vuln,
        help='Directories or files of collection of package vulnerabilities '
             'description and their known impact statements in JSON format '
             '(.json). It is possible to use Jinja Templating for JSON Object '
             'Value content (.json-jinja). Allowable value is '
             '`<dirPaths>[/[fileName.json]]` for plain JSON OR '
             '`<dirPath>/jinjaContext.yaml:<dirPpaths>'
             '[/[fileName.json-jinja]]` for JSON with Jinja Templating. '
             'Multiple locations are allowed and the first read prevail.')
    parser.add_argument(
        '--min-cvssv3', type=float, default=9.0,
        help='Include results in the scan report with CVSSv3 results meeting '
             'this minimum value.')
    parser.add_argument(
        '--product', type=str,
        help='Product name, example "RIC" or "TCSA", to support arbitrary '
             '`project`.')
    parser.add_argument(
        '--ignore-pkg-ver', action='store_true',
        help='Ignore package version in the Vuln. Report.')
    parser.add_argument(
        '--layer-map', type=str,
        help='File (YAML) containing Layer Mapping data.')
    parser.add_argument(
        '--sub-charted-sfx', type=str, default='',
        help="Sub-charted Service Name's suffix. If a service named `foo` is "
             'sub-charted and named `foo-bar`, then the suffix is `-bar` '
             '(NOTE: use `--opt=val`, so it is not treated as starting a new '
             "option), so the base Service Name can be known by subtracting "
             'the expected suffix given in here.')
    parser.add_argument(
        '--use-other-sub-charted-svcs', type=str, default='',
        help="List (comma-delimited) of other sub-charted Service Name's "
             'suffixes that their `known-vulnerabilities` information will be '
             'used. For ex. if a service named `foo` is sub-charted and named '
             'as `foo-bar`, to allow its `known-vulnerabilities` information '
             'to be used, put `,-bar` (NOTE: put `,` in front `-bar`, so it '
             'is not treated as starting a new option) as part of the list.')
    parser.add_argument(
        '--output', type=str,
        help='Filename to write report in CSV format.')


def _parse_args_report_known_vuln(value):
    files = value.split(':')

    if len(files) == 1:
        jinja_context = None
        json_file = files[0]
    elif len(files) == 2:
        jinja_context = files[0]
        json_file = files[1]
    else:
        raise ValueError(value)
    if (
            (jinja_context == '') or
            (json_file == '')
    ):
        raise ValueError(value)

    return (jinja_context, json_file)


def _query_release_artifactory(api_info, params, **kwargs):
    '''_query_release_artifactory gets the latest build no. from `artifactory`
    web server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
    '''
    cmd_args = kwargs.get('cmd_args')
    q_pars = dict(cmd_args.extra_q_pars)
    headers = kwargs.get('headers', {})
    release = ''

    if cmd_args.auth and (cmd_args.auth.find(':', 1, -1) != -1):
        auth_params = cmd_args.auth.split(':', 1)
    else:
        raise Exception('The specified product required `--auth` parameter '
                        'in form of `<username>:<password>`. Given: '
                        f'{cmd_args.auth}')

    url_params = api_info['urlParams'][MAIN_VER_RE]
    body_params = api_info['bodyParams'][MAIN_VER_RE]
    basic_auth = requests.auth.HTTPBasicAuth(*auth_params)
    rsp = requests.post(
        api_info['url'].format(**{**params, **url_params, **q_pars}),
        headers=headers.update({'Content-Type': 'text/plain'}),
        data=api_info['body'].format(**{**params, **body_params, **q_pars}),
        auth=basic_auth,
    )
    if rsp.status_code == 200:
        results = json.loads(rsp.text)['results']
        if results:
            file_name = results[0]['name']
            found = re.search(
                api_info['queryFuncData'][MAIN_VER_RE]['releaseCaptureRE'],
                file_name,
            )
            if found:
                release = found.group(1)
                logging.debug(f'Found release version: {release}')
            else:
                logging.warning(
                    'Failed to find latest release version, due to unexpected '
                    f'file name pattern: {file_name}'
                )
        else:
            logging.warning(
                'Failed to find latest release version, due to no result from '
                'query.'
            )
    else:
        logging.warning(f'Querying server for latest release failed: {rsp}')

    return release


def _query_release_harbor(api_info, params, **kwargs):
    '''_query_release_harbor gets the latest release ver. from `harbor`
    registry server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
    '''
    headers = kwargs.get('headers', {})
    release = ''

    url_params = api_info['urlParams'][MAIN_VER_RE]
    body_params = api_info['bodyParams'][MAIN_VER_RE]
    rsp = requests.get(
        api_info['url'].format(**{**params, **url_params}),
        data=api_info['body'].format(**{**params, **body_params}),
        headers=headers.update({
            'accept': 'application/json',
            'X-Accept-Vulnerabilities':
                'application/vnd.security.vulnerability.report; version=1.1, '
                'application/vnd.scanner.adapter.vuln.report.harbor+json; '
                'version=1.0',
        }),
    )
    if rsp.status_code == 200:
        results = json.loads(rsp.text)
        if results and results[0]['tags']:
            release = results[0]['tags'][0]['name'].split('-')[0]
            logging.debug(f'Found release version: {release}')
        else:
            logging.warning(
                'Failed to find latest release version, due to no result from '
                'query.'
            )
    else:
        logging.warning(f'Querying server for latest release failed: {rsp}')

    return release


def _query_build_artifactory(api_info, params, **kwargs):
    '''_query_build_artifactory gets the latest build no. from `artifactory`
    web server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
    '''
    cmd_args = kwargs.get('cmd_args')
    q_pars = dict(cmd_args.extra_q_pars)
    headers = kwargs.get('headers', {})
    build = -1

    if cmd_args.auth and (cmd_args.auth.find(':', 1, -1) != -1):
        auth_params = cmd_args.auth.split(':', 1)
    else:
        raise Exception('The specified product required `--auth` parameter '
                        'in form of `<username>:<password>`. Given: '
                        f'{cmd_args.auth}')

    url_params = _match_regex_key(api_info['urlParams'], params['relVer'])
    body_params = _match_regex_key(api_info['bodyParams'], params['relVer'])
    basic_auth = requests.auth.HTTPBasicAuth(*auth_params)
    rsp = requests.post(
        api_info['url'].format(**{**params, **url_params, **q_pars}),
        headers=headers.update({'Content-Type': 'text/plain'}),
        data=api_info['body'].format(**{**params, **body_params, **q_pars}),
        auth=basic_auth,
    )
    if rsp.status_code == 200:
        results = json.loads(rsp.text)['results']
        if results:
            file_name = results[0]['name']
            found = re.search(
                _match_regex_key(api_info['queryFuncData'], params['relVer'])[
                    'buildCaptureRE'
                ],
                file_name,
            )
            if found:
                build = int(found.group(1))
                logging.debug(f'Found build ID: {build}')
            else:
                logging.warning(
                    'Failed to find latest build ID, due to unexpected file '
                    f'name pattern: {file_name}'
                )
        else:
            logging.warning(
                'Failed to find latest build ID, due to no result from query.'
            )
    else:
        logging.warning(f'Querying server for latest build failed: {rsp}')

    return build


def _query_build_buildapi(api_info, params, **kwargs):
    '''_query_build_buildapi gets the latest build no. from `buildapi` web
    server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
    '''
    cmd_args = kwargs.get('cmd_args')
    q_pars = dict(cmd_args.extra_q_pars)
    build = -1

    url_params = _match_regex_key(api_info['urlParams'], params['relVer'])
    body_params = _match_regex_key(api_info['bodyParams'], params['relVer'])
    rsp = requests.get(
        api_info['url'].format(**{**params, **url_params, **q_pars}),
        data=api_info['body'].format(**{**params, **body_params, **q_pars}),
    )
    if rsp.status_code == 200:
        results = json.loads(rsp.text)['_list']
        if results:
            build = results[0]['id']
            logging.debug(f'Found build ID: {build}')
        else:
            logging.warning(
                'Failed to find latest build ID, due to no result from query.'
            )
    else:
        logging.warning(f'Querying server for latest build failed: {rsp}')

    return build


def _query_build_harbor(api_info, params, **kwargs):
    '''_query_build_harbor gets the latest build no. from `harbor` registry
    server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
    '''
    headers = kwargs.get('headers', {})
    build = -1

    url_params = api_info['urlParams'][MAIN_VER_RE]
    body_params = api_info['bodyParams'][MAIN_VER_RE]
    rsp = requests.get(
        api_info['url'].format(**{**params, **url_params}),
        data=api_info['body'].format(**{**params, **body_params}),
        headers=headers.update({
            'accept': 'application/json',
            'X-Accept-Vulnerabilities':
                'application/vnd.security.vulnerability.report; version=1.1, '
                'application/vnd.scanner.adapter.vuln.report.harbor+json; '
                'version=1.0',
        }),
    )
    if rsp.status_code == 200:
        results = json.loads(rsp.text)
        if results and results[0]['tags']:
            build = results[0]['tags'][0]['name']
            build = results[0]['tags'][0]['name'].split('-')[1]
            logging.debug(f'Found build ID: {build}')
        else:
            logging.warning(
                'Failed to find latest build ID, due to no result from query.'
            )
    else:
        logging.warning(f'Querying server for latest build failed: {rsp}')

    return build


def _query_repo_artifactory(api_info, params, **kwargs):
    '''_query_repo_artifactory verifies that a specific artifact is available
    from `artifactory` web server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
'''
    # pylint: disable=too-many-locals
    cmd_args = kwargs.get('cmd_args')
    q_pars = dict(cmd_args.extra_q_pars)
    get_reg_url = kwargs.get('getRegistryURL', False)
    url = ''
    auth = ('basic', cmd_args.auth)

    if cmd_args.auth and (cmd_args.auth.find(':', 1) != -1):
        auth_params = cmd_args.auth.split(':', 1)
    else:
        raise Exception('The specified product required `--auth` parameter '
                        'in form of `<username>:<password>`. Given: '
                        f'{cmd_args.auth}')

    url_params = _match_regex_key(api_info['urlParams'], params['relVer'])
    body_params = _match_regex_key(api_info['bodyParams'], params['relVer'])
    basic_auth = requests.auth.HTTPBasicAuth(*auth_params)
    rsp = requests.post(
        api_info['url'].format(**{**params, **url_params, **q_pars}),
        headers={'Content-Type': 'text/plain'},
        data=api_info['body'].format(**{**params, **body_params, **q_pars}),
        auth=basic_auth,
    )
    if rsp.status_code == 200:
        results = json.loads(rsp.text)['results']
        found = 0
        for info in results:
            if found == 1:
                logging.warning(
                    f"Found multiple file with build no: {params['buildNo']}",
                )
                logging.warning(f'  - {url}')
            found += 1
            url = (
                f"{urllib.parse.urljoin(api_info['url'], '/')}{info['repo']}/"
                f"{info['path']}/{info['name']}"
            )
            if found > 1:
                logging.warning(f'  - {url}')
                url = ''
        if not found:
            logging.warning(
                f"Failed to find file with build no: {params['buildNo']}",
            )
    else:
        logging.warning(f'Querying server for URL failed: {rsp}')

    if get_reg_url:
        url_info = urllib.parse.urlparse(url)
        # .path = f'/{reg_svr_pfx}/{nmspc...}/{repo}/{tag}'
        url_paths = url_info.path.split('/')
        # Construct: reg_svr = <reg_svr_pfx>.<artifactory_svr>
        reg_svr = f'{url_paths[1]}.{url_info.netloc}'
        nmspc = '/'.join(url_paths[2:-2])   # The `nmspc` may contains '/'.
        repo = url_paths[-2]
        tag = url_paths[-1]
        # Construct: docker://<reg_svr>/<nmspc...>/<repo>:<tag>
        url = url_info._replace(
            scheme='docker',
            netloc=reg_svr,
            path=f'/{nmspc}/{repo}:{tag}',
        ).geturl()

    return (urllib.parse.urlparse(url), auth)


def _query_repo_buildweb(api_info, params, **kwargs):
    '''_query_repo_buildweb verifies that a specific artifact is available from
    `buildweb` web server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
'''
    _ = kwargs
    url = ''

    url_params = _match_regex_key(api_info['urlParams'], params['relVer'])
    url = api_info['url'].format(**{**params, **url_params})

    return (urllib.parse.urlparse(url), ())


def _query_repo_harbor(api_info, params, **kwargs):
    '''_query_repo_harbor verifies that a specific artifact is available from
    `harbor` registry server.

    See `PRODUCT_BUILD_REPO` for details on `Args` and `Return`.
'''
    cmd_args = kwargs.get('cmd_args')
    url = ''

    if cmd_args.auth and (cmd_args.auth.find(':', 1) == -1):
        raise Exception('The specified product required `--auth` parameter '
                        'in form of `<username>:<password>`. Given: '
                        f'{cmd_args.auth}')

    url_params = api_info['urlParams'][MAIN_VER_RE]
    url = api_info['url'].format(**{**params, **url_params})

    url_info = urllib.parse.urlparse(url)
    # .path =   f'/api/v2.0/projects/{nmspc_prjPart}/repositories/'
    #           f'{nmspc_pathPart...}/{repo}/artifacts'
    url_paths = url_info.path.split('/')
    # Construct: nmspc = <nmspc_prjPart>/<nmspc_pathPart...>
    #   The `nmspc_pathPart` may contains '/'.
    nmspc = '/'.join((url_paths[4:5] + url_paths[6:-2]))
    repo = url_paths[-2]
    # .query = f'q=tags%3D{tag}}&page=1&page_size=1&with_tag=true'
    tag = urllib.parse.parse_qs(url_info.query)['q'][0].split('=')[1]
    # Construct: docker://<regSvr>/<ns...>/<repo>:<tag>
    url = url_info._replace(
        scheme='docker',
        path=f'/{nmspc}/{repo}:{tag}',
        query=''
    ).geturl()

    return (urllib.parse.urlparse(url), ('basic', cmd_args.auth))


def _requests_osspi(cmd_args, method, args=(), kwargs=None,
                    retry_max=6, retry_wait=10):
    '''_requests_osspi send HTTP Request with retry if receives HTTP Response
    5xx.

    Args:
        cmd_args (argparse.Namespace):  Command line arguments.
            The attributes of interest:
                api_key (str):  OSSPI API Key for Dashboard interactions.
        method (requests.api):  The `requests` method.
        args (tuple):           List Arguments to the `requests` method.
        kwargs (dict):          Keyword Arguments to the `requests` method.
        retry_max:              Max. no. retry.
        retry_wait:             Wait time between retry (in sec.).
    Return:
        (requests.Response):    The `requests` response.
    '''
    if kwargs is None:
        kwargs = {}
    headers = kwargs.get('headers', {})
    headers['Authorization'] = f'Token {cmd_args.api_key}'
    kwargs['headers'] = headers
    rsp = None
    count = 0
    while count <= retry_max:
        if count:
            logging.debug(f'Retrying: {count} ...')
        rsp = method(*args, **kwargs)
        if (rsp.status_code // 100) == 5:
            count += 1
            time.sleep(retry_wait)
            continue
        break
    return rsp


def _setup_logging(stdout_lvl=logging.DEBUG):
    formatter = logging.Formatter('%(asctime)-15s %(levelname)s: %(message)s')

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(stdout_lvl)
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

    file_handler = logging.FileHandler('inspector_gadget.log', mode='w')
    file_handler.setLevel(stdout_lvl)
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)

    logging.getLogger().setLevel(stdout_lvl)


def _url_exists(url, auth):
    '''_url_exists checks whether or not the given url exists

    Args:
        url (urllib.parse.urlparse):    The URL to check for existence.
        auth (tuple):   The URL Authentication Method.
                        No Authentication:      ()
                        Basic Authentication:   ('basic', f'{usr}:{pwd}')
                        Token Authentication:
                            ('token', {httpHeaderName: httpHeaderValue})
    Returns:
        (str): Real final URL if exist, otherwise empty string.
    '''
    if url.scheme == 'docker':
        # URL: docker://<regSvr>/<ns_repo>:<tag>
        (ns_repo, tag) = url.path.rsplit(':', 1)
        url_str = url._replace(
            scheme='https',
            path=f'/v2{ns_repo}/manifests/{tag}',
        ).geturl()
    elif url.scheme in ('http', 'https'):
        url_str = url.geturl()
    else:
        raise Exception(f'Unsupported URL Scheme: {url.netloc}')

    if auth:
        if auth[0] == 'basic':
            req_params = {
                'auth': requests.auth.HTTPBasicAuth(*auth[1].split(':', 1)),
            }
        elif auth[0] == 'token':
            req_params = {'headers': auth[1]}
    else:
        req_params = {}

    logging.debug(f"Checking URL for existence: {url_str}")
    req = requests.head(url_str, allow_redirects=True, **req_params)
    if req.status_code == 200:
        logging.debug(f"URL exists: {url_str}")
        return req.url  # Return final URL, in case of redirection occurs.
    logging.debug(f"URL does not exist: {url_str}: {req}")
    return ''


if __name__ == '__main__':
    sys.exit(main())
