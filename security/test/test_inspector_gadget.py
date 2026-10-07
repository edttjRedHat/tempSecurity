#!/usr/bin/env python3

import argparse
from collections import namedtuple
import copy
import sys
from unittest import mock

import pytest

from . import utils
from .. import inspector_gadget as ig


TEST_ARGS = [
    './inspector_gadget.py',
    '-v',
    '--prod-cfg', 'conf.yml',
    '--log-level', '20,-1',
    'install-osspi',
    'https://ossspi.com/',
]


def test_cmd_dev_report(monkeypatch: object) -> None:
    utils.auto_patch(monkeypatch, ig, 'load_known_vulnerabilities')
    utils.auto_patch(monkeypatch, ig, 'read_merge_audit_result')
    utils.auto_patch(monkeypatch, ig, 'write_dev_report_csv')
    cmd_args = argparse.Namespace(
        dry_run=True,
        known_vulnerabilities='kvFile', output='outFile',
    )

    # Dry Run.
    ig.cmd_dev_report(cmd_args)
    ig.write_dev_report_csv.assert_not_called()

    # Real Run.
    cmd_args.dry_run = False
    ig.cmd_dev_report(cmd_args)
    ig.write_dev_report_csv.assert_called_once()


def test_cmd_rel_report(monkeypatch: object) -> None:
    utils.auto_patch(monkeypatch, ig, 'load_known_vulnerabilities')
    utils.auto_patch(monkeypatch, ig, 'read_merge_audit_result')
    utils.auto_patch(monkeypatch, ig, 'write_rel_report_csv')
    cmd_args = argparse.Namespace(
        dry_run=True,
        known_vulnerabilities='kvFile', output='outFile',
    )

    # Dry Run.
    ig.cmd_rel_report(cmd_args)
    ig.write_rel_report_csv.assert_not_called()

    # Real Run.
    cmd_args.dry_run = False
    ig.cmd_rel_report(cmd_args)
    ig.write_rel_report_csv.assert_called_once()


def test_cmd_get_osspi_scan(monkeypatch: object) -> None:
    utils.auto_patch(monkeypatch, ig, 'osspi_fetch_latest_success_audit_id')
    cmd_args = argparse.Namespace(
        dry_run=True, audit_id=None,
        project='SDP_SP-Mainline', output='f',
    )

    # Dry Run.
    with monkeypatch.context() as mp:
        import logging
        utils.auto_patch(mp, logging, 'debug')
        ig.cmd_get_osspi_scan(cmd_args)
        logging.debug.assert_called_once_with(
            'Dry Run: fetching packages vulnerabiltiies skipped',
        )

    # Real Run.
    with mock.patch('builtins.open'):
        import json
        utils.auto_patch(monkeypatch, json, 'dump')
        utils.auto_patch(monkeypatch, ig, 'osspi_fetch_vulnerable_packages')
        ig.osspi_fetch_vulnerable_packages.return_value = {
            '10': {'id': 10},
        }
        cmd_args.dry_run = False
        ig.cmd_get_osspi_scan(cmd_args)
        json.dump.assert_called_once_with(
            ig.osspi_fetch_vulnerable_packages.return_value,
            mock.ANY, indent=4,
        )


def test_load_known_vulnerabilities(monkeypatch: object) -> None:
    def m_lfp(pl, k, fl, fn):
        _, _ = k, fl
        fn[0](pl, *fn[1], **fn[2])

    utils.auto_patch(monkeypatch, ig, '_load_from_paths')
    cmd_args = argparse.Namespace(
        known_vulnerabilities=None, ignore_pkg_ver=True,
        sub_charted_sfx='-sub1', use_other_sub_charted_svcs=',-sub2',
    )

    ig._load_from_paths.side_effect = m_lfp
    with mock.patch('builtins.open'):
        import json
        import logging
        import pathlib
        import yaml
        utils.auto_patch(monkeypatch, logging, 'warning')
        known_vuln = [{
            'service_name': 'svcName-sub1',
            'image_name': 'imgName',
            'package_name': 'pkgName-v0',
            'cve': 'CVE-YYYY-NNNNN',
            'impact_summary': 'Not Exploitable',
            'impact_analysis': 'N/A',
        }, {
            'imgpkg': 'svcName-sub2',
            'third_party_library': 'pkgName-v0',
            'cve_id': 'CVE-YYYY-NNNNN',
            'impact_summary': 'Not Exploitable',
            'impact_analysis': 'N/A',
        }]
        vuln = {
            ('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN'):
                ig.KnownVulnerability(
                    'svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN',
                    'Not Exploitable', 'N/A',
                ),
            ('svcName', '', 'pkgName', 'CVE-YYYY-NNNNN'):
                ig.KnownVulnerability(
                    'svcName', '', 'pkgName', 'CVE-YYYY-NNNNN',
                    'Not Exploitable', 'N/A',
                ),
        }
        jCtx = yaml.safe_load(ig.KNOWN_VULN_IMPACT_SUMMARY)

        # Using plain file.
        utils.auto_patch(monkeypatch, json, 'load')
        cmd_args.known_vulnerabilities = [(None, 'jsonFile')]
        json.load.return_value = known_vuln
        assert ig.load_known_vulnerabilities(cmd_args) == vuln
        logging.warning.assert_not_called()

        # Using Jinja Template.
        cmd_args.known_vulnerabilities = [('jinjaCtx', 'jinjaTempl')]
        del known_vuln[0]['image_name']
        del vuln[('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN')]
        with mock.patch.object(pathlib.Path, 'is_file') as m_is_file:
            import jinja2
            utils.auto_patch(monkeypatch, jinja2, 'Environment')
            utils.auto_patch(monkeypatch, json, 'loads')
            utils.auto_patch(monkeypatch, yaml, 'safe_load')

            json.loads.return_value = known_vuln

            # Jinja Context file exist.
            m_is_file.return_value = True
            yaml.safe_load.side_effect = [jCtx, {}]
            assert ig.load_known_vulnerabilities(cmd_args) == vuln
            logging.warning.assert_called_once()
            logging.warning.reset_mock()

            # Jinja Context file does not start with Map.
            yaml.safe_load.side_effect = [jCtx, []]
            with pytest.raises(Exception) as exc:
                ig.load_known_vulnerabilities(cmd_args)
            assert str(exc.value) == \
                'Jinja Context file (YAML) Top Level must be Map: jinjaCtx'

            # Jinja Context file does not exist.
            m_is_file.return_value = False
            yaml.safe_load.side_effect = [jCtx, {}]
            with pytest.raises(Exception) as exc:
                ig.load_known_vulnerabilities(cmd_args)
            assert str(exc.value) == 'Invalid Jinja Context file: jinjaCtx'

        # The known_vulnerabilities file does not exist.
        open.side_effect = FileNotFoundError()
        with pytest.raises(FileNotFoundError):
            ig.load_known_vulnerabilities(cmd_args)

        # The known_vulnerabilities file is an invalid JSON file.
        open.side_effect = json.decoder.JSONDecodeError('', '{}', 0)
        with pytest.raises(json.decoder.JSONDecodeError):
            ig.load_known_vulnerabilities(cmd_args)


def test_osspi_fetch_latest_success_audit_id(monkeypatch: object) -> None:
    import requests
    utils.auto_patch(monkeypatch, requests.Response, 'json')
    utils.auto_patch(monkeypatch, ig, '_requests_osspi')
    rsp = requests.Response()
    cmd_args = argparse.Namespace(project='SDP SP', branch='main')

    # Successful case.
    ig._requests_osspi.return_value = rsp
    requests.Response.json.return_value = {
        'results': [{
            'id': 123,
            'product': 'SDP SP',
            'branch': 'main',
            'latest_success_audit': 456,
        }],
    }
    rsp.status_code = 200
    assert ig.osspi_fetch_latest_success_audit_id(
        cmd_args,
    ) == 456

    # Failed case.
    rsp.status_code = 204
    assert ig.osspi_fetch_latest_success_audit_id(
        cmd_args,
    ) == -1


def test_osspi_fetch_package(monkeypatch: object) -> None:
    import requests
    utils.auto_patch(monkeypatch, requests.Response, 'json')
    utils.auto_patch(monkeypatch, ig, '_requests_osspi')
    rsp = requests.Response()
    cmd_args = argparse.Namespace(project='SDP SP', branch='main')

    # Successful case.
    ig._requests_osspi.return_value = rsp
    requests.Response.json.return_value = {}
    rsp.status_code = 200
    assert ig.osspi_fetch_package(
        cmd_args, '123', 'https://localhost',
    ) == {}

    # Failed case.
    rsp.status_code = 204
    with pytest.raises(Exception) as exc:
        ig.osspi_fetch_package(
            cmd_args, '123', 'https://localhost',
        )
    assert str(exc.value) == \
        'Unexpected response when fetching package 123: status 204'


def test_osspi_fetch_vulnerable_packages(monkeypatch: object) -> None:
    utils.auto_patch(monkeypatch, ig, '_fetch_multi_pages_osspi')
    utils.auto_patch(monkeypatch, ig, 'osspi_fetch_package')
    cmd_args = argparse.Namespace()

    ig._fetch_multi_pages_osspi.return_value = [{
        'uid': 0,
        'links': {'package': 'https://localhost/package/10/'},
    }, {
        'uid': 1,
        'links': {'package': 'https://localhost/package/11/'},
    }, {
        'uid': 2,
        'links': {'package': 'https://localhost/package/10/'},
    }]
    ig.osspi_fetch_package.side_effect = [{
        'id': 10,
    }, {
        'id': 11,
    }]
    assert ig.osspi_fetch_vulnerable_packages(
        cmd_args, 123
    ) == {'10': {'id': 10}, '11': {'id': 11}}


def test_osspi_merge_vuln_with_known(monkeypatch: object) -> None:
    utils.auto_patch(monkeypatch, ig, '_jira_create_issue_link')
    url = 'https://jira.com/'
    cmd_args = argparse.Namespace(project='PrjName', sub_charted_sfx='Name')
    osspi = {
        ('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN'):
            ig.OsspiVulnerability(
                '0', 'svcName:0.0.0-0', 'imgName:0.0', 'pkgName',
                8.0, 'CVE-YYYY-NNNNN', 'https://cve.com/CVE-YYYY-NNNNN', '',
                'path/to/file1',
            ),
    }
    vuln_data = ig.dataclasses.asdict(list(osspi.values())[0])

    # Is sub-charted and unjustified vulnerability.
    ig._jira_create_issue_link.return_value = url
    assert ig.osspi_merge_vuln_with_known(cmd_args, osspi, None) == {
        ('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN'): {
            **vuln_data,
            **{
                'impact_summary': '',
                'impact_analysis': f'[Create Jira|{url}]',
                'custom': '',
            },
        },
    }

    # Not sub-charted and justified vulnerability.
    cmd_args.sub_charted_sfx = None
    assert ig.osspi_merge_vuln_with_known(cmd_args, osspi, {
        ('svcName', '', 'pkgName', 'CVE-YYYY-NNNNN'): ig.KnownVulnerability(
            'svcName', '', 'pkgName', 'CVE-YYYY-NNNNN',
            'Not Exploitable', 'N/A',
        ),
    }) == {
        ('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN'): {
            **vuln_data,
            **{
                'impact_summary': 'Not Exploitable',
                'impact_analysis': 'N/A',
                'custom': '',
            },
        },
    }


def test_osspi_packages_vulnerabilities(monkeypatch: object) -> None:
    import logging
    import textwrap
    utils.auto_patch(monkeypatch, logging, 'warning')
    monkeypatch.setattr(
        ig, '_get_svc_and_ctr_img_name',
        mock.MagicMock(), False,
    )
    monkeypatch.setattr(ig, 'BLACKDUCK_PATH_RE', {})
    monkeypatch.setattr(ig, 'PROD_CFG', {
        'ProductDataOverrides': {
            'BLACKDUCK_PATH_RE': {
                'PRD': textwrap.dedent(r'''
                    # prodName_0.0.0-0.tgz#
                    r'prodName_([\d.]+)-(\d+)[^#]+#'
                    # interimPath/svcName_0.0.0-0.tar#
                    r'(?:[^/#]+/)+([^#]+?)_(?:[\d.]+-\d+)\.tar()#'
                    # sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tar.gz#   # noqa: E501
                    r'sha256-([0-9a-f]{64})\.tar\.gz#'
                    # /path/to/file
                    r'(.+)'
                '''.lstrip('\n'))
            },
        },
    })
    monkeypatch.setattr(ig, 'MAPPER', namedtuple(
        'MAPPER', 'svcName getSvcAndCtrImgNameFunc',
    )({
        'PRD': {'svcNameAlias': 'svcName'},
    }, {
        'PRD': '_get_svc_and_ctr_img_name',
    }))
    cmd_args = argparse.Namespace(ignore_pkg_ver=True)
    packages = {
        '0': {
            'package': 'pkgName',
            'blackduck_paths': [
                'prodName_0.0.0-0.tgz#'
                'interimPath/svcNameAlias_0.0.0-0.tar#'
                'sha256-123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0.tar.gz#'   # noqa: E501
                'path/to/file1',
            ],
            'vulnerabilities': [{
                'uid': 'CVE-YYYY-NNNNN',
                'cvss3_basescore': 8.0,
                'json': {'link': 'https://cve.com/CVE-YYYY-NNNNN'},
            }],
        },
        '1': {
            'package': 'pkgName-0.0.0-0',
            'blackduck_paths': [
                'prodName_0.0.0-0.tgz#'
                'interimPath/svcName_0.0.0-0.tar#'
                'sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tar.gz#'   # noqa: E501
                'path/to/file1',
                'prodName_0.0.0-0.tgz#'
                'interimPath/svcName_0.0.0-0.tar#'
                'sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tar.gz#'   # noqa: E501
                'path/to/file2',
            ],
            'vulnerabilities': [{
                'uid': 'CVE-YYYY-NNNNN',
                'cvss3_basescore': 8.0,
                'json': {'link': 'https://cve.com/CVE-YYYY-NNNNN'},
            }],
        },
    }

    # Loading vulnerabilities with Layer Mapping data and duplicated package.
    ig._get_svc_and_ctr_img_name.return_value = \
        ((('imgName', ':0.0'), [('svcName', ':0.0.0-0')]),)
    assert ig.osspi_packages_vulnerabilities(
        cmd_args, packages, 'PRD',
    ) == ({
        ('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN'):
            ig.OsspiVulnerability(
                '0', 'svcName:0.0.0-0', 'imgName:0.0', 'pkgName',
                8.0, 'CVE-YYYY-NNNNN', 'https://cve.com/CVE-YYYY-NNNNN', '',
                'path/to/file1, path/to/file2',
            ),
    }, '0.0.0', '0')
    logging.warning.assert_called_once_with(
        'DUPLICATE package vulnerability: '
        "('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN')",
    )
    logging.warning.reset_mock()

    # Loading vulnerabilities without Layer Mapping data and non-matching path.
    ig.MAPPER = ig.MAPPER._replace(getSvcAndCtrImgNameFunc={})
    packages['0']['blackduck_paths'] = ['invalidPath']
    assert ig.osspi_packages_vulnerabilities(
        cmd_args, packages, 'PRD',
    ) == ({
        ('svcName', '', 'pkgName', 'CVE-YYYY-NNNNN'):
            ig.OsspiVulnerability(
                '0', 'svcName', '', 'pkgName',
                8.0, 'CVE-YYYY-NNNNN', 'https://cve.com/CVE-YYYY-NNNNN', '',
                'path/to/file1, path/to/file2',
            ),
    }, '0.0.0', '0')
    logging.warning.assert_called_once_with('Non-matching path=invalidPath')
    logging.warning.reset_mock()

    # Loading vulnerabilities with CVE Score filtering.
    assert ig.osspi_packages_vulnerabilities(
        cmd_args, packages, 'PRD', 9,
    ) == ({}, '0.0.0', '0')


def test_read_merge_audit_result(monkeypatch: object) -> None:
    def m_lfp(pl, k, fl, fn):
        _, _ = k, fl
        fn[0](pl, *fn[1], **fn[2])

    utils.auto_patch(monkeypatch, ig, '_load_from_paths')
    utils.auto_patch(monkeypatch, ig, '_osspi_project_to_prod_id')
    utils.auto_patch(monkeypatch, ig, 'osspi_packages_vulnerabilities')
    utils.auto_patch(monkeypatch, ig, 'osspi_merge_vuln_with_known')
    monkeypatch.setattr(ig, 'ALL_OSSPI_PROJECTS', ['PrjName'])
    cmd_args = argparse.Namespace(
        project='PrjName', input=['filePath'],
        product='PRD', min_cvssv3=0.0,
    )
    merged_vuln = {
        ('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN'): {
            'build_num': '0', 'service_name': 'svcName:0.0.0-0',
            'image_name': 'imgName:0.0', 'package_name': 'pkgName',
            'cvssv3': 8.0, 'cve': 'CVE-YYYY-NNNNN',
            'cve_link': 'https://cve.com/CVE-YYYY-NNNNN', 'cve_desc': '',
            'file_paths': 'path/to/file',
            'impact_summary': 'Not Exploitable', 'impact_analysis': 'N/A',
            'custom': '',
        },
    }

    ig._load_from_paths.side_effect = m_lfp
    with mock.patch('builtins.open'):
        import json
        utils.auto_patch(monkeypatch, json, 'load')

        json.load.return_value = {'0': {
            'package': 'pkgName',
            'blackduck_paths': ['topLevelArchive#interimPath#/path/to/file'],
            'vulnerabilities': [{
                'uid': 'CVE-YYYY-NNNNN',
                'cvss3_basescore': 8.0,
                'json': {'link': 'https://cve.com/CVE-YYYY-NNNNN'},
            }],
        }}
        ig.osspi_packages_vulnerabilities.return_value = ({
            ('svcName', 'imgName', 'pkgName', 'CVE-YYYY-NNNNN'):
                ig.OsspiVulnerability(
                    '0', 'svcName:0.0.0-0', 'imgName:0.0', 'pkgName',
                    8.0, 'CVE-YYYY-NNNNN', 'https://cve.com/CVE-YYYY-NNNNN',
                    '', 'path/to/file',
                ),
        }, '0.0.0', '0')
        ig.osspi_merge_vuln_with_known.return_value = merged_vuln

        # Product is given from CLI.
        assert ig.read_merge_audit_result(cmd_args, {}) == merged_vuln

        # Product is derived from OSSPI Project Name.
        cmd_args.product = None
        ig._osspi_project_to_prod_id.return_value = 'PRD'
        assert ig.read_merge_audit_result(cmd_args, {}) == merged_vuln

        # Unsupported Product.
        cmd_args.project = 'Unsupported'
        with pytest.raises(Exception) as exc:
            ig.read_merge_audit_result(cmd_args, {})
        assert str(exc.value) == 'Unsupported project for packages ' \
            'vulnerabilities inspection: Unsupported'

        # The OSSPI scan results file does not exist.
        open.side_effect = FileNotFoundError()
        with pytest.raises(FileNotFoundError):
            ig.read_merge_audit_result(cmd_args)

        # The OSSPI scan results file is an invalid JSON file.
        open.side_effect = json.decoder.JSONDecodeError('', '{}', 0)
        with pytest.raises(json.decoder.JSONDecodeError):
            ig.read_merge_audit_result(cmd_args)


def test_write_dev_report_csv(monkeypatch: object) -> None:
    import csv
    import logging
    utils.auto_patch(monkeypatch, csv, 'DictWriter')
    utils.auto_patch(monkeypatch, logging, 'error')
    utils.auto_patch(monkeypatch, ig, '_osspi_confluence_wikisafe')
    cmd_args = argparse.Namespace(output='')

    # Invalid file path as argument to `--ouput`.
    ig.write_dev_report_csv(cmd_args, {})
    logging.error.assert_called_once_with(
        'A valid file path is required for option `--output`.',
    )
    logging.error.reset_mock()
    ig._osspi_confluence_wikisafe.assert_not_called()

    with mock.patch('builtins.open'):
        # Empty vulnerabilities.
        cmd_args.output = 'report.csv'
        ig.write_dev_report_csv(cmd_args, {})
        ig._osspi_confluence_wikisafe.assert_not_called()

        # Some vulnerabilities.
        ig.write_dev_report_csv(cmd_args, {('s', 'p', 'c'): {}})
        ig._osspi_confluence_wikisafe.assert_called_once()


def test_write_rel_report_csv(monkeypatch: object) -> None:
    import csv
    import logging
    utils.auto_patch(monkeypatch, csv, 'DictWriter')
    utils.auto_patch(monkeypatch, logging, 'error')
    utils.auto_patch(monkeypatch, ig, '_osspi_confluence_wikisafe')
    cmd_args = argparse.Namespace(output='', no_col_service=False)
    vuln = {
        ('svcName', 'pkgName', 'CVE-YYYY-NNNNN'): {
            'build_num': '0', 'service_name': 'svcName:0.0.0-0',
            'image_name': 'imgName:0.0', 'package_name': 'pkgName',
            'cvssv3': 8.0, 'cve': 'CVE-YYYY-NNNNN',
            'cve_link': 'https://cve.com/CVE-YYYY-NNNNN', 'cve_desc': '',
            'file_paths': 'path/to/file',
            'impact_summary': 'No Impact', 'impact_analysis': 'Create Jira',
            'custom': '',
        },
    }

    # Invalid file path as argument to `--ouput`.
    ig.write_rel_report_csv(cmd_args, {})
    logging.error.assert_called_once_with(
        'A valid file path is required for option `--output`.',
    )
    logging.error.reset_mock()
    ig._osspi_confluence_wikisafe.assert_not_called()

    with mock.patch('builtins.open'):
        # Empty vulnerabilities.
        cmd_args.output = 'report.csv'
        ig.write_rel_report_csv(cmd_args, {})
        ig._osspi_confluence_wikisafe.assert_not_called()

        # Some vulnerabilities.
        ig.write_rel_report_csv(cmd_args, vuln)
        assert ig._osspi_confluence_wikisafe.call_count == 2


def test_main(monkeypatch: object) -> None:
    utils.auto_patch(monkeypatch, ig, '_setup_logging')
    utils.auto_patch(monkeypatch, ig, 'cmd_install_osspi')

    # Test config file.
    with mock.patch.object(
            sys,
            'argv',
            TEST_ARGS,
    ):
        import pathlib

        with mock.patch.object(pathlib.Path, 'is_file') as m_is_file:
            # Config file exists.
            m_is_file.return_value = True
            with mock.patch('builtins.open'):
                import yaml
                utils.auto_patch(monkeypatch, yaml, 'safe_load')
                yaml.safe_load.return_value = {}
                ig.main()

            # Config file does not exist.
            m_is_file.return_value = False
            with pytest.raises(Exception):
                ig.main()


def test_append_str_to_filename() -> None:
    assert str(ig._append_str_to_filename('/path/to/file', '-sfx')) == \
        '/path/to/file-sfx'
    assert str(ig._append_str_to_filename('/path/to/name.ext', '-sfx')) == \
        '/path/to/name-sfx.ext'
    assert str(ig._append_str_to_filename(
        '/path/to/name.ext1.ext2.ext3', '-sfx',
    )) == '/path/to/name-sfx.ext1.ext2.ext3'


def test_drop_pkg_ver() -> None:
    assert ig._drop_pkg_ver('pkg_V0') == 'pkg_V0'
    assert ig._drop_pkg_ver('pkg-V0') == 'pkg'
    assert ig._drop_pkg_ver('pkg-v0.0.0-000') == 'pkg'
    assert ig._drop_pkg_ver('pkg-0.0.0-0.os0') == 'pkg'
    assert ig._drop_pkg_ver('pkg-1.0.0+really0.0.0-0') == 'pkg'
    assert ig._drop_pkg_ver('pkg-0:0.0.0') == 'pkg'
    assert ig._drop_pkg_ver('pkg-0.0.0~osName00u0') == 'pkg'


def test_fetch_multi_pages_osspi(monkeypatch: object) -> None:
    import requests
    utils.auto_patch(monkeypatch, requests.Response, 'json')
    utils.auto_patch(monkeypatch, ig, '_requests_osspi')
    rsp1 = requests.Response(); rsp1.status_code = 200  # noqa: E702
    rsp2 = requests.Response(); rsp2.status_code = 200  # noqa: E702
    rsp3 = requests.Response(); rsp3.status_code = 204  # noqa: E702
    cmd_args = argparse.Namespace()

    # Successful case.
    ig._requests_osspi.side_effect = [rsp1, rsp2]
    requests.Response.json.side_effect = [{
        'next': 'https:/localhost/next',
        'foo': {'bar': [0]},
    }, {
        'next': None,
        'foo': {'bar': [1]},
    }]
    assert ig._fetch_multi_pages_osspi(
        cmd_args, 'https:/localhost/first', ('foo', 'bar'),
    ) == [0, 1]

    # Failed case.
    ig._requests_osspi.side_effect = [rsp3]
    with pytest.raises(Exception) as exc:
        ig._fetch_multi_pages_osspi(
            cmd_args, 'https:/localhost/first', ('foo', 'bar'),
        )
    assert str(exc.value) == \
        'Unexpected response when fetching multi-page data: status 204'


def test_jira_create_issue_link(monkeypatch: object) -> None:
    utils.auto_patch(monkeypatch, ig, '_osspi_project_to_prod_id')
    monkeypatch.setattr(ig, 'ALL_OSSPI_PROJECTS', ['PrjName'])
    monkeypatch.setattr(ig, 'JIRA_PID', {'PRD': 0})
    monkeypatch.setattr(ig, 'JIRA_EXTRAS', {'PRD': ''})
    cmd_args = argparse.Namespace(project='PrjName', product='PRD')
    url = f'{ig.JIRA_BASE_URL}/secure/CreateIssueDetails!init.jspa?pid=0' \
        '&issuetype=1&summary=Summary&description=Description&priority=2'

    # Product is given from CLI.
    assert ig._jira_create_issue_link(cmd_args, 'Summary', 'Description') == url    # noqa: E501

    # Product is derived from OSSPI Project Name.
    cmd_args.product = None
    ig._osspi_project_to_prod_id.return_value = 'PRD'
    assert ig._jira_create_issue_link(cmd_args, 'Summary', 'Description') == url    # noqa: E501

    # Unsupported Product.
    cmd_args.project = 'Unsupported'
    assert ig._jira_create_issue_link(cmd_args, 'Summary', 'Description') == ''


def test_load_from_paths(monkeypatch: object) -> None:
    import logging
    import pathlib
    m_func = mock.Mock(lambda x: None)
    utils.auto_patch(monkeypatch, logging, 'debug')
    utils.auto_patch(monkeypatch, logging, 'warning')

    # Loading from directory.
    with (
        mock.patch.object(pathlib.Path, 'is_dir') as m_is_dir,
        mock.patch.object(pathlib.Path, 'glob') as m_glob,
    ):
        m_is_dir.return_value = True
        m_glob.return_value = []
        ig._load_from_paths(
            ['dirPath/'], 'XXX', ('ext', 'EXT'),
            (m_func, (), {}),
        )
        logging.warning.reset_mock()
        logging.debug.assert_called_once_with('Found 0 XXX files.')
        logging.debug.reset_mock()
        m_func.assert_not_called()

    # Loading from file.
    with (
        mock.patch.object(pathlib.Path, 'is_dir') as m_is_dir,
        mock.patch.object(pathlib.Path, 'is_file') as m_is_file,
    ):
        # Non-matching file.
        m_is_dir.return_value = False
        m_is_file.return_value = True
        ig._load_from_paths(
            ['filePath'], 'XXX', ('ext', 'EXT'),
            (m_func, (), {}),
        )
        logging.warning.assert_called_once_with(
            'Not a EXT (.ext) file: filePath',
        )
        logging.warning.reset_mock()
        logging.debug.assert_not_called()

        # Matching file.
        ig._load_from_paths(
            ['filePath.ext'], 'XXX', ('ext', 'EXT'),
            (m_func, (), {}),
        )
        logging.warning.assert_not_called()
        logging.debug.reset_mock()
        m_func.assert_called_once()
        m_func.reset_mock()

    # Failed loading.
    with (
        mock.patch.object(pathlib.Path, 'is_dir') as m_is_dir,
        mock.patch.object(pathlib.Path, 'is_file') as m_is_file,
    ):
        m_is_dir.return_value = False
        m_is_file.return_value = False
        ig._load_from_paths(
            ['invalidPath'], 'XXX', ('ext', 'EXT'),
            (m_func, (), {}),
        )
        logging.warning.assert_called_once_with(
            'Invalid XXX path: invalidPath',
        )
        logging.warning.reset_mock()
        logging.debug.assert_not_called()
        m_func.assert_not_called()


def test_get_svc_and_ctr_img_name__percent_sep() -> None:
    # pylint: disable=no-value-for-parameter
    cmd_args = argparse.Namespace()
    fut = ig._get_svc_and_ctr_img_name__percent_sep

    assert fut(cmd_args, 'service%tag', 'container%tag') == \
        ((('container', ':tag'), [('service', ':tag')]),)
    assert fut(cmd_args, '', 'container') == \
        ((('container', ''), [('', '')]),)


def test_get_svc_and_ctr_img_name__img_lyr_sha_2_map(
    monkeypatch: object,
) -> None:
    # pylint: disable=no-value-for-parameter
    lyr_map_yaml = '''\
LayerMappings:
  ImgpkgBundles:
    - URL: localhost:5000/imgpkg/service-foo1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      Tag: 1.2.3-0
      ContainerImgs:
        - URL: localhost:5000/image/container-bar1@sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0
          Tag: latest
          ImgLayers:
            - 23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01
    - URL: localhost:5000/imgpkg/service-foo2@sha256:3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012
      Tag: null
      ContainerImgs:
        - URL: localhost:5000/image/container-bar2@sha256:456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123
          Tag: null
          ImgLayers:
            - 23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01
            - 56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234
  ContainerImgs:
    - URL: localhost:5000/image/container-bar1@sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0
      Tag: latest
      ImgLayers:
        - 23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01
'''     # noqa: E501
    cmd_args = argparse.Namespace(layer_map='lyrMap.yaml')

    with mock.patch('builtins.open'):
        import yaml
        lyr_map_data = yaml.safe_load(lyr_map_yaml)
        fut = ig._get_svc_and_ctr_img_name__img_lyr_sha_2_map
        fut_map = fut.map
        utils.auto_patch(monkeypatch, yaml, 'safe_load')

        # With Layer Mapping data.
        with monkeypatch.context() as mp:
            mp.setattr(fut.__func__, 'map', copy.deepcopy(fut_map))
            yaml.safe_load.return_value = lyr_map_data
            assert fut(
                cmd_args, 'service-orphan', 'container-orphan',
                '23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01',     # noqa: E501
            ) == (
                (
                    ('container-bar1', ':latest'),
                    [('service-foo1', ':1.2.3-0'), ('', '')],
                ),
                (
                    (
                        'container-bar2',
                        '@sha256:456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123',     # noqa: E501
                    ),
                    [(
                        'service-foo2',
                        '@sha256:3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012',     # noqa: E501
                    )],
                ),
            )
            assert fut(
                cmd_args, 'service-orphan', 'container-orphan',
                '56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234',     # noqa: E501
            ) == (
                (
                    (
                        'container-bar2',
                        '@sha256:456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123',     # noqa: E501
                    ),
                    [(
                        'service-foo2',
                        '@sha256:3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012',     # noqa: E501
                    )],
                ),
            )
            assert fut(
                cmd_args, 'service-orphan', 'container-orphan',
                'foo-bar',
            ) == ((('container-orphan', ''), [('service-orphan', '')]),)

        # Without Layer Mapping data.
        with monkeypatch.context() as mp:
            mp.setattr(fut.__func__, 'map', copy.deepcopy(fut_map))
            yaml.safe_load.return_value = {}
            assert fut(
                cmd_args, 'service-orphan', 'container-orphan',
                '23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01',     # noqa: E501
            ) == ((('container-orphan', ''), [('service-orphan', '')]),)


def test_osspi_confluence_wikisafe() -> None:
    assert ig._osspi_confluence_wikisafe({
        'cve_desc': 'Need to be escaped: \r\n\r\n  * {\n\n\n  * |\r\r\r  * }',
        'impact_analysis': 'Remove\r\n\r\n  multiple\n\n\n  newlines\r\r\r',
    }) == {
        'cve_desc': 'Need to be escaped: \n  * \\{\n  * \\|\n  * \\}',
        'impact_analysis': 'Remove\n  multiple\n  newlines\n',
    }


def test_osspi_project_to_prod_id() -> None:
    # Known OSSPI Dashboard Project.
    for (k, v) in ig.OSSPI_PROJECTS.items():
        for e in v:
            assert ig._osspi_project_to_prod_id(e) == k

    # Unknown OSSPI Dashboard Project.
    with pytest.raises(Exception) as exc:
        ig._osspi_project_to_prod_id('_')
    assert str(exc.value) == 'Unsupported OSSPI Dashboard Project: _'


def test_requests_osspi(monkeypatch: object) -> None:
    import logging
    import requests
    utils.auto_patch(monkeypatch, logging, 'debug')
    utils.auto_patch(monkeypatch, requests, 'get')
    rsp1 = requests.Response(); rsp1.status_code = 500  # noqa: E702
    rsp2 = requests.Response(); rsp2.status_code = 200  # noqa: E702
    cmd_args = argparse.Namespace(api_key='0123456789abcdef')

    # Successful with retry.
    requests.get.side_effect = [rsp1, rsp2]
    req = ig._requests_osspi(
        cmd_args, requests.get, ('https://localhost',),
        retry_wait=0,
    )
    logging.debug.assert_called_once_with('Retrying: 1 ...')
    assert req.status_code == 200

    # Failed after exhausting retries.
    requests.get.side_effect = [rsp1, rsp1]
    req = ig._requests_osspi(
        cmd_args, requests.get, ('https://localhost',),
        retry_max=1, retry_wait=0,
    )
    assert req.status_code == 500


def test_validate_BLACKDUCK_PATH_RE() -> None:
    import re
    bd_paths = {
        ig.TCX: [
            'tcx-services-3.8.0-2607#tcx-strimzi-kafka-operator%3.1.1-2486#tcx-docker-local.usw1.packages.broadcom.com/release/images/operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#operator#0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#/opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar',     # noqa: E501
            'tcx-services-3.8.0-2607#tcx-strimzi-kafka-operator%3.1.1-2486#tcx-docker-local.usw1.packages.broadcom.com/snapshot/images/operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#operator#0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#/opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar',    # noqa: E501
            'tcx-services-3.8.0-2607#tcx-strimzi-kafka-operator%3.1.1-2486#tcx-docker-local.usw1.packages.broadcom.com/tcxtest/images/operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#operator#0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#/opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar',     # noqa: E501
        ],
        ig.TPS: [
            'tcx-platform-services-3.8.0-2607#tcx-strimzi-kafka-operator%3.1.1-2486#tcx-docker-local.usw1.packages.broadcom.com/release/images/operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#operator#0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#/opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar',     # noqa: E501
            'tcx-platform-services-3.8.0-2607#tcx-strimzi-kafka-operator%3.1.1-2486#tcx-docker-local.usw1.packages.broadcom.com/snapshot/images/operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#operator#0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#/opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar',    # noqa: E501
            'tcx-platform-services-3.8.0-2607#tcx-strimzi-kafka-operator%3.1.1-2486#tcx-docker-local.usw1.packages.broadcom.com/tcxtest/images/operator@sha256%7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db#operator#0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03#/opt/strimzi/lib/com.fasterxml.jackson.core.jackson-core-2.14.1.jar',     # noqa: E501
        ],
        ig.TCX_DEPLOYMENT_CONTAINER: [
            'tcx-docker-local.usw1.packages.broadcom.com/release/images/deployment%2.4.2-451#deployment%2.4.2-451#63118abbc74650e8ed1192edb2c2c1837ec39c320fecd5d931503a042c641af2#/usr/lib/python3.11/site-packages/pip/_vendor/packaging/',                                       # noqa: E501
            'tcx-docker-local.usw1.packages.broadcom.com/snapshots/images/deployment%TCX-5302-2.4.2-SNAPSHOT-13#deployment%TCX-5302-2.4.2-SNAPSHOT-13#63118abbc74650e8ed1192edb2c2c1837ec39c320fecd5d931503a042c641af2#/usr/lib/python3.11/site-packages/pip/_vendor/packaging/',   # noqa: E501
        ],
        ig.TCX_K8S_INSTALLER: [
            #   Variant 1
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/pkg/infra/kubelet',                                                                                                                                                                 # noqa: E501
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/pkg/infra/cni-plugins-linux-amd64-v0.9.1.tgz#bandwidth',                                                                                                                            # noqa: E501
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/pkg/infra/etcd-v3.5.0-linux-amd64.tar.gz#etcd-v3.5.0-linux-amd64/etcd',                                                                                                             # noqa: E501
            #   Variant 2
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/docker/infra/docker-k8s-dns-node-cache_1.17.1.tar.gz#3afdf90870c0700d48a0cb32f14380ab1f935c21a6fc430f2aeadd15479e7528/layer.tar#usr/lib/x86_64-linux-gnu/libtasn1.so.6.5.5',        # noqa: E501
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/docker/infra/docker-postgresql_11.15.0-photon-3-r14.tar.gz#3afdf90870c0700d48a0cb32f14380ab1f935c21a6fc430f2aeadd15479e7528/layer.tar#usr/lib/x86_64-linux-gnu/libtasn1.so.6.5.5',  # noqa: E501
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/docker/infra/docker-kube-controllers_v3.19.2.tar.gz#89f82cc4beaabcd943f2084f3014a12f222336774aee7fef11150460d1d73001/layer.tar#usr/bin/kube-controllers',                           # noqa: E501
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/docker/infra/node-v3.25.1.tar.gz#3afdf90870c0700d48a0cb32f14380ab1f935c21a6fc430f2aeadd15479e7528/layer.tar#usr/lib/x86_64-linux-gnu/libtasn1.so.6.5.5',                            # noqa: E501
            'VMware-K8s-Installer-1.0.0-92.tar.gz#k8s-installer/cluster/docker/infra/harbor-core-2.8.2-photon-3-r55.tar.gz#3afdf90870c0700d48a0cb32f14380ab1f935c21a6fc430f2aeadd15479e7528/layer.tar#usr/lib/x86_64-linux-gnu/libtasn1.so.6.5.5',          # noqa: E501
        ],
        ig.TCA: [
            # OVA File - Inner OVA.
            #   Variant 1.1
            'VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#VMware-Telco-Cloud-Automation-3.1.0-23448769-disk1.vmdk#partition-2/initrd.img-5.10.201-1.ph4#usr/lib/liblzma.so.5.2.5',                                                                                                                                      # noqa: E501
            #   Variant 1.2
            'VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#VMware-Telco-Cloud-Automation-3.1.0-23448769-disk1.vmdk#opt/vmware/lib/libz.so',                                                                                                                                                                              # noqa: E501
            'VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#VMware-Telco-Cloud-Automation-3.1.0-23448769-disk1.vmdk#etc/vmware/cap/capengine/support/ph4-UpdateDepRpms.tar.gz#zchunk-libs-1.1.7-2.ph4.x86_64.rpm#usr/lib/libzck.so.1.1.7',                                                                                # noqa: E501
            #   Variant 2.1
            'VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#VMware-Telco-Cloud-Automation-3.1.0-23448769-disk3.vmdk#containerd/data/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/lib/libz.so.1.2.13',                                                                                                          # noqa: E501
            'VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#VMware-Telco-Cloud-Automation-3.1.0-23448769-disk3.vmdk#containerd/data/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/root/.cache/pip/http-v2/3/b/d/5/3/3bd53b300a0bc174e69474ff28b696ba271b5dd4cd2ae328c0a8ba92.body#urllib3/__init__.py',         # noqa: E501
            #   Variant 2.2
            'VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#VMware-Telco-Cloud-Automation-3.1.0-23448769-disk3.vmdk#containerd/data/io.containerd.content.v1.content/blobs/sha256/5b39652bbe70f6c8b54ebbf80f30085c802973cf84acce236d68daa37c19fa3c#opt/cruise-control/libs/zookeeper-3.6.3.jar#org/apache/zookeeper',     # noqa: E501
            'VMware-Telco-Cloud-Automation-3.1.0-23448769.ova#VMware-Telco-Cloud-Automation-3.1.0-23448769-disk3.vmdk#opt/vmware/registry/docker/registry/v2/blobs/sha256/fe/fea43f71b0b0e24e9f10fc13902b90f6640005a677f28cd0d0c8f3cc617c2537/data#lib/x86_64-linux-gnu/libz.so.1.2.11',                                    # noqa: E501
            # OVA File - Container.
            'publish/cap-builder/ova/VMware-Telco-Cloud-Automation-3.0.0-21758171.ova',                                                                                                                                                                                                                                     # noqa: E501
        ],
        ig.TCSA: [
            # Legacy.
            #   Variant 1
            'VMware-TCOps-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/clis/tcxctl',                                                                                                                                # noqa: E501
            #   Variant 2
            'VMware-TCOps-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/images/kafka.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',                               # noqa: E501
            'VMware-TCOps-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/imgpkg/services/istio_3.0.0-304.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',            # noqa: E501
            'VMware-TCOps-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/imgpkg/services/collector-manager_latest.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',   # noqa: E501
            # Mainline.
            #   Variant 1
            'VMware-TCSA-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/clis/tcxctl',                                                                                                                                 # noqa: E501
            #   Variant 2
            'VMware-TCSA-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/images/kafka.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',                                # noqa: E501
            'VMware-TCSA-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/imgpkg/services/istio_3.0.0-304.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',             # noqa: E501
            'VMware-TCSA-Deployer-develop-2.1.0-SNAPSHOT-3964.tar.gz#tcx-deployer/imgpkg/services/collector-manager_latest.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',    # noqa: E501
            # Release.
            #   Variant 1
            'VMware-TCSA-Deployer-2.1.0-10.tar.gz#tcx-deployer/clis/tcxctl',                                                                                                                                # noqa: E501
            #   Variant 2
            'VMware-TCSA-Deployer-2.1.0-10.tar.gz#tcx-deployer/images/kafka.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',                               # noqa: E501
            'VMware-TCSA-Deployer-2.1.0-10.tar.gz#tcx-deployer/imgpkg/services/istio_3.0.0-304.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',            # noqa: E501
            'VMware-TCSA-Deployer-2.1.0-10.tar.gz#tcx-deployer/imgpkg/services/collector-manager_latest.tar#sha256-1179bf59e63b5abf70bcff50326e3a997e952aaaf24f3d2c6093e85baf77e182.tar.gz#usr/bin/ncat',   # noqa: E501
        ],
        ig.RIC_INSTALLER: [
            'vmware-ric-installer-0.0.0_62851256.tar.gz#installer/installer.tar#fd8ced994c330a1dd02bc54ccc32b06617513bb713d5ccb440eb1240787a9beb/layer.tar#usr/bin/vim',    # noqa: E501
        ],
        ig.CRIC: [
            'vmware-cric-bundle-0.0.0_62810041.tar.gz#imgpkgs/hoggerflink_0.0.0_62810041.tar#sha256-ceb46a86f1aab78c6dab7a6e7c9eb0e7485aea933427c1a46805830bc2497f48.tar.gz#usr/bin/lua',                   # noqa: E501
            'vmware-cric-bundle-0.0.0_62810041.tar.gz#imgpkgs/istio-custom_0.0.0_62810041.tar#sha256-ceb46a86f1aab78c6dab7a6e7c9eb0e7485aea933427c1a46805830bc2497f48.tar.gz#usr/bin/lua',                  # noqa: E501
            'vmware-cric-bundle-0.0.0_62810041.tar.gz#devkit/devkit.tgz#rapp-devkit/cric/docker/devkitrunner.tar#92ab736eee018f3ec14a77003a6a687997ff546ac5f9eb008ea7e06bba9ea892/layer.tar#usr/bin/lua',   # noqa: E501
        ],
        ig.CRIC_SDK: [
            'vmware-cric-sdk-0.0.0_63756515.tar.gz#devkit/devkit.tgz#rapp-devkit/cric/docker/devkitrunner.tar#3b653e99282c4c625654230e88f93fc6171637caa7abc4f27745ee1d4aa593e5/layer.tar#bootstrapper',     # noqa: E501
            'vmware-cric-sdk-0.0.0_63756515.tar.gz#cric/docker/devkitrunner.tar#3b653e99282c4c625654230e88f93fc6171637caa7abc4f27745ee1d4aa593e5/layer.tar#bootstrapper',                                   # noqa: E501
        ],
        ig.CRIC_RAPP_ES: [
            'vmware-energy-saving-bundle-0.0.0_64327753.tar.gz#imgpkgs/energy-saving_0.0.0_64327753.tar#sha256-791e6f6c30629e8cc0e6b708c86ad7f9734005bb1ca5be4016691d340f2005d7.tar.gz#usr/bin/lua',    # noqa: E501
        ],
        ig.CRIC_RAPP_RAN_KPI: [
            'vmware-ran-kpi-bundle-0.0.0_64327753.tar.gz#imgpkgs/ran-kpi_0.0.0_64327753.tar#sha256-ee433f69a9e58dceae7b9ba096c3cc0192b2ba2d10188b5d268f14ed38f2341a.tar.gz#ran-kpi',    # noqa: E501
        ],
        ig.DRIC: [
            'vmware-dric-bundle-0.0.0_64327750.tar.gz#imgpkgs/dric_0.0.0_64327750.tar#sha256-0286978b7af7a7f77a5f1e1cb36ff6d7e7eda08bfc9e3733a550caf7577d4d03.tar.gz#usr/bin/wget',                 # noqa: E501
            'vmware-dric-bundle-0.0.0_64327750.tar.gz#imgpkgs/cert-manager-custom_0.0.0_64327750.tar#sha256-0286978b7af7a7f77a5f1e1cb36ff6d7e7eda08bfc9e3733a550caf7577d4d03.tar.gz#usr/bin/wget',  # noqa: E501
        ],
        ig.DRIC_SDK: [
            'vmware-dric-sdk-0.0.0_64327748.tar.gz#sdk/third_party/com_github_cares_cares.a',   # noqa: E501
        ],
        ig.DRIC_SDK_MPP: [
            'vmware-dric-sdk-mpp-0.0.0_64327748.tar.gz#sdk/third_party/com_github_redis_hiredis.a',     # noqa: E501
        ],
        ig.DRIC_XAPP_VONR: [
            'vmware-xapp-vonr-bundle-0.0.0_64327750.tar.gz#imgpkgs/xapp-vonr_0.0.0_64327750.tar#sha256-7846449c5eddebd867bcb7538162469a7605115a253495592e586ee77cfc65af.tar.gz#usr/bin/systemd-analyze',    # noqa: E501
        ],
        ig.RMS: [
            'vmware-rms-bundle-0.0.0_62855608.tar.gz#imgpkgs/es-operator_0.0.0_62855608.tar#sha256-6b44875008a92252fdfd13c6c2e6462cae456cf114dbe26e465df97f6a5280af.tar.gz#usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/rack-2.2.3/rack.gemspec',      # noqa: E501
            'vmware-rms-bundle-0.0.0_62855608.tar.gz#imgpkgs/logstash-custom_0.0.0_62855608.tar#sha256-6b44875008a92252fdfd13c6c2e6462cae456cf114dbe26e465df97f6a5280af.tar.gz#usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/rack-2.2.3/rack.gemspec',  # noqa: E501
        ],
        ig.UHANA: [
            #   Variant 1
            'uhana-bundle-65335473.tar.gz#docker/docker-ambassador-auth-service_2.0.0.tar.gz#ambassador-auth-service_2.0.0.tar#8965d0b1e10d1036675c35bd8ea3aa0a23ebb9819a9aa956a1e2d69a298ec735/layer.tar#lib/libz.so.1.2.11',                                                                                  # noqa: E501
            'uhana-bundle-65335473.tar.gz#docker/docker-collector_0.0.0+65335473.tar.gz#docker/collector.tar#5c173a4c0563d369b9e1644f663bc22015b5efa438fb5520e61b6625515c1fde/layer.tar#ctrserver/src/java/io/uhana/collector/collector_5g_main_deploy.jar#org/apache',                                         # noqa: E501
            'uhana-bundle-65335473.tar.gz#docker/docker-ambassador-auth-httpbasic_0.1.1_20240104.tar.gz##/docker/docker-ambassador-auth-httpbasic_0.1.1_20240104.tar#1ebf16d2458dca0e2e94520a563b1c9713315ad65c79194f814e906f63f4397f/layer.tar#usr/local/lib/python3.6/distutils/command/wininst-6.0.exe',     # noqa: E501
            'uhana-bundle-65335473.tar.gz#docker/docker-curator_5.8.1.tar.gz#uhana/uhana_piran/curator/docker/docker-curator_5.8.1.tar#1799dbbd3f3f5e4a2336866e06a2993d47a41883e104c362bb2a2ed54f75f4ae/layer.tar#curator/lib/distutils/command/wininst-6.0.exe',                                               # noqa: E501
            'uhana-bundle-65335473.tar.gz#docker/docker-minideb_stretch.tar.gz#tmp/piran/docker/docker-minideb_stretch.tar#ccac04f8f22ac16316615f5c2c5ecac2bb1aec6254424a3c9c35ecef95df3bb0/layer.tar#lib/x86_64-linux-gnu/libz.so.1.2.8',                                                                      # noqa: E501
            'uhana-bundle-65335473.tar.gz#cluster/cluster-bundle-65312685.tar.gz#docker/infra/docker-hadoop-datanode_2.7.2.tar.gz#82abc25ad9cb20adadf08c9376364676812d1baeeacb2ae8c0e1c445c2c98a35/layer.tar#opt/hadoop-2.7.2/share/hadoop/yarn/lib/zookeeper-3.4.6-tests.jar',                                 # noqa: E501
            #   Variant 2
            'uhana-bundle-65335473.tar.gz#cluster/cluster-bundle-65312685.tar.gz#pkg/infra/cni-plugins-linux-amd64-v0.8.5.tgz#bandwidth',                                                                                                                                                                       # noqa: E501
            'uhana-bundle-65335473.tar.gz#cluster/cluster-bundle-65312685.tar.gz#pkg/infra/kubelet',                                                                                                                                                                                                            # noqa: E501
            #   Variant 3
            'uhana-bundle-65335473.tar.gz#installer/k8s-launcher.tar.gz#j2skaffold.zip#runfiles/third_party_py_deps/pypi__pyyaml/yaml/__init__.py',                                                                                                                                                             # noqa: E501
        ],
    }

    for (k, v) in ig.BLACKDUCK_PATH_RE.items():
        for e in bd_paths[k]:
            match = re.fullmatch(v, e)
            assert match
            match = [i for i in match.groups() if i is not None]
            if match:   # Some pattern is designed to yield all `None`.
                assert len(match) == 6
