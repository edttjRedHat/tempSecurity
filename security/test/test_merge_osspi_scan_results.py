#!/usr/bin/env python3

import sys
from pathlib import Path
from unittest import mock

from .. import merge_osspi_scan_results as sut  # Source Under Test


TEST_ARGS = [
    f'./{Path(sut.__file__).name}',
    'scanResFile.json',
]

TEST_SCAN_RES = '''\
{
  "packages": [
    {
      "_unique_id": "baseos:rpm:Linux-PAM:1.5.3-2.ph4:photon",
      "detected_paths": [
        "/path1#c996457c0951f3b94a3d4eb1af71d7820626a15ff7eee8d51eca9f4488d71273#/var/lib/rpm/rpmdb.sqlite#Linux-PAM-1.5.3-2.ph4.src.rpm"
      ]
    },
    {
      "_unique_id": "44d8c92a-f682-4904-b571-c83f83ae1a91-36b26205-cef2-4a93-98d4-14658e23f108-e312622f-cfbd-4e45-8337-eb7f5cde784a",
      "bd_metadata": {
        "paths": [
          "/path1#/opt/strimzi/lib/org.apache.logging.log4j.log4j-api-2.17.2.jar#tcx_docker_local_usw1_packages_broadcom_com_release_images_operator_sha256_7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db.tar!/0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03/layer.tar!/"
        ]
      }
    },
    {
      "_unique_id": "baseos:rpm:Linux-PAM:1.5.3-2.ph4:photon",
      "detected_paths": [
        "/path1#c996457c0951f3b94a3d4eb1af71d7820626a15ff7eee8d51eca9f4488d71273#/var/lib/rpm/rpmdb.sqlite#Linux-PAM-1.5.3-2.ph4.src.rpm"
      ],
      "newKey": null
    },
    {
      "_unique_id": "44d8c92a-f682-4904-b571-c83f83ae1a91-36b26205-cef2-4a93-98d4-14658e23f108-e312622f-cfbd-4e45-8337-eb7f5cde784a",
      "bd_metadata": {
        "paths": [
          "/path2#/opt/strimzi/lib/org.apache.logging.log4j.log4j-api-2.17.2.jar#tcx_docker_local_usw1_packages_broadcom_com_release_images_operator_sha256_7513b1f57cf9885838f1c40ffb2dec2fb0a27f213a12bcd303a0702c95a588db.tar!/0f468335af6f699b59ccfb22421db61a657de51de8c4d7580764022542808a03/layer.tar!/"
        ],
        "newKey": null
      }
    }
  ]
}
'''     # noqa: E501


def test_main():
    with mock.patch.object(
            sys,
            'argv',
            TEST_ARGS,
    ):
        scan_res_file = Path(TEST_ARGS[1])
        scan_res_file.write_text(TEST_SCAN_RES)
        sut.main()
        scan_res = sut.json.load(open(scan_res_file, encoding='utf-8'))
        assert len(scan_res['packages']) == 2
        for pkg in scan_res['packages']:
            if pkg['_unique_id'].startswith('baseos:'):
                assert len(pkg['detected_paths']) == 2
                assert pkg['newKey'] is None
            else:
                assert len(pkg['bd_metadata']['paths']) == 2
                assert pkg['bd_metadata']['newKey'] is None
        scan_res_file.unlink()


def test_parse_args():
    with mock.patch.object(sys, 'argv', TEST_ARGS):
        args = sut._parse_args()
        assert args.scan_res_file == TEST_ARGS[1]
