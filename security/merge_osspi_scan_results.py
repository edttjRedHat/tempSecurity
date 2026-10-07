#!/usr/bin/env python3
'''Merge duplicated packages and combine the detected paths.'''

# The Scan Report file is a JSON with the following schemes:
#   {
#     "packages" : [
#       {
#         "_unique_id": "<pgkMan>:<baseOS>:<pkgName>:<pkgVer>",
#         "detected_paths": [
#           "<path2_1>",
#           ...
#           "<path2_N>"
#         ],
#         "bd_metadata": {
#           "paths": [
#             "<path1_1>",
#             ...
#             "<path1_N>"
#           ],
#           ...
#         },
#         ...
#       },
#       ...
#     ],
#     "server": {
#       "scanner": "docker",
#       "type": "anchore,Hub"
#     }
#   }
# Some internal scanner put the detected path under
#   `.packages[].detected_path`, while other under
#   `.packages[].bd_metadata.paths`.
# When multiple scan of Container Images are reconciled, the `.packages`
#   array may contains duplicated unique package if multiple Container
#   Images contains the same exact package.
# When uploading to OSSPI Dashboard, these duplicated packages are ignored,
#   resulting only the first element of a unique package is uploaded.
# Combined elements in `.packages` that belongs to the same unique package into
#   a single entry, but merge the entries from `.packages[].detected_path` or
#   `.packages[].bd_metadata.paths`, so the information of which Container
#   Images it came from is not lost, when these entries translate to
#   `.blackduck_paths` in the downloaded OSSPI Audit Report.

import argparse
from collections import defaultdict
import json
import sys


def main() -> None:
    '''
    Primary entry point for executing this helper tool. Command
    line arguments are parsed and the requested action evaluated.
    '''
    # pylint: disable=too-many-nested-blocks
    args = _parse_args()
    scan_res = json.load(open(args.scan_res_file, encoding='utf-8'))
    pkg_set = defaultdict(list)

    while scan_res['packages']:
        pkg = scan_res['packages'].pop()
        pkg_set[pkg['_unique_id']].append(pkg)

    for val1 in pkg_set.values():
        m_pkg = {}
        while val1:
            s_pkg = val1.pop()
            for (key2, val2) in s_pkg.items():
                if ((key2 == 'detected_paths') and isinstance(val2, list)):
                    m_pkg[key2] = m_pkg.get(key2, []) + val2
                elif ((key2 == 'bd_metadata') and isinstance(val2, dict)):
                    m_pkg[key2] = m_pkg.get(key2, {})
                    for (key3, val3) in val2.items():
                        if ((key3 == 'paths') and val3):
                            m_pkg[key2][key3] = \
                                m_pkg.get(key2, {}).get(key3, []) + val3
                        else:
                            m_pkg[key2][key3] = val3
                else:
                    m_pkg[key2] = val2
        scan_res['packages'].append(m_pkg)

    json.dump(
        scan_res,
        open(args.scan_res_file, 'w', encoding='utf-8'),
        indent=2,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'scan_res_file',
        type=str,
        help='Reconciled OSSPI Scan Result file (JSON). This report will be '
        'read and updated after merging any duplicated packages.',
    )

    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(main())
