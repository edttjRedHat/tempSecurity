#!/usr/bin/env python3
'''Create summary report of OSL Inventory Scan results.'''

import argparse
from collections import defaultdict, OrderedDict
import sys
import yaml


def main() -> None:
    '''
    Primary entry point for executing this helper tool. Command
    line arguments are parsed and the requested action evaluated.
    '''
    # pylint: disable=too-many-locals
    args = _parse_args()
    max_pkg_str = 8     # Lengh of header `pkg name`.
    rep_data = open(args.rep_file).read()
    headers = []

    # The report file is a multi-document YAML with `--- # SCAN_TYPE` line as
    #   the document marker.
    for line in rep_data.splitlines():
        if line.startswith('---'):
            headers.append(line.split()[2])
    max_scan_type = len(headers)
    sum_data = defaultdict(lambda: [' ' for i in range(max_scan_type)])
    i = 0
    for scan in yaml.safe_load_all(rep_data):
        if scan:
            for pkg in scan:
                sum_data[pkg][i] = '*'
                max_pkg_str = max(max_pkg_str, len(pkg))
        i += 1
    sum_data = OrderedDict(sorted(
        sum_data.items(),
        key=lambda x: str.lower(x[0])
    ))

    # Create report.
    #   +-------------+-------------+-...-+-------------+
    #   | SCAN_TYPE_1 | SCAN_TYPE_2 | ... | pkg name    |
    #   +-------------+-------------+-...-+-------------+
    #   |      *      |             | ... | foo         |
    #   ...
    #   |      *      |      *      | ... | bar         |
    #   +-------------+-------------+-...-+-------------+
    header_border = ''
    header_title = ''
    header_pads = []
    for title in headers:
        title_len = len(title)
        header_border += f'+-{"-"*title_len}-'
        header_title += f'| {title} '
        title_pad = title_len - 1
        header_pads.append([
            ((title_pad//2)+1),
            ((title_pad//2)+2) if (title_pad % 2) else ((title_pad//2)+1),
        ])
    header_border += f'+-{"-"*max_pkg_str}-+'
    header_title += f'| pkg name{" "*(max_pkg_str - 8)} |'

    print('\n'.join([header_border, header_title, header_border]))
    for (key, val) in sum_data.items():
        line = '|'
        for i in range(max_scan_type):
            line += f"{' '*header_pads[i][0]}{val[i]}{' '*header_pads[i][1]}|"
        line += f" {key}{' '*(max_pkg_str - len(key))} |"
        print(line)
    print(header_border)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'rep_file',
        type=str,
        help='Reconciled report file (YAML).',
    )

    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(main())
