#!/usr/bin/env python3
'''Identify BaseOS Layer Id. of a given set of Container Image's Layers.'''

import argparse
import sys
import yaml


def main() -> None:
    '''
    Primary entry point for executing this helper tool. Command
    line arguments are parsed and the requested action evaluated.
    '''
    # pylint: disable=too-many-nested-blocks
    args = _parse_args()
    img_layers = yaml.safe_load(open(args.img_layers).read())
    known_layers = yaml.safe_load(open(args.known_layers).read())
    base_os = ''

    # The BaseOS can not be the LAST layer.
    # The prev. version of BaseOS's layers may exist in earlier layer, so we
    #   MUST look up backward.
    for elem in img_layers[-2::-1]:     # Look up backward, without last one.
        base_os = known_layers.get(elem, '')
        if base_os:
            base_os = f'{base_os}|{elem}'
            break

    print(base_os)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        'img_layers',
        type=str,
        help='File (YAML) containing Container Image Layer Id.s',
    )
    parser.add_argument(
        'known_layers',
        type=str,
        help='File (YAML) containing known BaseOS Layer Id.s.',
    )

    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(main())
