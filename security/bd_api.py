#!/usr/bin/env python3
'''Access BlackDuck Hub via REST API.'''

import argparse
from enum import IntFlag
import logging
import os
import re
import sys
from typing import Any, Union

import blackduck
import requests

from py_libs import utils
from py_libs.custom_types import NamedDict, SingletonMeta


class ArgsProjVerMask(IntFlag):
    '''
    Bit-mask flag for inclusion of Project and Project Version in CLI
    Arguments.
    '''
    PROJ__FLT_RGX__OPT =        0x0001  # Project Filter RegEx as optional par.             # pylint: disable=line-too-long # noqa: E222, E501
    PROJ__URL__OPT =            0x0002  # Project URL as optional par.                      # pylint: disable=line-too-long # noqa: E222, E501
    PROJ_VER__FLT_RGX__OPT =    0x0010  # Project Version Filter RegEx as optional par.     # pylint: disable=line-too-long # noqa: E222, E501
    PROJ_VER__URL__OPT =        0x0020  # Project Version URL as optional par.              # pylint: disable=line-too-long # noqa: E222, E501
    PROJ__NAME__POS =           0x0100  # Project Name as positional par.                   # pylint: disable=line-too-long # noqa: E222, E501
    PROJ__URL__POS =            0x0200  # Project URL as positional par.                    # pylint: disable=line-too-long # noqa: E222, E501
    PROJ_VER__NAME__POS =       0x1000  # Project Version Name as positional par.           # pylint: disable=line-too-long # noqa: E222, E501
    PROJ_VER__URL__POS =        0x2000  # Project Version URL as positional par.            # pylint: disable=line-too-long # noqa: E222, E501


class ArgsProjVerEPparMask(IntFlag):
    '''
    Bit-mask flag for inclusion of Project Version End Point Parameters in CLI
    Arguments.
    '''
    CLONE_URL__OPT =        0x01    # Clone Source URL as optional par.         # noqa: E222, E501


class BdClient(blackduck.Client, metaclass=SingletonMeta):
    '''
    Singleton Wrapper for `blackduck.Client` class.
    '''


def cmd__get_context(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> dict[str, Any]:
    '''
    Retrieve Context from an End Point URL.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                ep_url (str):   End Point URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Depend on the sub-command.
    '''
    _ = sc_args
    return _get_context(bdhub, cmd_args.ep_url)


def cmd__project(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> Union[None, str]:
    '''
    Execute command for within `project` context.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                sub_cmd_project (str):  Sub-Command of `project`.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Depend on the sub-command.
    '''
    # Run the sub-command.
    funcname = f"project__{cmd_args.sub_cmd_project.replace('-', '_')}"
    sc_args.dbg_hdr.append(f'{funcname}(...):')
    # pylint: disable=eval-used
    return eval(funcname)(cmd_args, bdhub, sc_args)


# pylint: disable=invalid-name
def project__create_version(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> str:
    '''
    Create a Project Version.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                proj_url (str):     BD Hub Project URL.
                projVer_name (str): Project Version Name in BD Hub.
                phase (str):        Current dev. phase of BD Hub Project
                                    Version.
                distribution (str): Distribution target of BD Hub Project
                                    Version.
                clone_url (str):    BD Hub Project Version URL clone source
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Created Project Version URL if successful, otherwise empty string.
    '''
    proj_url = cmd_args.proj_url
    projVer_name = cmd_args.projVer_name
    phase = cmd_args.phase
    distribution = cmd_args.distribution
    clone_url = cmd_args.clone_url
    projVer_url = ''

    if not proj_url:
        proj_url = project__get_project_url(cmd_args, bdhub, sc_args)

    if proj_url:
        if not projVer_name:
            logging.error(
                'CLI Arg. `projVer_name` can not be set to empty string.',
            )
            return projVer_url

        proj_ctx = _get_context(bdhub, proj_url)
        projVer_ep = bdhub.list_resources(proj_ctx)['versions']
        projVer_json = {
            'versionName': projVer_name,
            'phase': phase,
            'distribution': distribution,
        }
        if clone_url:
            projVer_json['cloneFromReleaseUrl'] = clone_url

        resp = bdhub.session.post(projVer_ep, json=projVer_json)
        _check_resp(bdhub, resp)
        if resp.status_code == 201:
            projVer_url = resp.headers['Location']

    return projVer_url


def project__delete_version(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> bool:
    '''
    Delete a Project Version.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                projVer_url (str):  BD Hub Project Version URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        '0'  -> Project Version deletion fails or is NOT carried out.
        '1'  -> Project Version deletion is successful.
    '''
    projVer_url = cmd_args.projVer_url
    ret_val = 0

    if not projVer_url:
        projVer_url = project__get_version_url(cmd_args, bdhub, sc_args)

    if projVer_url:
        resp = bdhub.session.delete(projVer_url)
        _check_resp(bdhub, resp)
        if resp.status_code == 204:
            ret_val = 1

    return ret_val


def project__get_project_context(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> dict[str, Any]:
    '''
    Get a Project Context.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                proj_url (str): BD Hub Project URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Context if exist, otherwise empty Context.
    '''
    proj_url = cmd_args.proj_url
    proj_ctx = {}

    if not proj_url:
        proj_url = project__get_project_url(cmd_args, bdhub, sc_args)

    if proj_url:
        proj_ctx = _get_context(bdhub, proj_url)
        bdhub.list_resources(proj_ctx)

    return proj_ctx


def project__get_project_ep_context(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> dict[str, Any]:
    '''
    Get Project End Point Context.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest: None
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project End Point Context without any Project listed.
    '''
    _ = (cmd_args, sc_args)
    return bdhub.session.get(
        bdhub.list_resources()['projects'],
        params={'q': 'name:*'},
    ).json()


def project__get_project_name(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> str:
    '''
    Get Project Name from Project URL.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                proj_url (str): BD Hub Project URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version Name.
    '''
    _ = sc_args
    proj_url = cmd_args.proj_url
    proj_name = ''

    proj_ctx = _get_context(bdhub, proj_url)
    if proj_ctx:
        proj_name = proj_ctx['name']

    return proj_name


def project__get_project_url(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> str:
    '''
    Get Project URL from Project Name.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                proj_name (str):    Project Name in BD Hub.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project URL if exist, otherwise empty string.
    '''
    _ = sc_args
    proj_name = cmd_args.proj_name
    proj_url = ''

    if not proj_name:
        logging.error('CLI Arg. `proj_name` can not be set to empty string.')
        return proj_url

    proj_ctxs = bdhub.get_resource(
        'projects', page_size=2,
        params={
            'sort': 'name asc',
            'q': f'name:{proj_name}',
        },
    )
    for elem in proj_ctxs:
        if elem['name'] == proj_name:
            proj_url = elem['_meta']['href']
        break

    return proj_url


def project__get_version_context(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> dict[str, Any]:
    '''
    Get a Project Version Context.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                projVer_url (str): BD Hub Project Version URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version Context if exist, otherwise empty Context.
    '''
    projVer_url = cmd_args.projVer_url
    projVer_ctx = {}

    if not projVer_url:
        projVer_url = project__get_version_url(cmd_args, bdhub, sc_args)

    if projVer_url:
        projVer_ctx = _get_context(bdhub, projVer_url)

    return projVer_ctx


def project__get_version_ep_context(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> dict[str, Any]:
    '''
    Get Project Version End Point Context.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest: None
                proj_url (str): BD Hub Project URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version End Point Context without any Project Version listed,
        if Project exist, otherwise empty context.
    '''
    proj_url = cmd_args.proj_url
    projVer_ctx = {}

    if not proj_url:
        proj_url = project__get_project_url(cmd_args, bdhub, sc_args)
        cmd_args.proj_url = proj_url

    if proj_url:
        proj_ctx = project__get_project_context(cmd_args, bdhub, sc_args)
        projVer_ctx = bdhub.session.get(
            bdhub.list_resources(proj_ctx)['versions'],
            params={'q': 'versionName:*'},
        ).json()

    return projVer_ctx


def project__get_version_name(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> str:
    '''
    Get Project Version Name from Project Version URL.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                projVer_url (str):  BD Hub Project Version URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version Name.
    '''
    _ = sc_args
    projVer_url = cmd_args.projVer_url
    projVer_name = ''

    projVer_ctx = _get_context(bdhub, projVer_url)
    if projVer_ctx:
        projVer_name = projVer_ctx['versionName']

    return projVer_name


def project__get_version_url(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> str:
    '''
    Get Project Version URL from Project Version Name.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                proj_url (str):     BD Hub Project URL.
                projVer_name (str): Project Version Name in BD Hub.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version URL if exist, otherwise empty string.
    '''
    proj_url = cmd_args.proj_url
    projVer_name = cmd_args.projVer_name
    projVer_url = ''

    if not proj_url:
        proj_url = project__get_project_url(cmd_args, bdhub, sc_args)

    if proj_url:
        if not projVer_name:
            logging.error(
                'CLI Arg. `projVer_name` can not be set to empty string.',
            )
            return projVer_url

        proj_ctx = _get_context(bdhub, proj_url)
        projVer_ctxs = bdhub.get_resource(
            'versions', proj_ctx, page_size=2,
            params={
                'sort': 'versionName asc',
                'q': f'versionName:{projVer_name}',
            },
        )
        for elem in projVer_ctxs:
            if elem['versionName'] == projVer_name:
                projVer_url = elem['_meta']['href']
            break

    return projVer_url


def project__list_parent_urls(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> list[str]:
    '''
    List Parent Project Version URLs in a Project Version.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                projVer_url (str):  BD Hub Project Version URL.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
       Parent Project Version URL list, otherwise empty array.
    '''
    projVer_url = cmd_args.projVer_url
    compVer_parent_arr = []

    if not projVer_url:
        projVer_url = project__get_version_url(cmd_args, bdhub, sc_args)

    if projVer_url:
        compVer_ctx = _get_context(
            bdhub,
            projVer_url.replace('projects', 'components', 1),
        )
        compVer_parent_arr = [
            elem['_meta']['href'] for elem in bdhub.get_resource(
                'references', compVer_ctx,
            )
        ]

    return compVer_parent_arr


def project__list_project_urls(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> list[str]:
    '''
    List Project URLs.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                proj_fltRgx (str):  RegEx pattern filter of Project Name.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version URL list, otherwise empty array.
    '''
    _ = sc_args
    proj_fltRgx = cmd_args.proj_fltRgx
    proj_url_arr = []

    for elem in bdhub.get_resource('projects', params={'sort': 'name asc'}):
        if (proj_fltRgx and (not re.search(proj_fltRgx, elem['name']))):
            continue
        proj_url_arr.append(elem['_meta']['href'])

    return proj_url_arr


def project__list_version_urls(
    cmd_args: argparse.Namespace,
    bdhub: blackduck.Client,
    sc_args: NamedDict,
) -> list[str]:
    '''
    List Project Version URLs in a Project.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                proj_url (str):         BD Hub Project URL.
                projVer_fltRgx (str):   RegEx pattern filter of Project Version
                                        Name.
        bdhub:      BlackDuck Hub Client instance.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version URL list, otherwise empty array.
    '''
    proj_url = cmd_args.proj_url
    projVer_fltRgx = cmd_args.projVer_fltRgx
    projVer_url_arr = []

    if not proj_url:
        proj_url = project__get_project_url(cmd_args, bdhub, sc_args)

    if proj_url:
        proj_ctx = _get_context(bdhub, proj_url)
        for elem in bdhub.get_resource(
            'versions', proj_ctx, params={'sort': 'createdat desc'},
        ):
            if (
                projVer_fltRgx and
                (not re.search(projVer_fltRgx, elem['versionName']))
            ):
                continue
            projVer_url_arr.append(elem['_meta']['href'])

    return projVer_url_arr
# pylint: enable=invalid-name


def main(mod_args: str = '') -> Any:    # pylint: disable=inconsistent-return-statements    # noqa: E501
    '''
    Primary entry point for executing this helper tool. Command
    line arguments are parsed and the requested action evaluated.

    Args:
        mod_args:   CLI Arguments when called as module.
    Return:
        Depend on the sub-command.
    '''
    if mod_args:
        args = _parse_args(mod_args)
    else:
        args = _parse_args()
        utils.setup_logging(None, *args.log_level)

    bdhub = BdClient(
        args.bdhub_api_token,
        args.bdhub_url,
        timeout=args.bdhub_conn_timeout,
        retries=args.bdhub_conn_retry,
    )
    bdhub.list_resources()
    sc_args = NamedDict(
        dbg_hdr=[],
    )

    # Run the sub-command.
    if args.sub_cmd:
        funcname = f"cmd__{args.sub_cmd.replace('-', '_')}"
        sc_args.dbg_hdr.append(f'{funcname}(...):')
        # pylint: disable=eval-used
        results = eval(funcname)(args, bdhub, sc_args)
        if mod_args:
            return results
        logging.debug(f'{" ".join(sc_args.dbg_hdr)} {results}')
        print(results)
    # Do `print()` in here, instead of using `logger`, because `logger` is
    #   directed towards STDERR. With this one can easily assign the result
    #   of the sub-command to a shell var., via `varName="$(<thisProg> ...)"`,
    #   without having to parse it to weed out the logging prints.


def _check_resp(bdhub: blackduck.Client, rsp: requests.Response) -> None:
    '''
    Check HTTP Response Status Code. If it is not `2xx`, print to logging. If
    it is either `4xx` or `5xx`, raise exception.

    Args:
        bdhub:  BlackDuck Hub Client instance.
        rsp:    HTTP Response.
    '''
    if (rsp.status_code // 100) != 2:
        bdhub.http_error_handler(rsp)
        rsp.raise_for_status()


def _get_context(bdhub: blackduck.Client, url: str) -> dict[str, Any]:
    '''
    Get BlackDuck End Point Context from End Point URL
    it is either `4xx` or `5xx`, raise exception.

    Args:
        bdhub:  BlackDuck Hub Client instance.
        url:    End Point URL.
    Return:
        End Point Context
    '''
    rsp = bdhub.session.get(url)
    _check_resp(bdhub, rsp)
    return rsp.json()


def _parse_args(mod_args: str = '') -> argparse.Namespace:
    '''
    Add CLI arguments.
    '''
    # pylint: disable=duplicate-code
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Main Program.
    utils.parse_args__log_level(parser)
    _parse_args__bdhub(parser)

    subparsers__main = parser.add_subparsers(
        title='sub-commands',
        description='The main context',
        dest='sub_cmd',
    )

    # Sub-Command `project`.
    subparser = subparsers__main.add_parser(
        'project',
        help='Execute command for within `project` context.',
    )

    subparsers__project = subparser.add_subparsers(
        title='sub-commands',
        description='The `project` sub-context.',
        dest='sub_cmd_project',
    )

    #   Sub-Command `project.list-project-urls`
    subparser = subparsers__project.add_parser(
        'list-project-urls',
        help='List Project URLs.',
    )
    _parse_args__proj_ver(
        subparser,
        (ArgsProjVerMask.PROJ__FLT_RGX__OPT),
    )

    #   Sub-Command `project.get-project-url`.
    subparser = subparsers__project.add_parser(
        'get-project-url',
        help='Get Project URL from Project Name.',
    )
    _parse_args__proj_ver(
        subparser,
        (ArgsProjVerMask.PROJ__NAME__POS),
    )

    #   Sub-Command `project.get-project-name`
    subparser = subparsers__project.add_parser(
        'get-project-name',
        help='Get Project Name from Project URL.',
    )
    _parse_args__proj_ver(
        subparser,
        (ArgsProjVerMask.PROJ__URL__POS),
    )

    #   Sub-Command `project.get-project-ep-context`
    subparser = subparsers__project.add_parser(
        'get-project-ep-context',
        help='Get Project End Point Context.',
    )

    #   Sub-Command `project.get-project-context`
    subparser = subparsers__project.add_parser(
        'get-project-context',
        help='Get a Project Context.',
    )
    _parse_args__proj_ver(
        subparser,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS
        ),
    )

    #   Sub-Command `project.list-version-urls`
    subparser = subparsers__project.add_parser(
        'list-version-urls',
        help='List Project Version URLs in a Project.',
    )
    _parse_args__proj_ver(
        subparser,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS |
            ArgsProjVerMask.PROJ_VER__FLT_RGX__OPT
        ),
    )

    #   Sub-Command `project.create-version`
    subparser = subparsers__project.add_parser(
        'create-version',
        help='Create a Project Version.',
    )
    _parse_args__proj_ver(
        subparser,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS |
            ArgsProjVerMask.PROJ_VER__NAME__POS
        ),
    )
    _parse_args__proj_ver__ep_par(
        subparser,
        (ArgsProjVerEPparMask.CLONE_URL__OPT),
    )

    #   Sub-Command `project.get-version-url`
    subparser = subparsers__project.add_parser(
        'get-version-url',
        help='Get Project Version URL from Project Version Name.',
    )
    _parse_args__proj_ver(
        subparser,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS |
            ArgsProjVerMask.PROJ_VER__NAME__POS
        ),
    )

    #   Sub-Command `project.get-version-name`
    subparser = subparsers__project.add_parser(
        'get-version-name',
        help='Get Project Version Name from Project Version URL.',
    )
    _parse_args__proj_ver(
        subparser,
        (ArgsProjVerMask.PROJ_VER__URL__POS),
    )

    #   Sub-Command `project.get-version-ep-context`
    subparser = subparsers__project.add_parser(
        'get-version-ep-context',
        help='Get Project Version End Point Context.',
    )
    _parse_args__proj_ver(
        subparser,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS
        ),
    )

    #   Sub-Command `project.get-version-context`
    subparser = subparsers__project.add_parser(
        'get-version-context',
        help='Get a Project Version Context.',
    )
    _parse_args__proj_ver(
        subparser,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ_VER__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS |
            ArgsProjVerMask.PROJ_VER__NAME__POS
        ),
    )

    #   Sub-Command `project.delete-version`
    subparser = subparsers__project.add_parser(
        'delete-version',
        help='Delete a Project Version.',
    )
    _parse_args__proj_ver(
        subparser,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ_VER__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS |
            ArgsProjVerMask.PROJ_VER__NAME__POS
        ),
    )

    common_opt__proj_ver = argparse.ArgumentParser(add_help=False)
    _parse_args__proj_ver(
        common_opt__proj_ver,
        (
            ArgsProjVerMask.PROJ__URL__OPT |
            ArgsProjVerMask.PROJ_VER__URL__OPT |
            ArgsProjVerMask.PROJ__NAME__POS |
            ArgsProjVerMask.PROJ_VER__NAME__POS
        ),
    )

    #   Sub-Command `project.list-parent-urls`
    subparser = subparsers__project.add_parser(
        'list-parent-urls',
        help='List Parent Project Version URLs in a Project.',
        parents=[common_opt__proj_ver],
    )

    # Sub-Command `get-context`.
    subparser = subparsers__main.add_parser(
        'get-context',
        help='Retrieve Context from an End Point URL.',
    )
    subparser.add_argument(
        'ep_url',
        type=utils.parse_type__str_need_non_empty,
        help='End Point URL.',
    )

    return parser.parse_args(mod_args if mod_args else None)


def _parse_args__bdhub(parser: argparse.ArgumentParser) -> None:
    '''
    Add CLI arguments for communication towards BlackDuck Hub.
    '''
    parser.add_argument(
        '--bdhub-url', default=os.getenv('BDHUB_URL', ''),
        type=utils.parse_type__str_need_non_empty_with_def_from_env_var,
        help='BD Hub URL (def: env. var. `BDHUB_URL`).',
    )
    parser.add_argument(
        '--bdhub-api-token', default=os.getenv('BDHUB_API_TOKEN', ''),
        type=utils.parse_type__str_need_non_empty_with_def_from_env_var,
        help='BD Hub URL (def: env. var. `BDHUB_API_TOKEN`).',
    )
    parser.add_argument(
        '--bdhub-conn-timeout',
        default=int(os.getenv('BDHUB_CONN_TIMEOUT', '15')),
        type=int,
        help='Timeout (in second) for connection towards BD Hub (def: env. '
        'var. `BDHUB_CONN_TIMEOUT` if set, otherwise 15).',
    )
    parser.add_argument(
        '--bdhub-conn-retry', default=int(os.getenv('BDHUB_CONN_RETRY', '3')),
        type=int,
        help='No. of retries when connection to BD Hub is timed out (def: '
        'env. var. `BDHUB_CONN_RETRY` if set, otherwise 3).',
    )


def _parse_args__proj_ver(parser: argparse.ArgumentParser, flag: int) -> None:
    '''
    Add CLI arguments for BlackDuck Hub Project and Project Version
    identification.
    '''
    if flag & ArgsProjVerMask.PROJ__FLT_RGX__OPT:
        parser.add_argument(
            '--proj-fltRgx',
            type=utils.parse_type__str_need_non_empty,
            help='RegEx pattern filter of Project Name.',
        )
    if flag & ArgsProjVerMask.PROJ__URL__OPT:
        parser.add_argument(
            '--proj-url',
            type=utils.parse_type__str_need_non_empty,
            help='BD Hub Project URL. If given the `proj_name` will be '
            'ignored.',
        )
    if flag & ArgsProjVerMask.PROJ_VER__FLT_RGX__OPT:
        parser.add_argument(
            '--projVer-fltRgx',
            type=utils.parse_type__str_need_non_empty,
            help='RegEx pattern filter of Project Version Name.',
        )
    if flag & ArgsProjVerMask.PROJ_VER__URL__OPT:
        parser.add_argument(
            '--projVer-url',
            type=utils.parse_type__str_need_non_empty,
            help='BD Hub Project Version URL. If given the `proj_name` and '
            '`projVer_name`will be ignored.',
        )
    if flag & ArgsProjVerMask.PROJ__NAME__POS:
        parser.add_argument(
            'proj_name',
            type=str,
            help='Project Name in BD Hub.',
        )
    if flag & ArgsProjVerMask.PROJ__URL__POS:
        parser.add_argument(
            'proj_url',
            type=utils.parse_type__str_need_non_empty,
            help='BD Hub Project URL.',
        )
    if flag & ArgsProjVerMask.PROJ_VER__NAME__POS:
        parser.add_argument(
            'projVer_name',
            type=str,
            help='Project Version Name in BD Hub.',
        )
    if flag & ArgsProjVerMask.PROJ_VER__URL__POS:
        parser.add_argument(
            'projVer_url',
            type=utils.parse_type__str_need_non_empty,
            help='BD Hub Project Version URL.',
        )


def _parse_args__proj_ver__ep_par(
    parser: argparse.ArgumentParser,
    flag: int,
) -> None:
    '''
    Add CLI arguments for BlackDuck Hub Project Version settings.
    '''
    parser.add_argument(
        '--phase',
        default='DEVELOPMENT',
        type=utils.parse_type__str_need_non_empty,
        help='Current dev. phase of BD Hub Project Version.',
    )
    parser.add_argument(
        '--distribution',
        default='EXTERNAL',
        type=utils.parse_type__str_need_non_empty,
        help='Distribution target of BD Hub Project Version.',
    )
    if flag & ArgsProjVerEPparMask.CLONE_URL__OPT:
        parser.add_argument(
            '--clone-url',
            type=utils.parse_type__str_need_non_empty,
            help='BD Hub Project Version URL clone source.',
        )


if __name__ == '__main__':
    sys.exit(main())
