#!/usr/bin/env python3
'''Access BlackDuck Hub via REST API.'''

import argparse
from datetime import datetime, timedelta, timezone
import logging
import re
import sys
from typing import Any, Union

import bd_api
from py_libs import utils
from py_libs.custom_types import NamedDict


def cmd__project(
    cmd_args: argparse.Namespace,
    bd_args: str,
    sc_args: NamedDict,
) -> Union[None, str]:
    '''
    Execute command for within `project` context.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                sub_cmd_project (str):  Sub-Command of `project`.
        bd_args:    BlackDuck API module arguments.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Depend on the sub-command.
    '''
    # Run the sub-command.
    funcname = f"project__{cmd_args.sub_cmd_project.replace('-', '_')}"
    sc_args.dbg_hdr.append(f'{funcname}(...):')
    # pylint: disable=eval-used
    return eval(funcname)(cmd_args, bd_args, sc_args)


# pylint: disable=invalid-name
def project__can_version_be_deleted(
    cmd_args: argparse.Namespace,
    bd_args: str,
    sc_args: NamedDict,
) -> str:
    '''
    Check if a Project Version can be deleted from the Project because it
    (or its Parent Project Version) is not the latest of a Release Branch
    anymore.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                main_ver_rgx (str): RegEx pattern to match the `mainline`
                                    version of the product (or version scheme
                                    for branchless release).
                proj_name (str):    Project Name in BD Hub.
                projVer_name (str): Project Version Name in BD Hub.
                parent_proj_name (str): Parent Project Name of the Project.
                rel_ver_info (str): Version information of the Release Branch.
                allowed_phases (list):  List of Project Version Phases that is
                                        allowed to be deleted.
                keep_days (int):        Number of days from creation of the
                                        Project Version before it can be
                                        deleted.
                del_non_match (bool)    Delete Project Version Name if it does
                                        not match the RegEx pattern.
        bd_args:    BlackDuck API module arguments.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Project Version URL if it can be deleted, otherwise empty string.
    '''
    _ = sc_args
    main_ver_rgx = cmd_args.main_ver_rgx
    rel_ver_info = cmd_args.rel_ver_info
    proj_name = cmd_args.proj_name
    projVer_name = cmd_args.projVer_name
    parent_proj_name = cmd_args.parent_proj_name
    (ver, rel_ver_rgx) = rel_ver_info if rel_ver_info else (None, None)
    f_args = NamedDict(
        proj_name=proj_name,
        projVer_name=projVer_name,
        parent_proj_name=parent_proj_name,
        allowed_phases=cmd_args.allowed_phases,
        keep_days=cmd_args.keep_days,
        del_non_match=cmd_args.del_non_match,
    )

    if ver is None:
        ver_rgx_arr = (main_ver_rgx,)
    else:
        # Fall back to main version, if does not match release version, i.e.
        #   the first time a release version is scanned.
        ver_rgx_arr = (rel_ver_rgx.format(ver=ver), main_ver_rgx)
    if parent_proj_name:
        compVer_parent_arr = tuple(bd_api.main(
            bd_args+['project', 'list-parent-urls', proj_name, projVer_name],
        ))
    else:
        compVer_parent_arr = ()

    return projVer_name if _can_delete_version(
        bd_args, f_args, ver_rgx_arr, compVer_parent_arr
    ) else ''


def project__clean_up_projVer(
    cmd_args: argparse.Namespace,
    bd_args: str,
    sc_args: NamedDict,
) -> str:
    '''
    Clean up old and orphan Project Versions.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                main_ver_rgx (str): RegEx pattern to match the `mainline`
                                    version of the product (or version scheme
                                    for branchless release).
                rel_ver_info (str): Version information of the Release Branch.
                proj_fltRgx (str):      RegEx pattern filter of Project Name.
                projVer_fltRgx (str):   RegEx pattern filter of Project Version
                                        Name.
                allowed_phases (list):  List of Project Version Phases that is
                                        allowed to be deleted.
                keep_days (int):        Number of days from creation of the
                                        Project Version before it can be
                                        deleted.
                del_non_match (bool)    Delete Project Version Name if it does
                                        not match the RegEx pattern.
        bd_args:    BlackDuck API module arguments.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        List of Project Version URLs those can be deleted.
    '''
    _ = sc_args
    main_ver_rgx = cmd_args.main_ver_rgx
    rel_ver_info = cmd_args.rel_ver_info
    (ver, rel_ver_rgx) = rel_ver_info if rel_ver_info else (None, None)
    projVer_url_arr = []

    if ver is None:
        ver_rgx_arr = (main_ver_rgx,)
    else:
        ver_rgx_arr = (rel_ver_rgx.format(ver=ver), main_ver_rgx)
    for prj_url in bd_api.main(bd_args+[
        'project', 'list-project-urls',
        '--proj-fltRgx', cmd_args.proj_fltRgx,
    ]):
        # pylint: disable=unnecessary-direct-lambda-call
        for prjVer_url in bd_api.main(bd_args+[
            'project', 'list-version-urls',
            '--proj-url', prj_url,
        ]+(
            lambda val: ['--projVer-fltRgx', val] if val else []
        )(cmd_args.projVer_fltRgx)+['']):
            if tuple(bd_api.main(bd_args+[
                'project', 'list-parent-urls', '--projVer-url', prjVer_url,
                '', '',
            ])):
                # Not orphan.
                continue
            f_args = NamedDict(
                proj_name=bd_api.main(
                    bd_args+['project', 'get-project-name', prj_url]
                ),
                projVer_name=bd_api.main(
                    bd_args+['project', 'get-version-name', prjVer_url]
                ),
                parent_proj_name='',
                allowed_phases=cmd_args.allowed_phases,
                keep_days=cmd_args.keep_days,
                del_non_match=cmd_args.del_non_match,
            )
            if _can_delete_version(bd_args, f_args, ver_rgx_arr, ()):
                projVer_url_arr.append(prjVer_url)
                logging.info(
                    'Found Project/ProjetVersion: ' + bd_api.main(
                        bd_args+['project', 'get-project-name', prj_url]
                    ) + '/' + bd_api.main(
                        bd_args+['project', 'get-version-name', prjVer_url]
                    )
                )

    return projVer_url_arr


def project__get_latest_version(
    cmd_args: argparse.Namespace,
    bd_args: str,
    sc_args: NamedDict,
) -> str:
    '''
    Get latest Project Version URL of a Release Branch in the Project.

    Args:
        cmd_args:   Command line arguments.
            The attributes of interest:
                main_ver_rgx (str): RegEx pattern to match the `mainline`
                                    version of the product (or version scheme
                                    for branchless release).
                proj_name (str):    Project Name in BD Hub.
                rel_ver_info (str): Version information of the Release Branch.
        bd_args:    BlackDuck API module arguments.
        sc_args:    Sub-Command arguments.
                    dbg_hdr (list): Header printouts for debug logging.
    Return:
        Latest Project Version Name if exist, otherwise empty string.
    '''
    _ = sc_args
    main_ver_rgx = cmd_args.main_ver_rgx
    proj_name = cmd_args.proj_name
    (ver, rel_ver_rgx) = cmd_args.rel_ver_info if cmd_args.rel_ver_info \
        else (None, None)
    projVer_name = ''

    if ver is None:
        ver_rgx_arr = (main_ver_rgx,)
    else:
        ver_rgx_arr = (rel_ver_rgx.format(ver=ver), main_ver_rgx)
    projVer_urls = bd_api.main(
        bd_args+['project', 'list-version-urls', proj_name],
    )
    projVer_name_arr = [bd_api.main(
        bd_args+['project', 'get-version-name', elem],
    ) for elem in projVer_urls]
    projVer_name = _get_latest_version(ver_rgx_arr, projVer_name_arr)

    return projVer_name
# pylint: enable=invalid-name


def main(mod_args: str = '') -> Any:    # pylint: disable=inconsistent-return-statements    # noqa: E501
    '''
    Primary entry point for executing this helper tool. Command
    line arguments are parsed and the requested action evaluated.

    Return:
        Depend on the sub-command.
    '''
    _ = mod_args
    args = _parse_args()
    utils.setup_logging(None, *args.log_level)

    bdapi_args = [
        f'--bdhub-api-token={args.bdhub_api_token}',
        f'--bdhub-url={args.bdhub_url}',
        f'--bdhub-conn-timeout={args.bdhub_conn_timeout}',
        f'--bdhub-conn-retry={args.bdhub_conn_retry}',
    ]
    sc_args = NamedDict(
        dbg_hdr=[],
    )

    # Run the sub-command.
    if args.sub_cmd:
        funcname = f"cmd__{args.sub_cmd.replace('-', '_')}"
        sc_args.dbg_hdr.append(f'{funcname}(...):')
        # pylint: disable=eval-used
        results = eval(funcname)(args, bdapi_args, sc_args)
        logging.debug(f'{" ".join(sc_args.dbg_hdr)} {results}')
        print(results)
    # Do `print()` in here, instead of using `logger`, because `logger` is
    #   directed towards STDERR. With this one can easily assign the result
    #   of the sub-command to a shell var., via `varName="$(<thisProg> ...)"`,
    #   without having to parse it to weed out the logging prints.


# pylint: disable=invalid-name
def _can_delete_version(
    bd_args: str,
    f_args: NamedDict,
    ver_rgx_arr: tuple[str],
    compVer_parent_arr: tuple[str],
) -> bool:
    '''
    Check if a version can be deleted.

    A version can be deleted if:
      - For non-orphan Project (it has Parent Project):
         1. Has at least 1 Parent that is not in the same Project of the
            Product.
         2. Has at least 1 Parent that is from other than the investigated
            Release Branch.
         3. None of the Parents is the latest version of the investigated
            Release Branch.
      - For orphan Project:
         1. Not the latest version of the investigated Release Branch OR the
            mainline.

    Args:
        bd_args:    BlackDuck API module arguments.
        f_args:     Function arguments.
                    .proj_name (str):           Project Name in BD Hub.
                    .projVer_name (str):        Project Version Name in BD Hub.
                    .parent_proj_name (str):    Parent Project Name of the
                                                Project.
                    .allowed_phases (list):     List of Project Version Phases
                                                that is allowed to be deleted.
                    .keep_days (int):           Number of days from creation of
                                                the Project Version before it
                                                can be deleted.
                    .del_non_match (bool)       Delete Project Version Name if
                                                it does not match the RegEx
                                                pattern.
        ver_rgx_arr:    List of RegEx patterns to match the version name.
                        The patterns shows up first has higher precedence, so
                        if a candidate is found, the next pattern will NOT be
                        evaluated.
        compVer_parent_arr: List of Parent Project Versions. Set to empty list
                            if it's an orphan Project or if the Parent should
                            not be considered as part decision making.
    Return:
        True if the version can be deleted.
    '''
    # pylint: disable=too-many-locals,consider-using-generator
    proj_name = f_args.proj_name
    projVer_name = f_args.projVer_name
    parent_proj_name = f_args.parent_proj_name
    projVer_ctx = bd_api.main(
        bd_args+['project', 'get-version-context', proj_name, projVer_name],
    )
    no_del = False

    if (
        (projVer_ctx['phase'] not in f_args.allowed_phases) or
        (
            datetime.now(timezone.utc) -
            datetime.fromisoformat(projVer_ctx['createdAt']) <=
            timedelta(days=f_args.keep_days)
        ) or
        not (
            f_args.del_non_match or
            any(
                re.fullmatch(ver_rgx, projVer_name) for ver_rgx in ver_rgx_arr
            )
        )
    ):
        no_del = True
    elif compVer_parent_arr:
        while True:
            # Check if used by other Projects.
            logging.debug(
                'Check if used by other Project: '
                f'{parent_proj_name} {compVer_parent_arr}',
            )
            for elem in compVer_parent_arr:
                proj_url = elem[0:elem.find('/versions/')]
                if bd_api.main(
                    bd_args+['project', 'get-project-name', proj_url],
                ) != parent_proj_name:
                    no_del = True
                    break
            if no_del:
                break
            # Check if used by other Project Versions of a Release Branch in
            #   the Parent Project.
            parentProjVer_projVer_name_arr = tuple([bd_api.main(
                bd_args+['project', 'get-version-name', elem],
            ) for elem in compVer_parent_arr])
            logging.debug(
                'Check if used by other Project Version: '
                f'{ver_rgx_arr[0]} {parentProjVer_projVer_name_arr}',
            )
            for elem in parentProjVer_projVer_name_arr:
                if re.fullmatch(ver_rgx_arr[0], elem):
                    continue
                no_del = True
                break
            if no_del:
                break
            # Check if used by the latest Project Version of a Release Branch
            #   in the Parent Project.
            parentProj_projVer_urls = bd_api.main(
                bd_args+['project', 'list-version-urls', parent_proj_name],
            )
            parentProj_projVer_name_arr = tuple([bd_api.main(
                bd_args+['project', 'get-version-name', elem],
            ) for elem in parentProj_projVer_urls])
            latest_parent_projVer_name = _get_latest_version(
                ver_rgx_arr, parentProj_projVer_name_arr,
            )
            logging.debug(
                'Check if used by the latest Project Version: '
                f'{latest_parent_projVer_name} '
                f'{parentProjVer_projVer_name_arr}',
            )
            if _get_latest_version(
                ver_rgx_arr, parentProjVer_projVer_name_arr,
            ) == latest_parent_projVer_name:
                no_del = True
            break
    else:   # No Parent Project.
        # Check if it is the latest Project Version of a Release Branch OR the
        #   mainline.
        projVer_urls = bd_api.main(
            bd_args+['project', 'list-version-urls', proj_name],
        )
        projVer_name_arr = tuple([bd_api.main(
            bd_args+['project', 'get-version-name', elem],
        ) for elem in projVer_urls])
        if _get_latest_version(ver_rgx_arr, projVer_name_arr) == projVer_name:
            no_del = True
        logging.debug(
            'Check if used by the latest own Project Version: '
            f'{projVer_name} {projVer_name_arr}',
        )

    return not no_del


def _get_latest_version(
    ver_rgx_arr: tuple[str],
    ver_name_arr: tuple[str],
) -> str:
    '''
    Get latest version name from an array based on the given RegEx patterns.

    Args:
        ver_rgx_arr:    Tuple of RegEx patterns to match the version name.
                        The patterns shows up first has higher precedence, so
                        if a candidate is found, the next pattern will NOT be
                        evaluated.
        ver_name_arr:   Tuple of version names to be matched on.
    Return:
        Latest Project Version Name if exist, otherwise empty string.
    '''
    cand_map = {}
    ret_val = ''

    for ver_rgx in ver_rgx_arr:
        for name in ver_name_arr:
            match = re.fullmatch(ver_rgx, name)
            if not match:
                continue
            match_cap = [elem for elem in match.groups() if elem is not None]
            if match_cap:
                map_val = name
                for elem in tuple(reversed(match_cap)):
                    sub_map = {elem: map_val}
                    map_val = sub_map
            else:   # Match alternate pattern without any capture.
                sub_map = {-1: name}
            utils.nested_update(cand_map, sub_map)
        if cand_map:
            #  Matching version name is found, do not evaluate next pattern.
            break
    if cand_map:
        item = cand_map
        while isinstance(item, dict):
            item = item[sorted(item.keys(), key=int, reverse=True)[0]]
        ret_val = item

    return ret_val
# pylint: enable=invalid-name


def _parse_args() -> argparse.Namespace:
    '''
    Add CLI arguments.
    '''
    # pylint: disable=duplicate-code,protected-access
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Main Program.
    utils.parse_args__log_level(parser)
    bd_api._parse_args__bdhub(parser)

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

    common_opt__ver_info = argparse.ArgumentParser(add_help=False)
    _parse_args__ver_info(common_opt__ver_info)

    #   Sub-Command `project.get-project`.
    subparser = subparsers__project.add_parser(
        'get-latest-version',
        help='Get latest Project Version URL of a Release Branch in the '
        'Project.',
        parents=[common_opt__ver_info],
    )
    bd_api._parse_args__proj_ver(
        subparser,
        (bd_api.ArgsProjVerMask.PROJ__NAME__POS),
    )

    #   Sub-Command `project.can-version-be-deleted`.
    subparser = subparsers__project.add_parser(
        'can-version-be-deleted',
        help='Check if a Project Version can be deleted from the Project '
        'because it (or its Parent Project Version) is not the latest '
        'anymore.',
        parents=[common_opt__ver_info],
    )
    bd_api._parse_args__proj_ver(
        subparser,
        (
            bd_api.ArgsProjVerMask.PROJ__NAME__POS |
            bd_api.ArgsProjVerMask.PROJ_VER__NAME__POS
        ),
    )
    _parse_args__ver_del_crit(subparser)
    subparser.add_argument(
        'parent_proj_name',
        type=str,
        help='Parent Project Name of the Project. Set to empty string to '
        'indicate that there is no Parent Project for this Project.',
    )

    #   Sub-Command `project.clean-up-projVer`.
    subparser = subparsers__project.add_parser(
        'clean-up-projVer',
        help='Clean up old and orphan Project Versions.',
        parents=[common_opt__ver_info],
    )
    bd_api._parse_args__proj_ver(
        subparser,
        (
            bd_api.ArgsProjVerMask.PROJ__FLT_RGX__OPT |
            bd_api.ArgsProjVerMask.PROJ_VER__FLT_RGX__OPT
        ),
    )
    _parse_args__ver_del_crit(subparser)

    return parser.parse_args()


def _parse_args__ver_info(parser: argparse.ArgumentParser) -> None:
    '''
    Add CLI arguments for BlackDuck Hub Project Version identification.
    '''
    parser.add_argument(
        '--rel-ver-info',
        default=(),
        type=_parse_type__rel_ver_info,
        help='Version information of the Release Branch. Skip to indicate '
        '`mainline` branch or branchless release. Syntax: '
        '<relVerVal>|<relVerRgx>. Where: relVerVal = Release Branch Version, '
        "e.g. `1.2.3`; relVerRgx = RegEx pattern to match the release version "
        'of the product (the final construct of this pattern is generated via '
        r'`relVerRgx.format(ver=verVerVal)`), e.g. `{ver}-(\d+)` (the `{ver}` '
        r'will be replaced with `relVerVal` and become `1.2.3-(\d+)`). For '
        'further detail, see `main_ver_rgx`.',
    )
    parser.add_argument(
        'main_ver_rgx',
        type=utils.parse_type__str_need_non_empty,
        help='RegEx pattern to match the mainline version of the product (or '
        'version scheme for branchless release). MUST be a full match. E.g. '
        r'`(\d+)\.(\d+)\.(\d+)-(\d+)`. This will pick `1.2.3-200` over '
        '`1.2.3-100`, or `1.2.3-100` over `1.1.4-200`. ONLY integer can be '
        'captured, otherwise it will cause failure. It is allowed to ONLY '
        'have 1 alternate pattern without any capture, e.g. '
        r'`(\d+)-SNAPSHOT-(\d+)|latest`. In this case, version `latest`, if '
        'any, will be picked ONLY if the first pattern fails to match any '
        'existing version.',
    )


def _parse_args__ver_del_crit(parser: argparse.ArgumentParser) -> None:
    '''
    Add CLI arguments for BlackDuck Hub Project Version deletion criteria.
    '''
    parser.add_argument(
        '--allowed-phases', default='PLANNING,DEVELOPMENT',
        type=_parse_type__proj_ver_phase,
        help='List of Project Version Phases that is allowed to be deleted '
        "(def: 'PLANNING,DEVELOPMENT'). Valid choices are 'PLANNING,"
        "DEVELOPMENT,RELEASED,DEPRECATED,ARCHIVED,PRERELEASE'.",
    )
    parser.add_argument(
        '--keep-days', default=7,
        type=int,
        help='Number of days from creation of the Project Version before it '
        'can be deleted (def: 7).',
    )
    parser.add_argument(
        '--del-non-match',
        action='store_true',
        help='Delete Project Version Name if it does not match the RegEx '
        'pattern.',
    )


def _parse_type__proj_ver_phase(val: str) -> tuple[str]:
    '''
    Ensure Argument Value for BlackDuck Hub Project Version Phase is valid.
    '''
    phases = val.split(',')
    for elem in phases:
        if elem not in (
            'PLANNING', 'DEVELOPMENT', 'RELEASED',
            'DEPRECATED', 'ARCHIVED', 'PRERELEASE',
        ):
            raise ValueError(val)
    return phases


def _parse_type__rel_ver_info(val: str) -> tuple[str]:
    '''
    Ensure Argument Value for Version information of the Release Branch is
    valid.
    '''
    info = val.split('|', 1)
    if len(info) != 2:
        raise ValueError(val)
    return tuple(info)


if __name__ == '__main__':
    sys.exit(main())
