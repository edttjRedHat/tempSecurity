#!/usr/bin/env python3

'''Helper tool for interacting with OSM Server.'''
# pylint: disable=too-many-lines

import argparse
import dataclasses
import datetime
import email.utils
import logging
import pathlib
import re
import sys
from typing import Any, List, Tuple, Dict, Union, NamedTuple
from urllib.parse import urlparse

import coreapi

from py_libs.custom_types import NamedDict


class OSMapiSpec(NamedTuple):
    '''
    OSM API specification.
    '''
    class ParsKind(NamedTuple):
        '''
        OSM API Parameter requirement kind.
        '''
        mand: Tuple[str]
        optl: Tuple[str]
    path: str
    pars: ParsKind
    keys: Tuple[str]
    pages: bool


@dataclasses.dataclass
class OSMclient:
    '''
    OSM Client connection.
    '''
    client: coreapi.Client
    schema: Any = None


OSM_API_SPEC = {
    'create-osm-rel': OSMapiSpec(
        'release create',
        OSMapiSpec.ParsKind(
            (
                'product_id', 'version', 'release_type', 'osl_date',
                'product_license_id', 'associated_bossd_release',
                'release_mgr_id', 'eng_mgr_id', 'product_mgr_id',
            ),
            ('cc_id', 'vp_contact_id'),
        ),
        (), False,
    ),
    'get-license': OSMapiSpec(
        'license read',
        OSMapiSpec.ParsKind(('id',), ()),
        (), False,
    ),
    'get-osm-rel': OSMapiSpec(
        'release read',
        OSMapiSpec.ParsKind(('id',), ()),
        (), False,
    ),
    'get-product': OSMapiSpec(
        'product read',
        OSMapiSpec.ParsKind(('id',), ()),
        (), False,
    ),
    'get-vmw-rel': OSMapiSpec(
        'rmrelease read',
        OSMapiSpec.ParsKind(('rm_id',), ()),
        (), False,
    ),
    'query-license': OSMapiSpec(
        'license list',
        OSMapiSpec.ParsKind((), ('value',)),
        ('results',), True,
    ),
    'query-osm-rel': OSMapiSpec(
        'release list',
        OSMapiSpec.ParsKind(('product_name',), ('version',)),
        ('results',), True,
    ),
    'query-prod-lic': OSMapiSpec(
        'product_license list',
        OSMapiSpec.ParsKind((), ('license',)),
        ('results',), True,
    ),
    'query-user': OSMapiSpec(
        'user list',
        OSMapiSpec.ParsKind(('email',), ()),
        ('results',), True,
    ),
    'query-vmw-rel': OSMapiSpec(
        'rmrelease list',
        OSMapiSpec.ParsKind(('rm_name', 'rm_version'), ()),
        ('results',), True,
    ),
    'update-osm-rel': OSMapiSpec(
        'release update',
        OSMapiSpec.ParsKind(('id', 'release_from_id'), ()),
        (), False,
    ),
}


def cmd_check_osm_rel(args: argparse.Namespace, osm: OSMclient) -> int:
    '''
    Execute sub-command `check-vmw-rel`.

    Args:
        args:   Command line arguments.
        osm:    OSMclient instance.
    Return:
        0:  Command is successfully executed.
        >0: Command execution yields error.
    '''
    ret_val = 0

    info_list = _query_osm(
        osm,
        NamedDict(
            cmd='query-osm-rel',
            pars=NamedDict(
                product_name=args.osm_rel_name,
                version=args.osm_rel_ver,
            ),
        ),
        args.dry_run,
    )
    if not args.dry_run:
        if info_list:
            verdict = 'exists'
            info = info_list[0]
            status = ' [' \
                f'status: {info.status}; ' \
                f'osl_generated: {info.osl_generated}' \
                ']'
        else:
            verdict = 'does not exist'
            status = ''
            ret_val = 1
        logging.info(
            f'OSM Release {verdict}: {args.osm_rel_name} '
            f'{args.osm_rel_ver}{status}',
        )

    return ret_val


def cmd_check_vmw_rel(args: argparse.Namespace, osm: OSMclient) -> int:
    '''
    Execute sub-command `check-vmw-rel`.

    Args:
        args:   Command line arguments.
        osm:    OSMclient instance.
    Return:
        0:  Command is successfully executed.
        >0: Command execution yields error.
    '''
    ret_val = 0

    # Ensure VMware Release has been created (in BOSS Director and sync:ed to
    #   OSM Server).
    info_list = _query_osm(
        osm,
        NamedDict(
            cmd='query-vmw-rel',
            pars=NamedDict(
                rm_name=args.vmw_rel_name,
                rm_version=args.vmw_rel_ver,
            ),
        ),
        args.dry_run,
    )
    if not args.dry_run:
        if info_list:
            verdict = 'exists'
        else:
            verdict = 'does not exist'
            ret_val = 1
        logging.info(
            f'VMware Release {verdict}: {args.vmw_rel_name} '
            f'{args.vmw_rel_ver}',
        )

    return ret_val


def cmd_create_osm_rel(args: argparse.Namespace, osm: OSMclient) -> int:
    '''
    Execute sub-command `create-osm-rel`.

    Args:
        args:   Command line arguments.
        osm:    OSMclient instance.
    Return:
        0:  Command is successfully executed.
        >0: Command execution yields error.
    '''
    return int(not _create_osm_rel(osm, args))


def cmd_list_license(args: argparse.Namespace, osm: OSMclient) -> int:
    '''
    Execute sub-command `list-license`.

    Args:
        args:   Command line arguments.
        osm:    OSMclient instance.
    Return:
        0:  Command is successfully executed.
        >0: Command execution yields error.
    '''
    ret_val = 0

    lic_list = _list_license(osm, args.dry_run)
    if not args.dry_run:
        if lic_list:
            for lic in lic_list:
                logging.info(f'Product License: {lic}')

    return ret_val


def cmd_list_osm_rel(args: argparse.Namespace, osm: OSMclient) -> int:
    '''
    Execute sub-command `list-osm-rel`.

    Args:
        args:   Command line arguments.
        osm:    OSMclient instance.
    Return:
        0:  Command is successfully executed.
        >0: Command execution yields error.
    '''
    ret_val = 0

    osm_rel_list = _list_osm_rel(osm, args)
    if not args.dry_run:
        if osm_rel_list:
            for osm_rel in osm_rel_list:
                osm_prod = _get_osm_prod(osm, osm_rel)
                logging.info(
                    f'OSM Release: {osm_prod.name} {osm_rel.version}',
                )
        elif osm_rel_list is None:
            ret_val = 1
        else:
            logging.info('Does not contain any OSM Release.')

    return ret_val


def main() -> int:
    '''
    Primary entry point for executing this helper tool. Command
    line arguments are parsed and the requested action evaluated.

    Return:
        0:  Command is successfully executed.
        >0: Command execution yields error.
    '''
    args = _parse_args()
    _setup_logging(args.log_level)

    if args.osm_auth:
        if args.osm_auth[0] == 'pwd':
            auth = coreapi.auth.BasicAuthentication(
                *args.osm_auth[1:2],
                urlparse(args.osm_url).netloc,
            )
        else:
            auth = coreapi.auth.TokenAuthentication(
                ':'.join(args.osm_auth[1:]), 'ApiKey',
                urlparse(args.osm_url).netloc,
            )
    else:
        auth = None

    osm = OSMclient(coreapi.Client(auth=auth))
    osm.schema = osm.client.get(args.osm_url)
    _a_update_schema(osm.schema)    # Temporary workaround

    # Run the sub-command.
    # pylint: disable=eval-used
    funcname = f"cmd_{args.sub_cmd.replace('-', '_')}"
    return eval(funcname)(args, osm)


def _a_update_schema(obj):
    # Temporary workaround until OSM Server fix the HTTP Resp. Re-Direction
    #   code or update `coreapi` schema to use `https` (avoiding re-direction
    #   altogether).
    # pylint: disable=protected-access
    for val in obj.values():
        if isinstance(val, coreapi.Object):
            _a_update_schema(val)
        elif isinstance(val, coreapi.Link):
            val._url = re.sub(r'^(http)(:)', r'\1s\2', val._url)


def _cast_args_auth(value: Any) -> Tuple[str]:
    auth_pars = value.split(':', 2)
    if len(auth_pars) == 3:
        if auth_pars[0] not in ('pwd', 'api'):
            raise ValueError(value)
    else:
        raise ValueError(value)
    for par in auth_pars[1:2]:
        if par == '':
            raise ValueError(value)
    return tuple(auth_pars)


def _cast_args_email(value: Any) -> str:
    name, email_addr = email.utils.parseaddr(value)
    if (
            name or
            (not email_addr) or
            (email_addr.find('@') < 1) or
            email_addr.endswith('@')
    ):
        raise ValueError(value)
    return value


def _cast_args_osm_osl_date(value: Any) -> str:
    return datetime.datetime.strptime(value, '%Y-%m-%d').strftime('%Y-%m-%d')


def _cast_args_osm_rel_name_ver(value: Any) -> Tuple[str]:
    name_rel = value.split(':')
    if len(name_rel) == 1:
        name_rel.append(None)
    elif len(name_rel) == 2:
        if name_rel[0] == '':
            raise ValueError(value)
    else:
        raise ValueError(value)
    return tuple(name_rel)


def _cast_args_osm_rel_type(value: Any) -> str:
    if value not in (
            'Beta',
            'RC',
            'GA',
    ):
        raise ValueError(value)
    return value


def _create_osm_rel(
        osm: OSMclient, args: argparse.Namespace,
) -> bool:
    '''
    List all OSM Releases of the specified VMware Release version.

    Args:
        osm:    OSMclient instance.
        args:   Command line arguments.
    Return:
        Verdict on successful execution.
    '''
    # Ensure VMware Release has been created (in BOSS Director and sync:ed to
    #   OSM Server).
    info_list = _query_osm(
        osm,
        NamedDict(
            cmd='query-vmw-rel',
            pars=NamedDict(
                rm_name=args.vmw_rel_name,
                rm_version=args.vmw_rel_ver,
            ),
        ),
    )
    if not info_list:
        logging.error(
            f"VMware Release does not exist: "
            f'{args.vmw_rel_name} {args.vmw_rel_ver}',
        )
        return False

    vmw_rel_id = info_list[0].rm_id

    if args.osm_rel_name_ver[1] is None:
        new_version = args.vmw_rel_ver
    else:
        new_version = args.osm_rel_name_ver[1]

    # Check if the requested OSM Release Version has been created.
    info_list = _query_osm(
        osm,
        NamedDict(
            cmd='query-osm-rel',
            pars=NamedDict(
                product_name=args.osm_rel_name_ver[0],
                version=new_version,
            ),
        ),
    )
    if info_list:
        if args.osm_clone:
            logging.error(
                'Cloning to existing OSM Release Version is not yet '
                'supported.',
            )
        else:
            osm_rel = info_list[0]
            osm_prod = _get_osm_prod(osm, osm_rel)
            logging.error(
                'OSM Release has already existed: '
                f'{osm_prod.name} {osm_rel.version}',
            )
        return False

    if not args.osm_clone:
        logging.error(
            'Creating new OSM Release without cloning is not yet '
            'supported.',
        )
        return False

    # Check if the cloned OSM Release Version exist and valid.
    info_list = _query_osm(
        osm,
        NamedDict(
            cmd='query-osm-rel',
            pars=NamedDict(
                product_name=args.osm_rel_name_ver[0],
                version=args.osm_clone,
            ),
        ),
    )
    if not info_list:
        logging.error(
            'Cloned OSM Release does not exist: '
            f'{args.osm_rel_name_ver[0]} {args.osm_clone}',
        )
        return False

    osm_rel = info_list[0]
    if (
            (osm_rel.status == 'pending') or
            (
                (osm_rel.status == 'cancelled') and
                not osm_rel.osl_generated
            )
    ):
        logging.error(
            'The OSM Release is not in a good state to be cloned: '
            f'{args.osm_rel_name_ver[0]} {args.osm_clone}',
        )
        return False

    return _do_clone_osm_rel(
        osm, args,
        NamedDict(
            old_osm_rel=NamedDict(_get_osm(
                osm, OSM_API_SPEC['get-osm-rel'],
                NamedDict(info=dict(id=osm_rel.id)),
            )),
            new_version=new_version,
            vmw_rel_id=vmw_rel_id,
        ),
    )


def _do_clone_osm_rel(
        osm: OSMclient, args: argparse.Namespace, data: NamedDict,
) -> bool:
    '''
    List all OSM Releases of the specified VMware Release version.

    Args:
        osm:    OSMclient instance.
        args:   Command line arguments.
        data:   User Data.
                    data.old_osm_rel (NamedDict):
                        Previous OSM Release Version as clone source.
                    data.new_version (str):
                        Requested OSM Release Version as clone target.
                    data.vmw_rel_id (str):
                        VMware Release Version Id.
    Return:
        Verdict on successful execution.
    '''
    # pylint: disable=too-many-branches
    if args.osm_license:
        if args.osm_license in _list_license(osm):
            pl_id = _query_osm(
                osm,
                NamedDict(
                    cmd='query-license',
                    pars=NamedDict(value=args.osm_license),
                ),
            )[0].id
            pl_id = _query_osm(
                osm,
                NamedDict(
                    cmd='query-prod-lic',
                    pars=NamedDict(license=pl_id),
                ),
            )[0].id
            print(pl_id)
    else:
        # /api/public/v1/product_license/1/
        pl_id = data.old_osm_rel.product_license.split('/')[-2]
    if args.osm_rm_email:
        rm_id = _get_user_id(osm, NamedDict(email=args.osm_rm_email))
    else:
        # /api/public/v1/user/83555/
        rm_id = data.old_osm_rel.release_mgr.split('/')[-2]
    if args.osm_em_email:
        em_id = _get_user_id(osm, NamedDict(email=args.osm_em_email))
    else:
        # /api/public/v1/user/83555/
        em_id = data.old_osm_rel.eng_mgr.split('/')[-2]
    if args.osm_pm_email:
        pm_id = _get_user_id(osm, NamedDict(email=args.osm_pm_email))
    else:
        # /api/public/v1/user/83555/
        pm_id = data.old_osm_rel.product_mgr.split('/')[-2]
    cc_id_list = []
    if args.osm_cc_emails:
        for elem in args.osm_cc_emails:
            cc_id_list.append(_get_user_id(osm, NamedDict(email=elem)))
    else:
        # [/api/public/v1/user/83555/, ...]
        for elem in data.old_osm_rel.cc:
            cc_id_list.append(elem.split('/')[-2])
    vp_id = ''
    if args.osm_vp_email:
        vp_id = _get_user_id(osm, NamedDict(email=args.osm_vp_email))
    elif data.old_osm_rel.vp_contact:
        # /api/public/v1/user/83555/
        vp_id = data.old_osm_rel.vp_contact.split('/')[-2]
    info = dict(
        # /api/public/v1/product/9081/
        product_id=data.old_osm_rel.product.split('/')[-2],
        version=data.new_version,
        release_type=args.osm_rel_type,
        osl_date=args.osm_osl_date,
        product_license_id=pl_id,
        associated_bossd_release=data.vmw_rel_id,
        release_mgr_id=rm_id,
        eng_mgr_id=em_id,
        product_mgr_id=pm_id,
    )
    if cc_id_list:
        info.update(cc_id=cc_id_list)
    if vp_id:
        info.update(vp_contact_id=vp_id)

    # Create new OSM Release Version.
    new_osm_rel = NamedDict(_get_osm(
        osm, OSM_API_SPEC['create-osm-rel'],
        NamedDict(info=info, dry_run=args.dry_run),
    ))

    # Request to clone Packages and Release References.
    if args.dry_run:
        new_osm_rel.___update___(id='<xxx>')
    _get_osm(
        osm, OSM_API_SPEC['update-osm-rel'],
        NamedDict(
            info=dict(
                id=new_osm_rel.id,
                release_from_id=data.old_osm_rel.id,
            ),
            dry_run=args.dry_run,
        ),
    )

    return True


def _get_osm(
        osm: OSMclient, api_spec: OSMapiSpec,
        data: Union[None, NamedDict] = None,
) -> Any:
    '''
    Send request to OSM for a specific information.

    Args:
        osm:        OSMclient instance.
        api_spec:   OSM REST API specification.
        data:       User Data.
                        data.info (dict):
                            This data structure must have attributes as listed
                            by `api_spec.pars.mand` and optionally
                            `api_spec.pars.opts`.
                        data.dry_run (bool) [optional]:
                            Whether the actual request towards OSM Server is
                            carried out or not.
    Return:
        Requested OSM information or `{}` if `data.dry_run==True`.
    '''
    osm_info = {}
    api_pars = {}
    for par in api_spec.pars.mand:
        api_pars.update({par: data.info[par]})
    for par in api_spec.pars.optl:
        if par in data.info:
            api_pars.update({par: data.info[par]})
    if ('dry_run' in data) and data.dry_run:
        pars = ''
        for (key, val) in api_pars.items():
            if isinstance(val, list):
                str_val = repr(','.join(val))
            else:
                str_val = repr(val)
            pars += f' -p {key}={str_val}'
        logging.info(f'coreapi action {api_spec.path}{pars}')
    else:
        osm_info = _req_osm(
            osm, api_spec.path.split(), api_pars,
            api_spec.keys, api_spec.pages,
        )
        if not api_spec.pages:
            osm_info = osm_info[0]
    return osm_info


def _get_osm_prod(
        osm: OSMclient, osm_rel: NamedDict,
) -> NamedDict:
    '''
    Get OSM Product information.

    Args:
        osm:        OSMclient instance.
        osm_rel:    OSM Release information.
    Return:
        Requested OSM information.
    '''
    return NamedDict(_get_osm(
        osm, OSM_API_SPEC['get-product'],
        NamedDict(
            info=dict(
                # /api/public/v1/product/9081/
                id=osm_rel.product.split('/')[-2],
            ),
        ),
    ))


def _get_user_id(
        osm: OSMclient, query: NamedDict,
) -> Union[None, str]:
    '''
    Get User Id.

    Args:
        osm:    OSMclient instance.
        query:  Query information.
                    email (str):    OSM query command.
    Return:
        Requested OSM information or `{}` if `dry_run==True`.
    '''
    info_list = _query_osm(
        osm,
        NamedDict(cmd='query-user', pars=query),
    )
    if info_list:
        return str(info_list[0].id)
    raise Exception(f'Can not find User with e-Mail Address: {query.email}')


def _list_license(
        osm: OSMclient, dry_run: bool = False,
) -> Union[List[str], None]:
    '''
    List Product Licenses.

    Args:
        osm:        OSMclient instance.
        dry_run:    Do not send the actual request to OSM Server.
    Return:
        Requested OSM information or `[]` if `args.dry_run==True` or `None` if
        error occurs.
    '''
    lic_list = []

    info_list = _query_osm(
        osm,
        NamedDict(
            cmd='query-prod-lic',
            pars=NamedDict(),
        ),
        dry_run,
    )
    if not dry_run:
        for lic in info_list:
            lic_info = NamedDict(_get_osm(
                osm, OSM_API_SPEC['get-license'],
                NamedDict(
                    info=dict(
                        # /api/public/v1/license/51/
                        id=lic.license.split('/')[-2]
                    ),
                ),
            ))
            lic_list.append(lic_info.value)

    return lic_list


def _list_osm_rel(
        osm: OSMclient, args: argparse.Namespace,
) -> Union[List[NamedDict], None]:
    '''
    List all OSM Releases of the specified VMware Release version.

    Args:
        osm:    OSMclient instance.
        args:   Command line arguments.
    Return:
        Requested OSM information or `[]` if `args.dry_run==True` or `None` if
        error occurs.
    '''
    osm_rel_list = []

    # Ensure VMware Release has been created (in BOSS Director and sync:ed to
    #   OSM Server).
    info_list = _query_osm(
        osm,
        NamedDict(
            cmd='query-vmw-rel',
            pars=NamedDict(
                rm_name=args.vmw_rel_name,
                rm_version=args.vmw_rel_ver,
            ),
        ),
    )
    if info_list:
        info = NamedDict(_get_osm(
            osm, OSM_API_SPEC['get-vmw-rel'],
            NamedDict(info=info_list[0], dry_run=args.dry_run),
        ))
        if info and info.mapping:
            for osm_link in info.mapping:
                osm_rel = NamedDict(_get_osm(
                    osm, OSM_API_SPEC['get-osm-rel'],
                    NamedDict(
                        info=dict(
                            # /api/public/v1/release/23492/
                            id=osm_link.split('/')[-2],
                        ),
                    ),
                ))
                osm_rel_list.append(osm_rel)
    else:
        logging.error(
            f"VMware Release does not exist: "
            f'{args.vmw_rel_name} {args.vmw_rel_ver}',
        )
        osm_rel_list = None

    return osm_rel_list


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--dry-run', action='store_true',
        help='Execute a dry run and skip invoking actual commands and making '
        'API calls',
    )
    parser.add_argument(
        '--log-level',
        default=logging.INFO,
        type=int,
        help='Set the logging level (Default: 20 (INFO)). Any logging that is '
        'higher then the set value will be emitted (See Python Logging for '
        'detail).',
    )
    parser.add_argument(
        '--osm-url',
        default='https://osm.eng.vmware.com/api/public/v1/docs',
        type=str,
        help='OSM REST API Schema URL.',
    )
    parser.add_argument(
        '--osm-auth', type=_cast_args_auth,
        help='Authentication parameter. For basic authentication, use '
        '`pwd:<username>:<password>` format. For API token, use '
        '`api:<email>:<token>` format.',
    )

    subparsers = parser.add_subparsers(dest='sub_cmd', help='Sub-Command Help')

    # Sub-Command.
    subparser = subparsers.add_parser(
        'check-osm-rel',
        help='Check status of a OSM Release',
    )
    _parse_args_osm_rel_1(subparser)

    # Sub-Command.
    subparser = subparsers.add_parser(
        'check-vmw-rel',
        help='Check whether VMware Release has been created.',
    )
    _parse_args_vmw_rel_common(subparser)

    # Sub-Command.
    subparser = subparsers.add_parser(
        'create-osm-rel',
        help='Create or clone OSM Release of a VMware Release.',
    )
    _parse_args_vmw_rel_common(subparser)
    _parse_args_osm_rel_2(subparser)

    # Sub-Command.
    subparser = subparsers.add_parser(
        'list-license',
        help='List Product Licenses.',
    )

    # Sub-Command.
    subparser = subparsers.add_parser(
        'list-osm-rel',
        help='List OSM Releases of a VMware Release.',
    )
    _parse_args_vmw_rel_common(subparser)

    return parser.parse_args()


def _parse_args_vmw_rel_common(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        'vmw_rel_name', type=str,
        help='VMware Release Name.',
    )
    subparser.add_argument(
        'vmw_rel_ver', type=str,
        help='VMware Release Version.',
    )


def _parse_args_osm_rel_1(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        'osm_rel_name', type=str,
        help='OSM Release Name.',
    )
    subparser.add_argument(
        'osm_rel_ver', type=str,
        help='OSM Release Version.',
    )


def _parse_args_osm_rel_2(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        '--osm-clone', type=str,
        help='Previous OSM Release Version to be cloned.',
    )
    subparser.add_argument(
        '--osm-license', type=str,
        help='Product License Type.',
    )
    subparser.add_argument(
        '--osm-rm-email', type=_cast_args_email,
        help='Release Manager e-Mail address.',
    )
    subparser.add_argument(
        '--osm-em-email', type=_cast_args_email,
        help='Engineering Manager e-Mail address.',
    )
    subparser.add_argument(
        '--osm-pm-email', type=_cast_args_email,
        help='Product Manager e-Mail address.',
    )
    subparser.add_argument(
        '--osm-cc-emails', nargs='*', type=_cast_args_email,
        help='CC e-Mail address list.',
    )
    subparser.add_argument(
        '--osm-vp-email', type=_cast_args_email,
        help='Vice President e-Mail address.',
    )
    subparser.add_argument(
        'osm_rel_name_ver', type=_cast_args_osm_rel_name_ver,
        help='OSM Release Name and optionally version (`<name>[:<version>]`).',
    )
    subparser.add_argument(
        'osm_rel_type', type=_cast_args_osm_rel_type,
        help='OSM Release Milestone.',
    )
    subparser.add_argument(
        'osm_osl_date', type=_cast_args_osm_osl_date,
        help='Requested OSL Date.',
    )


def _query_osm(
        osm: OSMclient, query: NamedDict, dry_run: bool = False,
) -> Union[Dict, List[NamedDict]]:
    '''
    Query OSM.

    This generally speaking means using `<xxx>... list` API.

    Args:
        osm:    OSMclient instance.
        query:  Query information.
                    cmd (str):          OSM query command.
                    pars (NamedDict):   OSM query parameters.
        dry_run:    Do not send the actual request to OSM Server.
    Return:
        Requested OSM information or `{}` if `dry_run==True`.
    '''
    ret_val = []

    info_list = _get_osm(
        osm, OSM_API_SPEC[query.cmd],
        NamedDict(info=query.pars, dry_run=dry_run),
    )
    if (isinstance(info_list, list)) and info_list:
        for elem in info_list:
            ret_val.append(NamedDict(elem))
    else:
        ret_val = {}

    return ret_val


def _req_osm(
        osm: OSMclient, api_keys: list, api_pars: dict,
        keys: Tuple[str], pages: bool = False,
        data: Union[None, NamedDict] = None,
) -> List[Any]:
    '''
    Fetches collection of object identified by key tree from OSM.

    Args:
        osm:        OSMclient instance.
        api_keys:   API Action keys.
        api_pars:   API Action parameters.
        keys:       Key tree structure inside the REST API response that its
                    value will be collated as list.
        pages:      The data may come in multiple pages.
        data:       User Data for future extension.
    Returns:
        List of collated objects those are value of specified key structure.
    '''
    _ = data
    wanted_objs = []
    offset = 0
    while True:
        if pages:
            api_pars.update({'offset': offset})
        rsp = osm.client.action(osm.schema, api_keys, api_pars)
        info = rsp
        for key in keys:
            info = info[key]
        if pages:
            wanted_objs += info
            next_url = rsp['next']
            if next_url is not None:
                offset = re.search(
                    r'(?:^|&)offset=(\d+)',
                    urlparse(next_url).query,
                ).group(1)
            else:
                break
        else:
            wanted_objs.append(info)
            break
    return wanted_objs


def _setup_logging(stdout_lvl: int = logging.WARNING) -> None:
    formatter = logging.Formatter('%(asctime)-15s %(levelname)s: %(message)s')

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(stdout_lvl)
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

    file_handler = logging.FileHandler(
        f'{pathlib.PurePath(__file__).stem}.log',
        mode='w',
    )
    file_handler.setLevel(stdout_lvl)
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)

    logging.getLogger().setLevel(stdout_lvl)


if __name__ == '__main__':
    sys.exit(main())
