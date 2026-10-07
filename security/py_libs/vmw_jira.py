#!/usr/bin/env python3

'''Generic REST API access for JIRA Server Platform'''

import functools
import json
import logging
import time
from types import MethodType
from typing import Any, Callable, List, Tuple, Union, NamedTuple, \
    ParamSpecArgs, ParamSpecKwargs, Self

import requests

from .custom_types import NamedDict, NestedDict

APIs = NamedDict()


class APIfuncCtlPar(NamedTuple):
    '''
    Control Parameter for REST API Method function.

    Parameters:
        retry_max:  Max. no. retry.
        retry_wait: Wait time between retry (in sec.).
        req_pars:   HTTP Request parameters.
    '''
    retry_max: int = 6
    retry_wait: int = 10
    req_pars: dict = {}


class APIpars(NamedTuple):
    '''REST API parameter data.'''
    url_pars: NamedDict = NamedDict()
    query_pars: NamedDict = NamedDict()
    body_pars: Union[None, dict] = None


class PageInfo(NamedTuple):
    '''
    Pagination Control.

    Parameters:
        maxPerPage: Max. no. of records per page (<= 0: API default.).
        maxRecords: Total no. of records (<= 0: All.).
    '''
    maxPerPage: int = 0
    maxRecords: int = 0


class UserData(NamedTuple):
    '''
    User Data.

    Parameters:
        auths:      Authentication parameters.
                    .token (str):
                        API Authentication Token.
        req_pars:   HTTP Request parameters.
    '''
    auths: NamedDict
    req_pars: dict = {}


def _api_func(func_name: str, func_info: NamedDict) -> Callable[..., Any]:
    '''
    Decorator to generate high level API function.

    Args:
        func_name:  Name of high level API function.
        func_info:  Information on how high level API function is generated.
                    .req_args (NamedDict):
                        Values for required arguments for lower level API
                        funtions.
                        See the decorated function for details.
                        .api_meth (M)
                        .api_path (M)
                    .opt_args (NamedDict):
                        Values for optional arguments for lower level API
                        function. If not listed, the default value of the
                        underlying function will be used.
                        See the decorated function for details.
                        .keys (O)
                        .page (O)
                        .keys (O)
    '''
    def x_api_func(dec_f: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(dec_f)
        def x_rest_api(
            self: Self, *args: ParamSpecArgs, **kwargs: ParamSpecKwargs
        ) -> Callable[..., Any]:
            opt_args = ('keys', 'page', 'am_ctl_par')
            dec_f_args = []
            for idx in range(len(args)):    # pylint: disable=consider-using-enumerate  # noqa: E501
                if (
                    (idx < 2) or
                    (idx > 4)
                ):
                    dec_f_args.append(args[idx])
                elif 2 <= idx <= 4:
                    key = opt_args[(idx-2)]
                    if key in kwargs:
                        dec_f_args.append(args[idx])
                    else:
                        kwargs[key] = args[idx]
            dec_f_args = [
                func_info.req_args.api_meth,
                func_info.req_args.api_path,
            ] + dec_f_args
            for key in opt_args:
                if key in func_info.opt_args:
                    if key not in kwargs:
                        kwargs[key] = func_info.opt_args[key]
            return dec_f(self, *dec_f_args, **kwargs)
        x_rest_api.__name__ = func_name
        x_rest_api.__qualname__ = \
            f"{dec_f.__qualname__.split('.')[0]}." \
            "{func_name}"
        return x_rest_api
    return x_api_func


class Jira:
    '''
    REST API interaction towards a Jira Server.
    '''
    # pylint: disable=too-few-public-methods
    def __init__(
            self: Self,
            base_url: str,
            reg_apis: NamedDict = APIs,
            def_am_ctl_par: APIfuncCtlPar = APIfuncCtlPar(),
    ):
        '''
        Args:
            base_url:       Jira Server base URL.
            reg_apis:       APIs to be registered.
            def_am_ctl_par: Default value for `am_ctl_par` in function
                            `_rest_api`.
        '''
        self.__base_url = base_url
        self.__def_am_ctl_par = def_am_ctl_par

        # Generate high level API functions and register it to Class Instance.
        for (key, val) in reg_apis.___items___():
            dec_f = _api_func(key, val)(self.__class__._rest_api)
            setattr(self, dec_f.__name__, MethodType(dec_f, self))

    def _rest_api(
            self: Self,
            api_meth: Callable[..., Any], api_path: str,
            api_pars: APIpars, data: Union[None, UserData] = None,
            keys: Tuple[str] = (), page: Union[None, PageInfo] = None,
            am_ctl_par: Union[None, APIfuncCtlPar] = None,
    ) -> List[Any]:
        '''
        Fetches collection of object identified by key tree using REST API.

        Args:
            api_meth:   REST API Method function to be called.
            api_path:   REST API End Point path.
            api_pars:   REST API parameters.
            data:       User Data.
            keys:       Key tree structure inside the REST API response that
                        its value will be collated as list.
            page:       Pagination Control for data that comes in pages.
            am_ctl_par: Control Parameter for `api_meth`.
        Returns:
            List of collated objects those are value of specified key
            structure.
        '''
        # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        if am_ctl_par is None:
            am_ctl_par = self.__def_am_ctl_par

        r_url = f'{self.__base_url}/{api_path.format(**api_pars.url_pars)}'
        r_kwargs = NestedDict({**am_ctl_par.req_pars, **data.req_pars})
        r_kwargs['headers']['Authorization'] = f'Bearer {data.auths.token}'
        r_kwargs['params'] = page_ctl = {}
        r_args = []

        if api_pars.query_pars:
            r_kwargs['params'].update({**api_pars.query_pars})
        if api_meth is requests.get:
            r_args.append(r_kwargs.pop('params', None))
            if isinstance(api_pars.body_pars, dict):
                r_kwargs['json'] = api_pars.body_pars
        elif api_meth is requests.put:
            if isinstance(api_pars.body_pars, dict):
                r_args.append(json.dumps(api_pars.body_pars))
        elif api_meth is requests.post:
            if isinstance(api_pars.body_pars, dict):
                r_args.extend([None, api_pars.body_pars])
        elif api_meth is requests.delete:
            pass
        else:
            raise Exception(f'Invalid REST API Method function: {api_meth}')
        if page and (page.maxPerPage > 0):
            page_ctl['maxResults'] = page.maxPerPage
        wanted_objs = []
        offset = 0
        while True:
            if page:
                page_ctl['startAt'] = offset
            rsp = None
            count = 0
            while count <= am_ctl_par.retry_max:
                if count:
                    logging.debug(f'Retrying: {count} ...')
                rsp = api_meth(r_url, *r_args, **r_kwargs)
                if (rsp.status_code // 100) == 5:
                    count += 1
                    time.sleep(am_ctl_par.retry_wait)
                    continue
                break
            rsp.raise_for_status()
            if (rsp.status_code // 100) == 2:
                info = rsp_data = rsp.json()
                for key in keys:
                    info = info[key]
                if page:
                    num_rec = len(info)
                    if page.maxRecords > 0:
                        wanted_objs.extend(
                            info[:min((page.maxRecords-offset), num_rec)],
                        )
                    else:
                        wanted_objs.extend(info)
                    offset += num_rec
                    if (
                        (
                            offset >= min(
                                rsp_data['total'],
                                page.maxRecords if page.maxRecords > 0
                                else rsp_data['total'],
                            )
                        ) or
                        (num_rec == 0)
                    ):
                        break
                else:
                    wanted_objs.append(info)
                    break
            else:
                logging.warning(f'JIRA REST API call failed: {rsp}')
                break
        return wanted_objs


APIs.___update___(
    search=NamedDict(
        req_args=NamedDict(
            api_meth=requests.post,
            api_path='search',
        ),
        opt_args=NamedDict(
            keys=['issues'], page=PageInfo(),
        ),
    ),
    issue__create_issue=NamedDict(
        req_args=NamedDict(
            api_meth=requests.post,
            api_path='issue',
        ),
        opt_args=NamedDict(
            keys=[],
        ),
    ),
    issue__get_create_issue_meta_project_issue_types=NamedDict(
        req_args=NamedDict(
            api_meth=requests.get,
            api_path='issue/createmeta/{projectIdOrKey}/issuetypes',
        ),
        opt_args=NamedDict(
            keys=['values'], page=PageInfo(),
        ),
    ),
    issue__get_create_issue_meta_fields=NamedDict(
        req_args=NamedDict(
            api_meth=requests.get,
            api_path='issue/createmeta/{projectIdOrKey}/issuetypes/'
            '{issueTypeId}',
        ),
        opt_args=NamedDict(
            keys=['values'], page=PageInfo(),
        ),
    ),
    issue__edit_issue=NamedDict(
        req_args=NamedDict(
            api_meth=requests.put,
            api_path='issue/{issueIdOrKey}',
        ),
        opt_args=NamedDict(
            keys=[],
        ),
    ),
    issue__get_edit_issue_meta=NamedDict(
        req_args=NamedDict(
            api_meth=requests.get,
            api_path='issue/{issueIdOrKey}/editmeta',
        ),
        opt_args=NamedDict(
            keys=[],
        ),
    ),
    issue__get_issue=NamedDict(
        req_args=NamedDict(
            api_meth=requests.get,
            api_path='issue/{issueIdOrKey}',
        ),
        opt_args=NamedDict(
            keys=[],
        ),
    ),
    issue__get_comments=NamedDict(
        req_args=NamedDict(
            api_meth=requests.get,
            api_path='issue/{issueIdOrKey}/comment',
        ),
        opt_args=NamedDict(
            keys=['comments'], page=PageInfo(),
        ),
    ),
    project__get_project=NamedDict(
        req_args=NamedDict(
            api_meth=requests.get,
            api_path='project/{projectIdOrKey}',
        ),
        opt_args=NamedDict(
            keys=[],
        ),
    ),
)
