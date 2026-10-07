#!/usr/bin/env python3
'''Collections of generic functions.'''

import argparse
import logging
import pathlib
import sys
from typing import Any, Callable, Union


from py_libs.decorators import static_func_vars


def nested_update(dict1: dict, dict2: dict) -> None:
    '''
    Update dictionary `dict1` with `dict2` in recursive manner.

    Args:
        dict1:  The source dictionary to be updated.
        dict2:  The dictionary where the update is coming from.
    Returns:
        None
    '''
    for key in dict2:
        if (
            (key in dict1) and
            isinstance(dict1[key], dict) and
            isinstance(dict2[key], dict)
        ):
            nested_update(dict1[key], dict2[key])
        else:
            dict1[key] = dict2[key]


def parse_args__log_level(
    parser: argparse.ArgumentParser,
    def_val: str = f'{logging.INFO},{logging.DEBUG}:{{}}',
) -> None:
    '''
    Adding CLI arguments for logging level.

    Args:
        parser:     Argument Parser instance.
        def_val:    Default Values.
                    Syntax: <consoleLvl>[,<fileLvl>[:<logFile>]]
                    Where:
                        consoleLvl   := Log level for console logging.
                        fileLvl      := Log level for file logging.
                        logFile      := Log file path (string `{}` will be
                                        replaced with Application Base Name).
    '''
    def_vals = __parse_type__logging(
        def_val.format(f'{pathlib.PurePath(sys.argv[0]).stem}.log')
    )
    parser.add_argument(
        '--log-level',
        default=def_vals,
        type=__parse_type__logging,
        help='Set the logging level. Syntax: '
        '<consoleLvl>[,<fileLvl>[:<logFile>]]. Where: consoleLvl = Log '
        f'level for console logging (def: {def_vals[0]}); fileLvl = Log level '
        f'for file logging (def: {def_vals[2]}; set to negative value to '
        'disable file logging); logFile = Log file path (def: '
        f"'{def_vals[1]}'). Any logging that is higher then the set value "
        'will be emitted (See Python Logging for detail).',
    )
    setup_logging(parser)   # pylint: disable=no-value-for-parameter


def parse_type__int_non_negative(val: str) -> int:
    '''
    Ensure Argument Value Type of `int` is not negative.

    Args:
        val:    Argument Value to be checked.
    '''
    val = int(val)
    if val < 0:
        raise ValueError(val)
    return val


def parse_type__str_need_non_empty(val: str) -> str:
    '''
    Ensure Argument Value Type of `str` is not an empty string.

    Args:
        val:    Argument Value to be checked.
    '''
    val = str(val)
    if not val:
        raise argparse.ArgumentTypeError('Need non-empty string.')
    return val


def parse_type__str_need_non_empty_with_def_from_env_var(val: str) -> str:
    '''
    Ensure Argument Value Type of `str` that if set to an empty string, it will
    take from an Env. Var. and that Env. Var. can not be unset or null.

    Args:
        val:    Argument Value to be checked.
    '''
    val = str(val)
    if not val:
        raise argparse.ArgumentTypeError(
            'Empty string is given or the option is not given while the '
            'corresponding env. var. is unset or null.'
        )
    return val


@static_func_vars(
    func_def_vals=(logging.INFO, '', logging.DEBUG),
    args_def_vals=(None, None, None),
)
def setup_logging(
    self: Callable[..., Any],
    parser: Union[None, argparse.ArgumentParser] = None,
    console_lvl: int = logging.WARNING,
    file_log: str = '', file_lvl: int = -1,
) -> None:
    '''
    Setup logging facilities.

    Args:
        self:           Self ref. (easy access to static func. var.).
        parser:         Command line arguments parser.
            The attributes of interest:
                log_level (str):  Set the logging level.
        console_lvl:    Logging level for console destination.
        file_log:       Log file path.
        file_lvl:       Logging level for file destination.
    '''
    _ = (console_lvl, file_log, file_lvl)
    if parser is not None:
        self.args_def_vals = list(parser.get_default('log_level'))
        return
    # Get the 3rd - 5th Function Argument Names.
    func_arg_names = self.__code__.co_varnames[2:5]

    # Future compatibility.
    # pylint: disable=consider-using-enumerate
    for idx in range(len(self.func_def_vals)):
        if self.args_def_vals[idx] is None:
            self.args_def_vals[idx] = self.func_def_vals[idx]
        arg_name = func_arg_names[idx]
        arg_val = locals()[arg_name]
        self.__dict__[arg_name] = self.args_def_vals[idx] if arg_val is None \
            else arg_val

    formatter = logging.Formatter('%(asctime)-15s %(levelname)s: %(message)s')
    if self.file_lvl < 0:
        self.file_log = ''
    if self.console_lvl < self.file_lvl:
        root_lvl = self.console_lvl
    else:
        root_lvl = self.file_lvl

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(self.console_lvl)
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

    if self.file_log:
        with open(self.file_log, 'a') as log:
            log.write(f"{'-'*20} New Invocation {'-'*20}\n")
        file_handler = logging.FileHandler(self.file_log, 'a')
        file_handler.setLevel(self.file_lvl)
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)

    logging.getLogger().setLevel(root_lvl)


def __parse_type__logging(val: str) -> tuple[Any]:
    '''
    Ensure Argument Value Type for logging is valid.

    Args:
        val:    Argument Value to be checked.
    '''
    (console_lvl, file_log, file_lvl) = (None, None, None)

    data = val.split(',')
    if len(data) == 1:
        data.append('')
    elif ((data[1] == '') or (len(data) > 2)):
        raise ValueError(val)
    if data[0]:
        console_lvl = parse_type__int_non_negative(int(data[0]))
    data = data[1].split(':', 1)
    if len(data) == 2:
        if data[1] == '':
            raise ValueError(val)
        file_log = data[1]
    if data[0]:
        file_lvl = int(data[0])

    return (console_lvl, file_log, file_lvl)
