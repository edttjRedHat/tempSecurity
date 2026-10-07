#!/usr/bin/env python3

'''Collections of custom decorators.'''

from typing import Any, Callable, ParamSpecKwargs


def static_func_vars(**kwargs: ParamSpecKwargs) -> Callable[..., Any]:
    '''
    Decorator to emulate function static variable.

    Args:
        kwargs: Dictionary containing static variable's name and its initial
                value.
    '''
    def init_func_vars(func: Callable[..., Any]) -> Callable[..., Any]:
        # pylint: disable=unnecessary-dunder-call
        for (key, val) in kwargs.items():
            setattr(func, key, val)
        return func.__get__(func, type(func))
    return init_func_vars
