#!/usr/bin/env python3

from ...py_libs import decorators


def test_static_func_vars() -> None:
    # pylint: disable=no-value-for-parameter
    @decorators.static_func_vars(var=[])
    def foo(self, val):
        self.var.append(val)

    assert foo.var == []
    foo(1)
    assert foo.var == [1]
    foo(2)
    assert foo.var == [1, 2]
