#!/usr/bin/env python3

from ...py_libs import utils


def test_nested_update() -> None:
    dict1 = {
        'a': 1,
        'b': {'bA': 21},
    }
    utils.nested_update(dict1, {
        'a': 10,
        'b': {'bB': 22},
        'c': 30,
    })
    assert dict1 == {
        'a': 10,
        'b': {
            'bA': 21,
            'bB': 22,
        },
        'c': 30,
    }
