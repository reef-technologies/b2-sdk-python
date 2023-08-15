######################################################################
#
# File: b2sdk/utils/wildcards.py
#
# Copyright 2023 Backblaze Inc. All Rights Reserved.
#
# License https://www.backblaze.com/using_b2_code.html
#
######################################################################
from __future__ import annotations

import fnmatch
import pathlib
from enum import Enum
from functools import partial
from typing import Callable

from wcmatch import glob as wcglob


class WildcardStyle(str, Enum):
    GLOB = 'glob'  # support * ? [], [!], no escaping
    SHELL = 'shell'  # support *, **, ?, [], [!], {}, with escaping


def _find_unescaped_char(
    folder_to_list: str, wildcard_character: str, offset: int = 0
) -> int | None:
    """Find the first occurrence of a character in a string, ignoring escaped characters.

    :raises ValueError: no unescaped character is found
    """
    max_index = len(folder_to_list)
    while offset < max_index:
        starter_index = folder_to_list.index(wildcard_character, offset)
        if starter_index is None:
            return None
        elif starter_index > 0 and folder_to_list[starter_index - 1] == '\\':
            # the character is escaped, ignore it
            offset = starter_index + 1
            continue
        return starter_index
    raise ValueError("no unescaped character found")


def get_solid_prefix(
    current_prefix: str, folder_to_list: str, wildcard_style: WildcardStyle
) -> str:
    """If we're running with wildcard-matching, we could get a different prefix from it.
    We search for the first occurrence of the special characters and fetch parent path from that place.

    Examples:
       'b/c/*.txt' –> 'b/c/'
       '*.txt' –> ''
       'a' –> 'a/'
    """
    MATCHERS = {
        # wildcard style: (wildcard match checker, allowed wildcard chars)
        WildcardStyle.SHELL.value:
            (
                _find_unescaped_char,
                ('*', '?', '[', '{'),  # ** is matched via *
            ),
        WildcardStyle.GLOB.value: (
            lambda folder, char: folder.index(char),
            ('*', '?', '['),
        ),
    }

    try:
        finder, charset = MATCHERS[wildcard_style]
    except KeyError:
        raise ValueError(f'Unknown wildcard style: {wildcard_style!r}')

    solid_length = len(folder_to_list)
    for wildcard_character in charset:
        try:
            char_index = finder(folder_to_list, wildcard_character)
        except ValueError:
            continue
        else:
            solid_length = min(char_index, solid_length)

    # +1 to include the starter character.  Using posix path to
    # ensure consistent behaviour on Windows (e.g. case sensitivity).
    path = pathlib.PurePosixPath(folder_to_list[:solid_length + 1])
    parent_path = str(path.parent)

    # Path considers dot to be the empty path.
    # There's no shorter path than that.
    if parent_path == '.':
        return ''

    # We could receive paths in different stage, e.g. 'a/*/result.[ct]sv' has two
    # possible parent paths: 'a/' and 'a/*/', with the first one being the correct one
    return min(parent_path, current_prefix, key=len)


def get_wildcard_matcher(match_pattern: str,
                         wildcard_style: WildcardStyle) -> Callable[[str], bool]:
    """Return a wildcard matcher for chosen style and pattern."""
    if wildcard_style == WildcardStyle.SHELL:
        wc_flags = (
            wcglob.CASE  # case sensitive
            | wcglob.BRACE  # support {} for multiple options
            | wcglob.GLOBSTAR  # support ** for recursive matching
            | wcglob.NEGATE  # support [!] for negation
        )
        wildcard_matcher = partial(
            lambda file_name: wcglob.globmatch(file_name, match_pattern, flags=wc_flags, limit=100)
        )
    elif wildcard_style == WildcardStyle.GLOB:
        wildcard_matcher = partial(lambda file_name: fnmatch.fnmatchcase(file_name, match_pattern))
    else:
        raise ValueError(f"Unknown wildcard style: {wildcard_style}")

    return wildcard_matcher
