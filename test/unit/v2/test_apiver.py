import importlib
import inspect
import pkgutil
from typing import Any

import b2sdk.v2


def _is_eligible(name: str, obj: Any):
    if name.startswith('_'):
        return False
    if inspect.isclass(obj) and not issubclass(obj, BaseException):
        return True
    return inspect.isfunction(obj)


def get_defined_symbols_from_module(module):
    defined = set()
    for name, obj in inspect.getmembers(module):
        if _is_eligible(name, obj):
            if getattr(obj, '__module__', '').startswith(module.__name__):
                defined.add(name)
    return defined


def get_names_exposed_by_v2_init():
    """
    Returns all names in b2sdk.v2 that are defined in b2sdk.v2.* modules.
    Ignores re-exports from b2sdk.v3 or elsewhere.
    """
    exposed = set()
    for name, obj in inspect.getmembers(b2sdk.v2):
        if _is_eligible(name, obj):
            obj_module = getattr(obj, '__module__', '')
            if obj_module.startswith('b2sdk.v2'):
                exposed.add(name)
    return exposed


def test_all_v2_symbols_are_exported_from_init():
    root_package = b2sdk.v2
    prefix = root_package.__name__ + '.'
    all_v2_defined_names = set()

    # Step 1: Collect all defined symbols from b2sdk.v2.*
    for finder, name, ispkg in pkgutil.walk_packages(root_package.__path__, prefix):
        module = importlib.import_module(name)
        all_v2_defined_names.update(get_defined_symbols_from_module(module))

    # Step 2: Collect only those exposed in b2sdk.v2 that are actually from b2sdk.v2
    exposed_in_init = get_names_exposed_by_v2_init()

    # Step 3: Find missing re-exports
    missing_exports = sorted(all_v2_defined_names - exposed_in_init)

    assert not missing_exports, (
        'The following symbols are defined in b2sdk.v2.* '
        'but not exposed in b2sdk.v2.__init__.py:\n' + '\n'.join(missing_exports)
    )
