# aepok_sentinel/__init__.py
# FIX #80: This file was missing entirely. Without it, Python cannot
# recognise `aepok_sentinel` as a package, and every `from
# aepok_sentinel.core.xxx import ...` fails with ModuleNotFoundError
# in standard (non-namespace-package) Python installations.
#
# All subdirectories (core/, utils/, cli/, gui/, deploy/, tests/)
# already had their own __init__.py files; only the top-level package
# marker was absent.
