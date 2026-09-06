"""The test package.

Imported by both runners before any test module - pytest resolves the
`tests.no_lan` imports through it, and `unittest discover -s tests`
imports the package it discovers in - which is what makes the mDNS guard
non-optional: see no_lan.
"""

from . import no_lan

no_lan.install()
