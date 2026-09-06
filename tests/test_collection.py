"""CI runs `unittest discover`, which collects only TestCase methods.

A bare `def test_x()`, a `@pytest.mark.parametrize`, or a pytest fixture
collects under pytest and not at all under unittest, so the day one is
added CI reports green over a test nobody ran. Nothing trips it today -
the string "pytest" appears nowhere in tests/, and pytest and unittest
collect the same 617 ids - and this is what keeps it that way.

Pinning a collection count in CI would do the same job and would need
editing on every test added. This names the constructs instead, so the
failure says what to do about it.
"""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TESTS_DIR = Path(__file__).resolve().parent


def _decorator_names(node):
    for dec in node.decorator_list:
        while isinstance(dec, ast.Call):
            dec = dec.func
        parts = []
        while isinstance(dec, ast.Attribute):
            parts.append(dec.attr)
            dec = dec.value
        if isinstance(dec, ast.Name):
            parts.append(dec.id)
        yield ".".join(reversed(parts))


def _base_names(node):
    for base in node.bases:
        if isinstance(base, ast.Name):
            yield base.id
        elif isinstance(base, ast.Attribute):
            yield base.attr


class CollectionTest(unittest.TestCase):
    def _modules(self):
        for path in sorted(TESTS_DIR.glob("test_*.py")):
            yield path, ast.parse(path.read_text())

    def test_no_module_level_test_function_is_left_uncollected(self):
        # unittest collects test_* methods of TestCase subclasses and
        # nothing else; a module-level def test_x() is a pytest test that
        # CI would never run.
        stray = [f"{path.name}:{node.lineno} {node.name}"
                 for path, tree in self._modules()
                 for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name.startswith("test_")]
        self.assertEqual(stray, [], "module-level test functions; unittest collects none of these, "
                                    "so CI would stay green over them. Put them in a TestCase.")

    def test_every_class_holding_tests_is_a_testcase(self):
        # A class with test_ methods that does not reach unittest.TestCase
        # is collected by pytest and skipped by unittest, silently.
        stray = []
        for path, tree in self._modules():
            cases = {"TestCase"}
            classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
            for _pass in range(len(classes) + 1):     # bases may be defined above, in any order
                for node in classes:
                    if cases.intersection(_base_names(node)):
                        cases.add(node.name)
            for node in classes:
                methods = [m.name for m in node.body
                           if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                           and m.name.startswith("test_")]
                if methods and not cases.intersection(_base_names(node)):
                    stray.append(f"{path.name}:{node.lineno} {node.name}")
        self.assertEqual(stray, [], "classes with test_ methods that are not unittest.TestCase "
                                    "subclasses; unittest collects none of their tests.")

    def test_nothing_depends_on_pytest(self):
        # Fixtures, parametrize and pytest.raises all vanish under
        # unittest discover, and installing pytest in CI is not the
        # answer while the suite is written for unittest.
        hits = []
        for path, tree in self._modules():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    hits += [f"{path.name}:{node.lineno} import {a.name}"
                             for a in node.names if a.name.split(".")[0] == "pytest"]
                elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "pytest":
                    hits.append(f"{path.name}:{node.lineno} from {node.module} import ...")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    hits += [f"{path.name}:{node.lineno} @{name}"
                             for name in _decorator_names(node) if name.split(".")[0] == "pytest"]
        self.assertEqual(hits, [], "pytest constructs in a suite CI runs with unittest discover.")


if __name__ == "__main__":
    unittest.main()
