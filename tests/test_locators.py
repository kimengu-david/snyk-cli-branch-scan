"""Unit tests for the manifest locators and the finding key. Run: python3 -m unittest discover -s tests"""
import importlib.util, os, unittest

spec = importlib.util.spec_from_file_location("enrich", os.path.join(os.path.dirname(__file__), "..", "enrich_snippets.py"))
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)


class ManifestMatch(unittest.TestCase):
    def test_package_json(self):
        self.assertTrue(e.manifest_match("package.json", '    "express": "^4.17.1",', "express"))
        self.assertFalse(e.manifest_match("package.json", '    "express-jwt": "0.1.3",', "express"))

    def test_requirements(self):
        self.assertTrue(e.manifest_match("requirements.txt", "Django==2.2.0", "django"))
        self.assertTrue(e.manifest_match("requirements.txt", "django_rest-framework>=3", "Django-Rest.Framework"))
        self.assertFalse(e.manifest_match("requirements.txt", "requests==2.19.0", "django"))

    def test_go_mod(self):
        self.assertTrue(e.manifest_match("go.mod", "\tgithub.com/gin-gonic/gin v1.6.0", "github.com/gin-gonic/gin"))
        self.assertTrue(e.manifest_match("go.mod", "require github.com/x/y v1.0.0", "github.com/x/y"))

    def test_pom(self):
        self.assertTrue(e.manifest_match("pom.xml", "  <artifactId>log4j-core</artifactId>", "org.apache.logging.log4j:log4j-core"))


class Snippet(unittest.TestCase):
    LINES = [f"line {i}" for i in range(1, 21)]

    def test_context_and_flag(self):
        s = e.snippet(self.LINES, 10, 10, 3)
        self.assertEqual([x["n"] for x in s], list(range(7, 14)))
        self.assertEqual([x["n"] for x in s if x["flagged"]], [10])

    def test_line_past_end_of_file_is_unavailable(self):
        self.assertIsNone(e.snippet(self.LINES, 99, 99, 3))

    def test_code_hash_ignores_whitespace_and_position(self):
        a = ["x = 1", "  eval( y )"]
        b = ["# moved", "", "x = 1", "eval(y)"]
        self.assertEqual(e.code_hash(a, 2, 2), e.code_hash(b, 4, 4))


class FindingKey(unittest.TestCase):
    def test_key_does_not_depend_on_line(self):
        f1 = {"rule": "r", "file": "a.js", "kind": "sast", "start": 10}
        f2 = dict(f1, start=15)
        self.assertEqual(e.finding_key("o/r", f1, "abc"), e.finding_key("o/r", f2, "abc"))

    def test_occurrence_separates_identical_findings(self):
        f = {"rule": "r", "file": "a.js", "kind": "sast"}
        self.assertNotEqual(e.finding_key("o/r", f, "abc", 0), e.finding_key("o/r", f, "abc", 1))


if __name__ == "__main__":
    unittest.main()
