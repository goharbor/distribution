import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))
import check
from binary_scope import ScopeError, discover_files, load_targets


@unittest.skipUnless(shutil.which("go"), "requires Go build-input discovery")
class BinaryScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.targets = {"entrypoints": ["./cmd/registry"], "tags": ["shipping"], "platforms": [
            {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"},
            {"GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0"}]}
        self.write("go.mod", "module example.test/product\n\ngo 1.20\n")
        self.write("cmd/registry/main.go", 'package main\nimport _ "example.test/product/service"\nfunc main() {}\n')
        self.write("service/service.go", "package service\n")

    def write(self, name, data):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data)

    def test_compilation_graph_excludes_tests_tools_and_unreferenced_packages(self):
        self.write("service/service_test.go", 'package service\nimport _ "example.test/product/testonly"\n')
        self.write("testonly/helper.go", "package testonly\n")
        self.write("cmd/helper/main.go", "package main\nfunc main() {}\n")
        self.write("service/testdata/sample.conf", "synthetic fixture\n")
        self.write("build.sh", "#!/bin/sh\necho build\n")
        self.write("docs/example.json", "{}\n")
        self.assertEqual(discover_files(self.root, self.targets), {"cmd/registry/main.go", "service/service.go"})

    def test_release_platform_union_build_tags_generated_code_and_embedded_inputs(self):
        self.write("service/platform_amd64.go", "package service\n")
        self.write("service/platform_arm64.go", "package service\n")
        self.write("service/platform_darwin.go", "package service\n")
        self.write("service/shipping.go", "//go:build shipping\n\npackage service\n")
        self.write("service/unused.go", "//go:build unused_product\n\npackage service\n")
        self.write("service/generated.pb.go", "// Code generated. DO NOT EDIT.\npackage service\n")
        self.write("service/embed.go", 'package service\nimport _ "embed"\n//go:embed assets/settings_test.json\nvar settings string\n')
        self.write("service/assets/settings_test.json", "{}\n")
        files = discover_files(self.root, self.targets)
        self.assertTrue({"service/platform_amd64.go", "service/platform_arm64.go", "service/shipping.go",
                         "service/generated.pb.go", "service/embed.go", "service/assets/settings_test.json"} <= files)
        self.assertFalse({"service/platform_darwin.go", "service/unused.go"} & files)

    def test_unresolved_import_fails_closed(self):
        self.write("service/service.go", 'package service\nimport _ "example.test/product/missing"\n')
        with self.assertRaises(ScopeError):
            discover_files(self.root, self.targets)

    def test_tracked_vendored_inputs_are_included_when_the_product_uses_them(self):
        self.write("go.mod", "module example.test/product\n\ngo 1.20\n\nrequire example.test/library v0.0.0\n")
        self.write("vendor/modules.txt", "# example.test/library v0.0.0\n## explicit; go 1.20\nexample.test/library\n")
        self.write("vendor/example.test/library/source.go", "package library\n")
        self.write("vendor/example.test/library/source_test.go", "package library\n")
        self.write("cmd/registry/main.go", 'package main\nimport _ "example.test/library"\nfunc main() {}\n')
        files = discover_files(self.root, self.targets)
        self.assertIn("vendor/example.test/library/source.go", files)
        self.assertNotIn("vendor/example.test/library/source_test.go", files)

    def test_library_entrypoint_is_rejected(self):
        self.targets["entrypoints"] = ["./service"]
        with self.assertRaises(ScopeError):
            discover_files(self.root, self.targets)

    def test_invalid_target_manifest_cannot_inject_go_arguments(self):
        self.targets["entrypoints"] = ["./../outside"]
        path = self.root / "targets.json"
        path.write_text(json.dumps(self.targets))
        with self.assertRaises(ScopeError):
            load_targets(path)

    def test_changed_line_filter_includes_multiline_matches_and_source_flow_locations(self):
        changes = {"main.go": [(10, 11)]}
        self.assertTrue(check.touches_change({"path": "main.go", "line": 8, "end_line": 10}, changes))
        self.assertTrue(check.touches_change({"path": "main.go", "line": 20, "related_ranges": [(10, 10)]}, changes))
        self.assertFalse(check.touches_change({"path": "main.go", "line": 20}, changes))
        self.assertFalse(check.touches_change({"path": "other.go", "line": 10}, changes))
