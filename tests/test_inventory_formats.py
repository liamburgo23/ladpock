"""Lockfile and manifest parsers for .NET, Java/Kotlin, Dart/Flutter, Swift and Elixir."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ladpock import inventory
from ladpock.files import FileIndex

FILES = {
    "api/Api.csproj": """<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog" Version="3.*" />
    <PackageReference Include="Dapper">
      <Version>2.0.123</Version>
    </PackageReference>
    <ProjectReference Include="../Core/Core.csproj" />
  </ItemGroup>
</Project>""",
    "api/packages.lock.json": """{"version": 1, "dependencies": {"net8.0": {
  "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"},
  "Core": {"type": "Project"}}}}""",
    "legacy/packages.config": """<?xml version="1.0"?>
<packages><package id="jQuery" version="1.8.2" targetFramework="net45" /></packages>""",
    "shop/pom.xml": """<project>
  <properties><jackson.version>2.9.8</jackson.version></properties>
  <dependencies>
    <!-- <dependency><groupId>ignored</groupId><artifactId>x</artifactId><version>1.0</version></dependency> -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>""",
    "android/gradle.lockfile": "com.squareup.okhttp3:okhttp:4.9.0=releaseRuntimeClasspath\nempty=\n",
    "android/app/build.gradle.kts": 'dependencies {\n    implementation("com.google.code.gson:gson:2.8.5")\n'
                                     '    implementation("androidx.core:core-ktx:1.+")\n}\n',
    "android/gradle/libs.versions.toml": '[versions]\nretrofit = "2.9.0"\n\n[libraries]\n'
                                         'retrofit = { module = "com.squareup.retrofit2:retrofit", version.ref = "retrofit" }\n'
                                         'junit = "junit:junit:4.12"\n',
    "app/pubspec.lock": """packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "0.13.3"
  my_local:
    dependency: "direct main"
    description:
      path: "../my_local"
    source: path
    version: "1.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
""",
    "ios/Package.resolved": """{"pins": [{"identity": "swift-nio", "kind": "remoteSourceControl",
  "location": "https://github.com/apple/swift-nio.git", "state": {"revision": "abc", "version": "2.40.0"}}], "version": 2}""",
    "elixir/mix.lock": '%{\n  "plug": {:hex, :plug, "1.14.0", "abc", [:mix], [], "hexpm", "def"},\n}\n',
}


class NewEcosystems(unittest.TestCase):
    def test_every_format_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            for rel, text in FILES.items():
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            components, warnings = inventory.collect(FileIndex(tmp))
        self.assertEqual(warnings, [])
        found = {(c.ecosystem, c.name, c.version) for c in components}
        expected = {
            ("NuGet", "Newtonsoft.Json", "12.0.1"), ("NuGet", "Dapper", "2.0.123"), ("NuGet", "System.Text.Json", "8.0.0"),
            ("NuGet", "jQuery", "1.8.2"),
            ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
            ("Maven", "com.squareup.okhttp3:okhttp", "4.9.0"), ("Maven", "com.google.code.gson:gson", "2.8.5"),
            ("Maven", "com.squareup.retrofit2:retrofit", "2.9.0"), ("Maven", "junit:junit", "4.12"),
            ("Pub", "http", "0.13.3"), ("SwiftURL", "github.com/apple/swift-nio", "2.40.0"), ("Hex", "plug", "1.14.0"),
        }
        self.assertEqual(expected - found, set())
        names = {c.name for c in components}
        self.assertNotIn("Serilog", names)  # 3.* isn't an exact version
        self.assertNotIn("Core", names)  # project references aren't packages
        self.assertNotIn("my_local", names)  # path dependencies aren't on pub.dev
        self.assertNotIn("ignored:x", names)  # commented out
        self.assertFalse(any(n.endswith("spring-boot-starter-web") for n in names))  # version comes from the parent


if __name__ == "__main__":
    unittest.main()
