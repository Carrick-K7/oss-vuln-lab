from __future__ import annotations

import subprocess
from pathlib import Path

from oss_vuln_digger.models import LanguageName, LanguageProfile, ProjectContext, ScanTarget, TargetMode
from oss_vuln_digger.plugins.base import ProjectAdapter


CPP_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}
PYTHON_SOURCE_SUFFIXES = {".py"}
JAVASCRIPT_SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
JAVA_SOURCE_SUFFIXES = {".java"}
RUST_SOURCE_SUFFIXES = {".rs"}


class CppSourceAdapter(ProjectAdapter):
    name = "cpp_source"

    def supports_target(self, target: ScanTarget) -> bool:
        return self.match_score(target) > 0

    def match_score(self, target: ScanTarget) -> int:
        if target.mode is not TargetMode.SOURCE_REPO:
            return 0
        root = Path(target.resolved_path)
        manifest_bonus = 20 if any((root / name).exists() for name in ("configure", "configure.ac", "autogen.sh", "CMakeLists.txt", "Makefile", "makefile")) else 0
        return manifest_bonus + _source_file_score(root, CPP_SOURCE_SUFFIXES)

    def prepare(self, target: ScanTarget) -> ProjectContext:
        root = Path(target.resolved_path)
        source_files = _collect_source_files(root, CPP_SOURCE_SUFFIXES)
        entrypoint_sources = _entrypoints_by_marker(root, CPP_SOURCE_SUFFIXES, "main(")
        entrypoints = [str(path) for path in entrypoint_sources]
        binary_candidates = {
            str(path.relative_to(root)): _binary_for_cpp_entrypoint(root, path)
            for path in entrypoint_sources
        }
        default_binary = next(iter(binary_candidates.values()), "")
        build_system = _detect_cpp_build_system(root)
        profile = LanguageProfile(
            name=LanguageName.C_CPP,
            manifests=_existing_files(root, ("configure", "configure.ac", "autogen.sh", "CMakeLists.txt", "Makefile", "makefile")),
            source_suffixes=sorted(CPP_SOURCE_SUFFIXES),
            build_system=build_system,
            test_command="make test" if build_system in {"make", "autotools", "configure_make"} else "",
            run_command=_default_cpp_repro_command(default_binary),
        )
        metadata = {
            "language": profile.name.value,
            "supports_binary_analysis": False,
            "build_hint": build_system,
            "binary_candidates": binary_candidates,
            "default_binary": default_binary,
            "suggested_repro_command": profile.run_command,
        }
        return ProjectContext(
            target=target,
            adapter_name=self.name,
            root=str(root),
            build_system=build_system,
            source_files=source_files,
            entrypoints=entrypoints,
            metadata=metadata,
            language_profiles=[profile],
        )


class PythonSourceAdapter(ProjectAdapter):
    name = "python_source"

    def supports_target(self, target: ScanTarget) -> bool:
        return self.match_score(target) > 0

    def match_score(self, target: ScanTarget) -> int:
        if target.mode is not TargetMode.SOURCE_REPO:
            return 0
        root = Path(target.resolved_path)
        manifest_bonus = 25 if any((root / name).exists() for name in ("pyproject.toml", "setup.py", "requirements.txt", "Pipfile")) else 0
        return manifest_bonus + _source_file_score(root, PYTHON_SOURCE_SUFFIXES)

    def prepare(self, target: ScanTarget) -> ProjectContext:
        root = Path(target.resolved_path)
        source_files = _collect_source_files(root, PYTHON_SOURCE_SUFFIXES)
        entrypoints = [
            str(path)
            for path in _entrypoints_by_any_marker(
                root,
                PYTHON_SOURCE_SUFFIXES,
                ("if __name__ == \"__main__\":", "if __name__ == '__main__':"),
            )
        ]
        default_entrypoint = entrypoints[0] if entrypoints else (source_files[0] if source_files else "")
        rel_entrypoint = _relative_to_root(root, default_entrypoint)
        build_system = _detect_python_build_system(root)
        run_command = f"python3 {rel_entrypoint} @payload_path@" if rel_entrypoint else "python3 @payload_path@"
        profile = LanguageProfile(
            name=LanguageName.PYTHON,
            manifests=_existing_files(root, ("pyproject.toml", "setup.py", "requirements.txt", "Pipfile")),
            source_suffixes=sorted(PYTHON_SOURCE_SUFFIXES),
            build_system=build_system,
            test_command="pytest",
            run_command=run_command,
        )
        metadata = {
            "language": profile.name.value,
            "supports_binary_analysis": False,
            "build_hint": build_system,
            "default_binary": f"python3 {rel_entrypoint}".strip(),
            "suggested_repro_command": run_command,
        }
        return ProjectContext(
            target=target,
            adapter_name=self.name,
            root=str(root),
            build_system=build_system,
            source_files=source_files,
            entrypoints=entrypoints,
            metadata=metadata,
            language_profiles=[profile],
        )


class JavaScriptSourceAdapter(ProjectAdapter):
    name = "javascript_source"

    def supports_target(self, target: ScanTarget) -> bool:
        return self.match_score(target) > 0

    def match_score(self, target: ScanTarget) -> int:
        if target.mode is not TargetMode.SOURCE_REPO:
            return 0
        root = Path(target.resolved_path)
        manifest_bonus = 25 if any((root / name).exists() for name in ("package.json", "pnpm-lock.yaml", "yarn.lock")) else 0
        return manifest_bonus + _source_file_score(root, JAVASCRIPT_SOURCE_SUFFIXES)

    def prepare(self, target: ScanTarget) -> ProjectContext:
        root = Path(target.resolved_path)
        source_files = _collect_source_files(root, JAVASCRIPT_SOURCE_SUFFIXES)
        entrypoints = [
            str(path)
            for path in _entrypoints_by_any_marker(
                root,
                JAVASCRIPT_SOURCE_SUFFIXES,
                ("require.main === module", "import.meta.url"),
            )
        ]
        default_entrypoint = entrypoints[0] if entrypoints else (source_files[0] if source_files else "")
        rel_entrypoint = _relative_to_root(root, default_entrypoint)
        build_system = _detect_javascript_build_system(root)
        run_command = f"node {rel_entrypoint} @payload_path@" if rel_entrypoint else "node @payload_path@"
        profile = LanguageProfile(
            name=LanguageName.JAVASCRIPT,
            manifests=_existing_files(root, ("package.json", "pnpm-lock.yaml", "yarn.lock")),
            source_suffixes=sorted(JAVASCRIPT_SOURCE_SUFFIXES),
            build_system=build_system,
            test_command="npm test" if (root / "package.json").exists() else "",
            run_command=run_command,
        )
        metadata = {
            "language": profile.name.value,
            "supports_binary_analysis": False,
            "build_hint": build_system,
            "default_binary": f"node {rel_entrypoint}".strip(),
            "suggested_repro_command": run_command,
        }
        return ProjectContext(
            target=target,
            adapter_name=self.name,
            root=str(root),
            build_system=build_system,
            source_files=source_files,
            entrypoints=entrypoints,
            metadata=metadata,
            language_profiles=[profile],
        )


class JavaSourceAdapter(ProjectAdapter):
    name = "java_source"

    def supports_target(self, target: ScanTarget) -> bool:
        return self.match_score(target) > 0

    def match_score(self, target: ScanTarget) -> int:
        if target.mode is not TargetMode.SOURCE_REPO:
            return 0
        root = Path(target.resolved_path)
        manifest_bonus = 30 if any((root / name).exists() for name in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle")) else 0
        return manifest_bonus + _source_file_score(root, JAVA_SOURCE_SUFFIXES)

    def prepare(self, target: ScanTarget) -> ProjectContext:
        root = Path(target.resolved_path)
        source_files = _collect_source_files(root, JAVA_SOURCE_SUFFIXES)
        entrypoint_files = _entrypoints_by_marker(root, JAVA_SOURCE_SUFFIXES, "public static void main")
        entrypoints = [str(path) for path in entrypoint_files]
        default_class = Path(entrypoints[0]).stem if entrypoints else ""
        build_system = _detect_java_build_system(root)
        run_command = f"java {default_class} @payload_path@" if default_class else "java <main-class> @payload_path@"
        profile = LanguageProfile(
            name=LanguageName.JAVA,
            manifests=_existing_files(root, ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle")),
            source_suffixes=sorted(JAVA_SOURCE_SUFFIXES),
            build_system=build_system,
            test_command="mvn test" if build_system == "maven" else ("gradle test" if build_system == "gradle" else ""),
            run_command=run_command,
        )
        metadata = {
            "language": profile.name.value,
            "supports_binary_analysis": False,
            "build_hint": build_system,
            "default_binary": f"java {default_class}".strip(),
            "suggested_repro_command": run_command,
        }
        return ProjectContext(
            target=target,
            adapter_name=self.name,
            root=str(root),
            build_system=build_system,
            source_files=source_files,
            entrypoints=entrypoints,
            metadata=metadata,
            language_profiles=[profile],
        )


class RustSourceAdapter(ProjectAdapter):
    name = "rust_source"

    def supports_target(self, target: ScanTarget) -> bool:
        return self.match_score(target) > 0

    def match_score(self, target: ScanTarget) -> int:
        if target.mode is not TargetMode.SOURCE_REPO:
            return 0
        root = Path(target.resolved_path)
        manifest_bonus = 30 if (root / "Cargo.toml").exists() else 0
        return manifest_bonus + _source_file_score(root, RUST_SOURCE_SUFFIXES)

    def prepare(self, target: ScanTarget) -> ProjectContext:
        root = Path(target.resolved_path)
        source_files = _collect_source_files(root, RUST_SOURCE_SUFFIXES)
        entrypoint_files = _entrypoints_by_marker(root, RUST_SOURCE_SUFFIXES, "fn main(")
        entrypoints = [str(path) for path in entrypoint_files]
        build_system = "cargo" if (root / "Cargo.toml").exists() else "unknown"
        run_command = "cargo run -- @payload_path@" if build_system == "cargo" else "@payload_path@"
        profile = LanguageProfile(
            name=LanguageName.RUST,
            manifests=_existing_files(root, ("Cargo.toml",)),
            source_suffixes=sorted(RUST_SOURCE_SUFFIXES),
            build_system=build_system,
            test_command="cargo test" if build_system == "cargo" else "",
            run_command=run_command,
        )
        metadata = {
            "language": profile.name.value,
            "supports_binary_analysis": False,
            "build_hint": build_system,
            "default_binary": "cargo run --" if build_system == "cargo" else "",
            "suggested_repro_command": run_command,
        }
        return ProjectContext(
            target=target,
            adapter_name=self.name,
            root=str(root),
            build_system=build_system,
            source_files=source_files,
            entrypoints=entrypoints,
            metadata=metadata,
            language_profiles=[profile],
        )


class ElfBinaryAdapter(ProjectAdapter):
    name = "elf_binary"

    def supports_target(self, target: ScanTarget) -> bool:
        return target.mode is TargetMode.BINARY_ARTIFACT

    def prepare(self, target: ScanTarget) -> ProjectContext:
        binary_path = Path(target.resolved_path)
        profile = LanguageProfile(
            name=LanguageName.BINARY,
            source_suffixes=[binary_path.suffix],
            build_system="not_applicable",
            run_command="<binary-artifact> < payload.bin",
        )
        metadata = {
            "language": profile.name.value,
            "supports_binary_analysis": True,
            "build_hint": "not_applicable",
            "file_description": _describe_file(binary_path),
            "elf_class": _elf_class(binary_path),
            "suggested_repro_command": profile.run_command,
        }
        return ProjectContext(
            target=target,
            adapter_name=self.name,
            root=str(binary_path.parent),
            build_system="not_applicable",
            source_files=[str(binary_path)],
            entrypoints=[str(binary_path)],
            metadata=metadata,
            language_profiles=[profile],
        )


def _collect_source_files(root: Path, suffixes: set[str]) -> list[str]:
    return sorted(
        str(path)
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in suffixes
    )


def _entrypoints_by_marker(root: Path, suffixes: set[str], marker: str) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in suffixes
        and marker in path.read_text(encoding="utf-8", errors="ignore")
    ]


def _entrypoints_by_any_marker(root: Path, suffixes: set[str], markers: tuple[str, ...]) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in suffixes
        and any(marker in path.read_text(encoding="utf-8", errors="ignore") for marker in markers)
    ]


def _existing_files(root: Path, names: tuple[str, ...]) -> list[str]:
    return [name for name in names if (root / name).exists()]


def _relative_to_root(root: Path, path_value: str) -> str:
    if not path_value:
        return ""
    return str(Path(path_value).resolve().relative_to(root.resolve()))


def _source_file_score(root: Path, suffixes: set[str]) -> int:
    score = 0
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in suffixes:
            score += 4
            if score >= 40:
                break
    return score


def _detect_cpp_build_system(root: Path) -> str:
    if (root / "configure").exists() and not (root / "configure.ac").exists() and not (root / "autogen.sh").exists():
        return "configure_make"
    if (root / "configure").exists() or (root / "configure.ac").exists() or (root / "autogen.sh").exists():
        return "autotools"
    if (root / "CMakeLists.txt").exists():
        return "cmake"
    if (root / "Makefile").exists() or (root / "makefile").exists():
        return "make"
    return "unknown"


def _detect_python_build_system(root: Path) -> str:
    if (root / "pyproject.toml").exists():
        return "pyproject"
    if (root / "setup.py").exists():
        return "setuptools"
    if (root / "requirements.txt").exists():
        return "requirements"
    if (root / "Pipfile").exists():
        return "pipenv"
    return "python"


def _detect_javascript_build_system(root: Path) -> str:
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (root / "yarn.lock").exists():
        return "yarn"
    if (root / "package.json").exists():
        return "npm"
    return "javascript"


def _detect_java_build_system(root: Path) -> str:
    if (root / "pom.xml").exists():
        return "maven"
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        return "gradle"
    return "java"


def _describe_file(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["file", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return "file utility unavailable"
    output = proc.stdout.strip() or proc.stderr.strip()
    return output or "unable to describe binary"


def _elf_class(path: Path) -> str:
    with path.open("rb") as handle:
        header = handle.read(5)
    if len(header) < 5:
        return "unknown"
    return {
        1: "ELF32",
        2: "ELF64",
    }.get(header[4], "unknown")


def _binary_for_cpp_entrypoint(root: Path, source_path: Path) -> str:
    rel = source_path.relative_to(root)
    stem = source_path.stem
    if rel.parts and rel.parts[0] == "tools":
        return f"./tools/{stem}"
    return f"./{stem}"


def _default_cpp_repro_command(binary_path: str) -> str:
    if not binary_path:
        return "<build-artifact> @payload_path@"
    if binary_path.endswith("/tiffcrop"):
        return f"{binary_path} @payload_path@ @output_path@"
    return f"{binary_path} @payload_path@"
