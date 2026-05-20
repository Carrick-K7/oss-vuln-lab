from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from shlex import quote

from oss_vuln_lab.models import (
    Candidate,
    EvidenceKind,
    EvidenceSpec,
    PocSpec,
    ProjectContext,
    ValidationResult,
    ValidationStatus,
)
from oss_vuln_lab.plugins.base import Validator


class DockerBuildValidator(Validator):
    name = "docker_build"

    def supports(self, project: ProjectContext, candidate: Candidate, poc: PocSpec) -> bool:
        return project.target.mode.value == "source_repo"

    def run(
        self,
        project: ProjectContext,
        candidate: Candidate,
        poc: PocSpec,
        run_dir: Path,
    ) -> ValidationResult:
        command_or_error = _docker_command(project, poc, run_dir, self.name)
        if isinstance(command_or_error, ValidationResult):
            return command_or_error
        return ValidationResult(
            validator_name=self.name,
            status=ValidationStatus.HYPOTHESIS,
            summary="Prepared a Docker build-and-run command, but this validator does not classify runtime evidence.",
            command=command_or_error,
            evidence="Command prepared successfully; use sanitizer_runtime for confirmation.",
            evidence_items=[_output_evidence("prepared-command", "Command prepared successfully; use sanitizer_runtime for confirmation.")],
        )


class SanitizerRuntimeValidator(Validator):
    name = "sanitizer_runtime"

    def supports(self, project: ProjectContext, candidate: Candidate, poc: PocSpec) -> bool:
        return project.target.mode.value == "source_repo"

    def run(
        self,
        project: ProjectContext,
        candidate: Candidate,
        poc: PocSpec,
        run_dir: Path,
    ) -> ValidationResult:
        command_or_error = _docker_command(project, poc, run_dir, self.name)
        if isinstance(command_or_error, ValidationResult):
            return command_or_error

        proc = subprocess.run(
            command_or_error,
            shell=True,
            capture_output=True,
            text=True,
            cwd=project.root,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        evidence = output.strip()[:8000]
        if _contains_sanitizer_signal(output):
            return ValidationResult(
                validator_name=self.name,
                status=ValidationStatus.CONFIRMED,
                summary="Sanitizer or crash evidence was captured while running the candidate PoC.",
                command=command_or_error,
                evidence=evidence,
                evidence_items=[_signal_evidence(output)],
            )
        status = ValidationStatus.FAILED if proc.returncode else ValidationStatus.HYPOTHESIS
        summary = "Command executed without sanitizer signal." if proc.returncode == 0 else "Command failed before sanitizer confirmation."
        return ValidationResult(
            validator_name=self.name,
            status=status,
            summary=summary,
            command=command_or_error,
            evidence=evidence,
            evidence_items=[_output_evidence("docker-runtime", evidence)],
        )


class HostBuildValidator(Validator):
    name = "host_build"

    def supports(self, project: ProjectContext, candidate: Candidate, poc: PocSpec) -> bool:
        return project.target.mode.value == "source_repo"

    def run(
        self,
        project: ProjectContext,
        candidate: Candidate,
        poc: PocSpec,
        run_dir: Path,
    ) -> ValidationResult:
        proc_or_error = _prepare_host_build(project, self.name)
        if isinstance(proc_or_error, ValidationResult):
            return proc_or_error
        build_proc, build_dir, build_cmd = proc_or_error
        evidence = _trim_output((build_proc.stdout or "") + "\n" + (build_proc.stderr or ""))
        status = ValidationStatus.HYPOTHESIS if build_proc.returncode == 0 else ValidationStatus.FAILED
        summary = "Host sanitizer build completed." if build_proc.returncode == 0 else "Host sanitizer build failed."
        return ValidationResult(
            validator_name=self.name,
            status=status,
            summary=summary,
            command=build_cmd,
            evidence=evidence,
            metadata={"build_dir": str(build_dir)},
            evidence_items=[_output_evidence("host-build", evidence)],
        )


class HostSanitizerRuntimeValidator(Validator):
    name = "host_sanitizer_runtime"

    def supports(self, project: ProjectContext, candidate: Candidate, poc: PocSpec) -> bool:
        return project.target.mode.value == "source_repo"

    def run(
        self,
        project: ProjectContext,
        candidate: Candidate,
        poc: PocSpec,
        run_dir: Path,
    ) -> ValidationResult:
        proc_or_error = _prepare_host_build(project, self.name)
        if isinstance(proc_or_error, ValidationResult):
            return proc_or_error
        build_proc, build_dir, build_cmd = proc_or_error
        build_output = ((build_proc.stdout or "") + "\n" + (build_proc.stderr or "")).strip()
        if build_proc.returncode != 0:
            return ValidationResult(
                validator_name=self.name,
                status=ValidationStatus.FAILED,
                summary="Host sanitizer build failed before runtime validation.",
                command=build_cmd,
                evidence=_trim_output(build_output),
                metadata={"build_dir": str(build_dir)},
                evidence_items=[_output_evidence("host-build", _trim_output(build_output))],
            )

        runtime_or_error = _host_runtime_command(project, poc, run_dir, build_dir, self.name)
        if isinstance(runtime_or_error, ValidationResult):
            return runtime_or_error
        runtime_cmd, env = runtime_or_error
        proc = subprocess.run(
            runtime_cmd,
            shell=True,
            capture_output=True,
            text=True,
            cwd=build_dir,
            env=env,
        )
        runtime_output = "\n".join(part for part in [proc.stdout or "", proc.stderr or ""] if part).strip()
        output = "\n".join(part for part in [runtime_output, build_output] if part).strip()
        if _contains_sanitizer_signal(output):
            return ValidationResult(
                validator_name=self.name,
                status=ValidationStatus.CONFIRMED,
                summary="Host runtime captured sanitizer or crash evidence.",
                command=f"{build_cmd} && {runtime_cmd}",
                evidence=_trim_output(output),
                metadata={"build_dir": str(build_dir)},
                evidence_items=[_signal_evidence(output)],
            )
        status = ValidationStatus.FAILED if proc.returncode else ValidationStatus.HYPOTHESIS
        summary = "Runtime completed without sanitizer evidence." if proc.returncode == 0 else "Runtime failed before sanitizer confirmation."
        return ValidationResult(
            validator_name=self.name,
            status=status,
            summary=summary,
            command=f"{build_cmd} && {runtime_cmd}",
            evidence=_trim_output(output),
            metadata={"build_dir": str(build_dir)},
            evidence_items=[_output_evidence("host-runtime", _trim_output(output))],
        )


class DirectRuntimeValidator(Validator):
    name = "direct_runtime"

    def supports(self, project: ProjectContext, candidate: Candidate, poc: PocSpec) -> bool:
        return project.target.mode.value == "source_repo"

    def run(
        self,
        project: ProjectContext,
        candidate: Candidate,
        poc: PocSpec,
        run_dir: Path,
    ) -> ValidationResult:
        runtime_cmd_or_error = _resolve_runtime_command(project, poc, run_dir, project.root)
        if isinstance(runtime_cmd_or_error, ValidationResult):
            runtime_cmd_or_error.validator_name = self.name
            return runtime_cmd_or_error
        env = dict(os.environ)
        env.update(poc.runtime_env)
        proc = subprocess.run(
            runtime_cmd_or_error,
            shell=True,
            capture_output=True,
            text=True,
            cwd=project.root,
            env=env,
        )
        output = "\n".join(part for part in [proc.stdout or "", proc.stderr or ""] if part).strip()
        trimmed = _trim_output(output)
        if _contains_runtime_signal(output):
            return ValidationResult(
                validator_name=self.name,
                status=ValidationStatus.CONFIRMED,
                summary="Direct runtime execution captured crash or exception evidence.",
                command=runtime_cmd_or_error,
                evidence=trimmed,
                evidence_items=[_signal_evidence(output)],
            )
        status = ValidationStatus.FAILED if proc.returncode else ValidationStatus.HYPOTHESIS
        summary = "Runtime completed without crash signal." if proc.returncode == 0 else "Runtime failed without a classified crash signal."
        return ValidationResult(
            validator_name=self.name,
            status=status,
            summary=summary,
            command=runtime_cmd_or_error,
            evidence=trimmed,
            evidence_items=[_output_evidence("direct-runtime", trimmed)],
        )


def _docker_command(project: ProjectContext, poc: PocSpec, run_dir: Path, validator_name: str) -> str | ValidationResult:
    if shutil.which("docker") is None:
        return ValidationResult(
            validator_name=validator_name,
            status=ValidationStatus.UNSUPPORTED,
            summary="Docker is not available in the current environment.",
            evidence="Install Docker to enable containerized build and runtime validation.",
        )
    if project.build_system not in {"make", "autotools", "configure_make"}:
        return ValidationResult(
            validator_name=validator_name,
            status=ValidationStatus.UNSUPPORTED,
            summary=f"Build system `{project.build_system}` is not supported by the builtin runtime validator.",
            evidence="The builtin validator currently supports Make, autotools, and configure+make C/C++ projects only.",
        )
    runtime_cmd = _resolve_runtime_command(project, poc, run_dir, "")
    if isinstance(runtime_cmd, ValidationResult):
        return runtime_cmd

    build_cmd = _shell_build_command(project)
    quoted_root = quote(project.root)
    return (
        "docker run --rm "
        "--network none "
        f"-v {quoted_root}:/src -w /src gcc:14 "
        f"bash -lc {quote(build_cmd + ' && ' + runtime_cmd)}"
    )


def _prepare_host_build(
    project: ProjectContext,
    validator_name: str,
) -> tuple[subprocess.CompletedProcess[str], Path, str] | ValidationResult:
    if shutil.which("gcc") is None or shutil.which("make") is None:
        return ValidationResult(
            validator_name=validator_name,
            status=ValidationStatus.UNSUPPORTED,
            summary="Host compiler toolchain is not available.",
            evidence="gcc and make are required for host validation.",
        )
    if project.build_system not in {"make", "autotools", "configure_make"}:
        return ValidationResult(
            validator_name=validator_name,
            status=ValidationStatus.UNSUPPORTED,
            summary=f"Host validation does not support build system `{project.build_system}`.",
            evidence="Supported build systems: make, autotools, configure_make.",
        )
    build_dir = Path(project.root)
    needs_autogen = False
    if project.build_system == "autotools" and not (build_dir / "configure").exists():
        if not (build_dir / "autogen.sh").exists():
            return ValidationResult(
                validator_name=validator_name,
                status=ValidationStatus.UNSUPPORTED,
                summary="Autotools project does not include a configure script or autogen bootstrap.",
                evidence="Expected either ./configure or ./autogen.sh in the project root.",
            )
        if shutil.which("libtoolize") is None:
            return ValidationResult(
                validator_name=validator_name,
                status=ValidationStatus.UNSUPPORTED,
                summary="Autotools bootstrap requires libtoolize, which is not available.",
                evidence="Install libtool to build source archives that only ship autogen.sh/configure.ac.",
            )
        needs_autogen = True
    build_cmd = _shell_build_command(project, needs_autogen)
    proc = subprocess.run(
        build_cmd,
        shell=True,
        capture_output=True,
        text=True,
        cwd=build_dir,
    )
    return proc, build_dir, build_cmd


def _host_runtime_command(
    project: ProjectContext,
    poc: PocSpec,
    run_dir: Path,
    build_dir: Path,
    validator_name: str,
) -> tuple[str, dict[str, str]] | ValidationResult:
    runtime_cmd = _resolve_runtime_command(project, poc, run_dir, str(build_dir))
    if isinstance(runtime_cmd, ValidationResult):
        runtime_cmd.validator_name = validator_name
        return runtime_cmd
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    env.update(poc.runtime_env)
    return runtime_cmd, env


def _resolve_runtime_command(
    project: ProjectContext,
    poc: PocSpec,
    run_dir: Path,
    build_root: str,
) -> str | ValidationResult:
    command = poc.repro_command
    if "<build-artifact>" in command or "<binary-artifact>" in command:
        return ValidationResult(
            validator_name="",
            status=ValidationStatus.UNSUPPORTED,
            summary="PoC command still contains unresolved executable placeholders.",
            evidence=command,
        )
    artifact_dir = run_dir.resolve()
    payload_path = _artifact_payload_path(artifact_dir, poc)
    output_path = (artifact_dir / "validator-output.bin").resolve()
    binary_root = str(Path(build_root or project.root).resolve())
    command = command.replace("@artifact_dir@", quote(str(artifact_dir)))
    command = command.replace("@payload_path@", quote(str(payload_path)))
    command = command.replace("@output_path@", quote(str(output_path)))
    command = command.replace("@build_root@", quote(binary_root))
    return command


def _artifact_payload_path(artifact_dir: Path, poc: PocSpec) -> Path:
    if poc.artifacts:
        first_name = poc.artifacts[0].name
        return artifact_dir / first_name
    return artifact_dir / "payload.txt"


def _shell_build_command(project: ProjectContext, needs_autogen: bool = False) -> str:
    build_system = project.build_system
    extra_args = " ".join(quote(str(arg)) for arg in project.metadata.get("configure_extra_args", []))
    configure_env = (
        "env "
        "CC=gcc "
        "CXX=g++ "
        "CFLAGS='-fsanitize=address,undefined -g -O1' "
        "CXXFLAGS='-fsanitize=address,undefined -g -O1' "
        "LDFLAGS='-fsanitize=address,undefined' "
    )
    if build_system == "make":
        return (
            "make clean >/dev/null 2>&1 || true; "
            "make CC=gcc CXX=g++ "
            "CFLAGS='-fsanitize=address,undefined -g -O1' "
            "CXXFLAGS='-fsanitize=address,undefined -g -O1'"
        )
    if build_system == "configure_make":
        extra = f" {extra_args}" if extra_args else ""
        return (
            "make distclean >/dev/null 2>&1 || true; "
            f"{configure_env}./configure{extra} >/dev/null && "
            "make -j1"
        )
    bootstrap = "./autogen.sh >/dev/null && " if needs_autogen else ""
    extra = f" {extra_args}" if extra_args else ""
    return (
        "make distclean >/dev/null 2>&1 || true; "
        f"{bootstrap}{configure_env}./configure --disable-shared{extra} >/dev/null && "
        "make -j1"
    )


def _contains_sanitizer_signal(output: str) -> bool:
    markers = (
        "AddressSanitizer",
        "UndefinedBehaviorSanitizer",
        "runtime error:",
        "heap-use-after-free",
        "stack-buffer-overflow",
        "Segmentation fault",
        "core dumped",
    )
    return any(marker in output for marker in markers)


def _contains_runtime_signal(output: str) -> bool:
    if _contains_sanitizer_signal(output):
        return True
    markers = (
        "Traceback (most recent call last):",
        "Exception in thread",
        "thread 'main' panicked",
        "panic!",
        "ERR_ASSERTION",
        "UnhandledPromiseRejection",
        "java.lang.",
        "Segmentation fault",
        "core dumped",
    )
    return any(marker in output for marker in markers)


def _trim_output(output: str, limit: int = 8000) -> str:
    output = output.strip()
    if len(output) <= limit:
        return output
    head = output[: limit // 2]
    tail = output[-(limit // 2) :]
    return f"{head}\n...\n{tail}"


def _signal_evidence(output: str) -> EvidenceSpec:
    return EvidenceSpec(
        kind=EvidenceKind.SANITIZER if _contains_sanitizer_signal(output) else EvidenceKind.TRACEBACK,
        label="runtime-signal",
        value=_trim_output(output),
    )


def _output_evidence(label: str, output: str) -> EvidenceSpec:
    return EvidenceSpec(
        kind=EvidenceKind.COMMAND_OUTPUT,
        label=label,
        value=_trim_output(output or "No output captured."),
    )
