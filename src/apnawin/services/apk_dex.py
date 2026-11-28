"""Optional Android SDK-backed DEX metadata inspection.

Uses apkanalyzer's documented dex list, dex references and dex packages
commands. It does not extract or execute DEX files and never returns methods,
fields, bytecode, or raw tool output.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from apnawin.services.apk_tool import run_apkanalyzer

_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 30
_MAX_DEX_FILES = 128
_MAX_CLASSES = 100_000
_MAX_RELEVANT_CLASSES = 2_000
_MAX_LINKAGE_CLASSES = 64
_MAX_LINKAGE_SCAN_TIMEOUT_SECONDS = 4.0
_MAX_LINKAGE_EVIDENCE_ROWS = 256
_DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z")
_CLASS_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")
_SIGNAL = re.compile(
    r"(?:vpn|tunnel|tun2socks|tun|socks|xray|openvpn|wireguard|"
    r"dns|proxy|shadowsocks|v2ray|trojan|service|connectivity|liapp)",
    re.IGNORECASE,
)


def _run(executable: str, args: list[str], timeout: float) -> str:
    output = run_apkanalyzer(
        executable,
        args,
        timeout,
        _MAX_OUTPUT_BYTES,
        "apkanalyzer failed during DEX inspection",
        "apkanalyzer timed out during DEX inspection",
        "apkanalyzer DEX output exceeds the allowed size",
    )
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("apkanalyzer DEX output is not UTF-8") from exc


def parse_dex_file_list(output: str) -> list[str]:
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX file list exceeds the allowed size")
    names: list[str] = []
    for line in output.splitlines():
        name = line.strip()
        if not name:
            continue
        if not _DEX_NAME.fullmatch(name):
            raise ValueError("apkanalyzer returned an unexpected DEX file name")
        names.append(name)
        if len(names) > _MAX_DEX_FILES:
            raise ValueError("APK contains too many DEX files")
    if len(names) != len(set(names)):
        raise ValueError("apkanalyzer returned duplicate DEX file names")
    return names


def _parse_defined_class_metadata(
    output: str,
) -> tuple[int, list[str], dict[str, dict[str, int]]]:
    """Parse defined classes and bounded numeric metadata for exact manifest joins."""
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX class listing exceeds the allowed size")
    count = 0
    relevant: set[str] = set()
    defined: dict[str, dict[str, int]] = {}
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "C":
            continue
        # Documented format: C d <defined-methods> <referenced-methods> <bytes> <name>
        if len(fields) != 6 or fields[1] not in {"d", "r"}:
            raise ValueError("apkanalyzer returned an unexpected class row")
        if any(not value.isdigit() for value in fields[2:5]):
            raise ValueError("apkanalyzer returned invalid class metadata")
        name = fields[5]
        if not _CLASS_NAME.fullmatch(name):
            raise ValueError("apkanalyzer returned an unexpected class name")
        if fields[1] != "d":
            continue
        if name in defined:
            raise ValueError("apkanalyzer returned a duplicate defined class")
        count += 1
        if count > _MAX_CLASSES:
            raise ValueError("APK contains too many defined classes")
        defined[name] = {
            "defined_method_count": int(fields[2]),
            "referenced_method_count": int(fields[3]),
            "byte_count": int(fields[4]),
        }
        if _SIGNAL.search(name):
            relevant.add(name)
    if len(relevant) > _MAX_RELEVANT_CLASSES:
        raise ValueError("too many potentially relevant class names")
    return count, sorted(relevant), defined


def _parse_defined_class_details(
    output: str,
) -> tuple[int, list[str], set[str]]:
    """Compatibility helper retaining the exact set of defined class names."""
    count, relevant, metadata = _parse_defined_class_metadata(output)
    return count, relevant, set(metadata)


def parse_defined_classes(output: str) -> tuple[int, list[str]]:
    """Parse defined class count and likely VPN/network class names."""
    count, relevant, _ = _parse_defined_class_details(output)
    return count, relevant


def _resolve_manifest_class(name: str, package_name: str | None) -> str | None:
    """Resolve Android component names without guessing when package context is absent."""
    if not isinstance(name, str) or not name or len(name) > 255:
        raise ValueError("manifest service name is invalid")
    if name.startswith("."):
        suffix = name[1:]
        if not _CLASS_NAME.fullmatch(suffix):
            raise ValueError("manifest service name is invalid")
        if not package_name:
            return None
        if not _PACKAGE_NAME.fullmatch(package_name):
            raise ValueError("manifest package name is invalid")
        return package_name + name
    if not _CLASS_NAME.fullmatch(name):
        raise ValueError("manifest service name is invalid")
    if "." not in name:
        if not package_name:
            return None
        if not _PACKAGE_NAME.fullmatch(package_name):
            raise ValueError("manifest package name is invalid")
        return package_name + "." + name
    return name


def _parse_native_method_count(output: str) -> int:
    """Count DEX method declarations carrying the native access flag.

    APK Analyzer emits smali text for one exact class. Method names and bodies
    are deliberately discarded; only the number of native declarations escapes.
    """
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX class code exceeds the allowed size")
    count = 0
    for line in output.splitlines():
        if len(line) > 16_384:
            raise ValueError("DEX class code contains an oversized line")
        if not line.startswith(".method "):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[0] != ".method":
            raise ValueError("apkanalyzer returned an unexpected method declaration")
        if "native" in fields[1:-1]:
            count += 1
    return count


def _parse_dex_linkage_evidence(output: str) -> dict[str, Any]:
    """Extract allowlisted process/native-loader call evidence from smali.

    Method names, descriptors, arbitrary strings and bytecode never leave this
    parser. Library literals are restricted to safe basenames and are linked
    to System.loadLibrary only through the exact argument register.
    """
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX class code exceeds the allowed size")
    string_register = re.compile(
        r'\bconst-string(?:/jumbo)?\s+(v[0-9]+|p[0-9]+),\s+"([^"]{1,512})"'
    )
    load_library_registers = re.compile(
        r'\{([^}]*)\},\s*Ljava/lang/System;->loadLibrary\('
    )
    load_path_registers = re.compile(
        r'\{([^}]*)\},\s*Ljava/lang/System;->load\('
    )
    runtime_exec_registers = re.compile(
        r'\{([^}]*)\},\s*Ljava/lang/Runtime;->exec\(([^)]*)\)'
    )
    process_builder_registers = re.compile(
        r'\{([^}]*)\},\s*Ljava/lang/ProcessBuilder;-><init>\(([^)]*)\)'
    )
    string_array_registers = re.compile(
        r'filled-new-array\s+\{([^}]*)\},\s*\[Ljava/lang/String;'
    )
    new_string_array = re.compile(
        r'new-array\s+(v[0-9]+|p[0-9]+),\s*(v[0-9]+|p[0-9]+),\s*\[Ljava/lang/String;'
    )
    string_array_put = re.compile(
        r'aput-object\s+(v[0-9]+|p[0-9]+),\s*(v[0-9]+|p[0-9]+),\s*(v[0-9]+|p[0-9]+)'
    )
    path_dex_loader_registers = re.compile(
        r'\{([^}]*)\},\s*Ldalvik/system/(?:DexClassLoader|PathClassLoader);-><init>\(([^)]*)\)'
    )
    dex_archive_suffix = re.compile(r"\.(dex|apk|jar)(?=$|:)", re.IGNORECASE)
    move_result_object = re.compile(r'move-result-object\s+(v[0-9]+|p[0-9]+)')
    move_object = re.compile(r'^\s*move-object(?:/(?:from16|16))?\s+(v[0-9]+|p[0-9]+),\s*(v[0-9]+|p[0-9]+)\s*$')
    destination_register = re.compile(r'^\s+[a-z][a-z0-9/-]*\s+(v[0-9]+|p[0-9]+)(?:\s*,|\s*$)')
    safe_library_name = re.compile(r"^[A-Za-z0-9_]{1,120}$")
    native_basename = re.compile(r"(lib[A-Za-z0-9_.+-]{1,120}\.so)$")
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    method_ordinal = 0

    def finish() -> None:
        if current is None:
            return
        if (
            current["invocation_kinds"]
            or current["native_library_literals"]
            or current["system_load_library_names"]
            or current["system_load_path_basenames"]
            or current["runtime_exec_library_basenames"]
            or current["process_builder_library_basenames"]
            or current["dynamic_dex_loader_path_extensions"]
        ):
            if len(rows) >= _MAX_LINKAGE_EVIDENCE_ROWS:
                raise ValueError("DEX linkage evidence contains too many methods")
            rows.append({
                "method_ordinal": current["method_ordinal"],
                "invocation_kinds": sorted(current["invocation_kinds"]),
                "invocation_counts": dict(sorted(current["invocation_counts"].items())),
                "native_library_literals": sorted(current["native_library_literals"]),
                "system_load_library_names": sorted(current["system_load_library_names"]),
                "system_load_path_basenames": sorted(current["system_load_path_basenames"]),
                "runtime_exec_library_basenames": sorted(current["runtime_exec_library_basenames"]),
                "process_builder_library_basenames": sorted(current["process_builder_library_basenames"]),
                "dynamic_dex_loader_path_extensions": sorted(current["dynamic_dex_loader_path_extensions"]),
                "dynamic_dex_loader_types": sorted(current["dynamic_dex_loader_types"]),
            })

    for line in output.splitlines():
        if len(line) > 16_384:
            raise ValueError("DEX class code contains an oversized line")
        if line.startswith(".method "):
            finish()
            method_ordinal += 1
            current = {
                "method_ordinal": method_ordinal,
                "invocation_kinds": set(),
                "invocation_counts": {},
                "native_library_literals": set(),
                "system_load_library_names": set(),
                "system_load_path_basenames": set(),
                "runtime_exec_library_basenames": set(),
                "process_builder_library_basenames": set(),
                "string_registers": {},
                "string_array_registers": {},
                "pending_string_array": None,
                "string_array_write_counts": {},
                "dynamic_dex_loader_path_extensions": set(),
                "dynamic_dex_loader_types": set(),
            }
            continue
        if line == ".end method":
            finish()
            current = None
            continue
        if current is None:
            continue

        # DEX requires move-result-object to immediately consume the result
        # of filled-new-array. Clear stale pending data before analyzing any
        # invocation on the next instruction.
        if current["pending_string_array"] is not None:
            result_match = move_result_object.search(line)
            if result_match:
                array_register = result_match.group(1)
                current["string_registers"].pop(array_register, None)
                current["string_array_registers"][array_register] = {"values": current["pending_string_array"], "writes": 0}
                current["string_array_write_counts"][array_register] = 0
                current["pending_string_array"] = None
                continue
            if line.strip() and not line.lstrip().startswith("#"):
                current["pending_string_array"] = None

        if "Ljava/lang/Runtime;->exec(" in line:
            current["invocation_kinds"].add("runtime_exec")
            current["invocation_counts"]["runtime_exec"] = current["invocation_counts"].get("runtime_exec", 0) + 1
            register_match = runtime_exec_registers.search(line)
            if register_match:
                registers = _explicit_invocation_registers(register_match.group(1))
                # Runtime.exec is an instance call: register zero is the Runtime receiver.
                if len(registers) > 1:
                    current["runtime_exec_library_basenames"].update(
                        _command_argument_libraries(current, registers[1], register_match.group(2), native_basename)
                    )
        if "Ljava/lang/ProcessBuilder;-><init>(" in line:
            current["invocation_kinds"].add("process_builder")
            current["invocation_counts"]["process_builder"] = current["invocation_counts"].get("process_builder", 0) + 1
            register_match = process_builder_registers.search(line)
            if register_match:
                registers = _explicit_invocation_registers(register_match.group(1))
                # ProcessBuilder constructors are instance calls; inspect only the first argument.
                if len(registers) > 1:
                    current["process_builder_library_basenames"].update(
                        _command_argument_libraries(current, registers[1], register_match.group(2), native_basename)
                    )
        if "Ljava/lang/System;->loadLibrary(" in line:
            current["invocation_kinds"].add("system_load_library")
            current["invocation_counts"]["system_load_library"] = current["invocation_counts"].get("system_load_library", 0) + 1
            register_match = load_library_registers.search(line)
            if register_match:
                registers = _explicit_invocation_registers(register_match.group(1))
                for register in registers:
                    literal = current["string_registers"].get(register)
                    if literal and safe_library_name.fullmatch(literal):
                        current["system_load_library_names"].add(literal)
        if "Ljava/lang/System;->load(" in line:
            current["invocation_kinds"].add("system_load")
            current["invocation_counts"]["system_load"] = current["invocation_counts"].get("system_load", 0) + 1
            register_match = load_path_registers.search(line)
            if register_match:
                registers = _explicit_invocation_registers(register_match.group(1))
                for register in registers:
                    literal = current["string_registers"].get(register)
                    basename = native_basename.search(literal or "")
                    if basename:
                        current["system_load_path_basenames"].add(basename.group(1))
        if any(token in line for token in (
            "Ldalvik/system/DexClassLoader;-><init>(",
            "Ldalvik/system/PathClassLoader;-><init>(",
            "Ldalvik/system/InMemoryDexClassLoader;-><init>(",
        )):
            current["invocation_kinds"].add("dynamic_dex_loader")
            current["invocation_counts"]["dynamic_dex_loader"] = current["invocation_counts"].get("dynamic_dex_loader", 0) + 1
            # DexClassLoader and PathClassLoader take a String path as their
            # first constructor argument (register 1 after the receiver).
            # Record only a bounded file extension, never the path itself.
            if "Ldalvik/system/DexClassLoader;-><init>(" in line:
                current["dynamic_dex_loader_types"].add("DexClassLoader")
            elif "Ldalvik/system/PathClassLoader;-><init>(" in line:
                current["dynamic_dex_loader_types"].add("PathClassLoader")
            elif "Ldalvik/system/InMemoryDexClassLoader;-><init>(" in line:
                current["dynamic_dex_loader_types"].add("InMemoryDexClassLoader")
            path_match = path_dex_loader_registers.search(line)
            if path_match:
                registers = _explicit_invocation_registers(path_match.group(1))
                descriptor = path_match.group(2)
                if len(registers) > 1 and descriptor.startswith("Ljava/lang/String;"):
                    path_literal = current["string_registers"].get(registers[1], "")
                    current["dynamic_dex_loader_path_extensions"].update(
                        suffix.group(1).lower()
                        for suffix in dex_archive_suffix.finditer(path_literal)
                    )

        # Track only arrays allocated as String[] in this method and populated
        # through direct aput-object register operands. Direct move-object aliases
        # share the same bounded state; indices, reflection and computed strings
        # are not followed.
        allocated_array = new_string_array.search(line)
        if allocated_array:
            array_register = allocated_array.group(1)
            current["string_registers"].pop(array_register, None)
            current["string_array_registers"][array_register] = {"values": [], "writes": 0}
            current["string_array_write_counts"][array_register] = 0
            continue

        array_put = string_array_put.search(line)
        if array_put:
            value_register, array_register, _index_register = array_put.groups()
            if array_register in current["string_array_registers"]:
                state = current["string_array_registers"][array_register]
                state["writes"] += 1
                if state["writes"] > 256:
                    aliases = [
                        register for register, candidate in current["string_array_registers"].items()
                        if candidate is state
                    ]
                    for register in aliases:
                        current["string_array_registers"].pop(register, None)
                        current["string_array_write_counts"].pop(register, None)
                else:
                    current["string_array_write_counts"][array_register] = state["writes"]
                    literal = current["string_registers"].get(value_register, "")
                    basename = native_basename.search(literal)
                    if basename and basename.group(1) not in state["values"]:
                        state["values"].append(basename.group(1))
            continue

        array_match = string_array_registers.search(line)
        if array_match:
            registers = re.findall(r"\b(?:v|p)[0-9]+\b", array_match.group(1))
            current["pending_string_array"] = sorted({
                basename.group(1)
                for register in registers
                if (basename := native_basename.search(current["string_registers"].get(register, "")))
            })
            continue

        # Preserve direct object moves of known string literals or tracked String[]
        # references. Other object types and computed values remain unresolved.
        move_match = move_object.match(line)
        if move_match:
            destination, source = move_match.groups()
            literal = current["string_registers"].get(source)
            array_state = current["string_array_registers"].get(source)
            current["string_registers"].pop(destination, None)
            current["string_array_registers"].pop(destination, None)
            current["string_array_write_counts"].pop(destination, None)
            if literal is not None:
                current["string_registers"][destination] = literal
            elif array_state is not None:
                current["string_array_registers"][destination] = array_state
                current["string_array_write_counts"][destination] = array_state["writes"]
            continue

        register_match = string_register.search(line)
        if register_match:
            register, literal = register_match.groups()
            current["string_registers"][register] = literal
            current["string_array_registers"].pop(register, None)
            current["string_array_write_counts"].pop(register, None)
            basename = native_basename.search(literal)
            if basename:
                current["native_library_literals"].add(basename.group(1))
            continue

        destination_match = destination_register.match(line)
        if destination_match:
            destination = destination_match.group(1)
            current["string_registers"].pop(destination, None)
            current["string_array_registers"].pop(destination, None)
            current["string_array_write_counts"].pop(destination, None)
            current["pending_string_array"] = None

    finish()
    totals = {
        "runtime_exec_calls": 0,
        "process_builder_calls": 0,
        "system_load_calls": 0,
        "system_load_library_calls": 0,
        "dynamic_dex_loader_calls": 0,
    }
    kind_to_total = {
        "runtime_exec": "runtime_exec_calls",
        "process_builder": "process_builder_calls",
        "system_load": "system_load_calls",
        "system_load_library": "system_load_library_calls",
        "dynamic_dex_loader": "dynamic_dex_loader_calls",
    }
    for row in rows:
        for kind, count in row["invocation_counts"].items():
            totals[kind_to_total[kind]] += count
    return {
        **totals,
        "methods_with_evidence": rows,
        "raw_smali_included": False,
    }



def _explicit_invocation_registers(register_operands: str) -> list[str]:
    """Return registers only for explicitly enumerated invoke operands.

    Smali invoke-range operands use ``vN .. vM``. Treating the two endpoints
    as an ordinary argument list can select the wrong argument register, so
    range calls are counted but never correlated by this bounded scanner.
    """
    if ".." in register_operands:
        return []
    return re.findall(r"\b(?:v|p)[0-9]+\b", register_operands)

def _command_argument_libraries(
    current: dict[str, Any],
    register: str,
    descriptor: str,
    native_basename: re.Pattern[str],
) -> list[str]:
    """Return safe library basenames from one direct string or filled string-array argument."""
    if descriptor == "[Ljava/lang/String;":
        return list(current["string_array_registers"].get(register, {}).get("values", []))
    literal = current["string_registers"].get(register, "")
    match = native_basename.search(literal)
    return [match.group(1)] if match else []


def _select_linkage_scan_targets(
    candidates: list[str],
    service_matches: list[dict[str, Any]],
) -> tuple[list[str], bool]:
    """Prioritize exact manifest-service classes before heuristic class names."""
    service_targets = sorted({
        item["resolved_class_name"] for item in service_matches
        if item["resolved_class_name"] and item["defined_in_dex"]
    })
    protector_targets = sorted({
        name for name in candidates
        if re.search(r"(?:^|\.)liapp(?:\.|$)", name, re.IGNORECASE)
    })
    candidate_targets = sorted(
        set(candidates) - set(service_targets) - set(protector_targets)
    )
    ordered = service_targets + protector_targets + candidate_targets
    return ordered[:_MAX_LINKAGE_CLASSES], len(ordered) > _MAX_LINKAGE_CLASSES


def parse_reference_counts(output: str) -> dict[str, int]:
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("DEX reference listing exceeds the allowed size")
    counts: dict[str, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2 or not _DEX_NAME.fullmatch(fields[0]):
            raise ValueError("apkanalyzer returned an unexpected DEX reference row")
        if not fields[1].isdigit():
            raise ValueError("apkanalyzer returned an invalid DEX reference count")
        if fields[0] in counts:
            raise ValueError("apkanalyzer returned duplicate DEX reference rows")
        counts[fields[0]] = int(fields[1])
    return counts


def inspect_apk_dex(
    apk_path: str | Path,
    executable: str = "apkanalyzer",
    timeout: float = _MAX_TIMEOUT_SECONDS,
    manifest_services: list[str] | None = None,
    package_name: str | None = None,
) -> dict[str, Any]:
    """Return DEX file counts and candidate VPN/network class names."""
    path = Path(apk_path)
    if not path.is_file():
        raise ValueError("APK path must refer to an existing regular file")
    if timeout <= 0 or timeout > _MAX_TIMEOUT_SECONDS:
        raise ValueError("apkanalyzer timeout is outside the allowed range")
    resolved = shutil.which(executable)
    if resolved is None and Path(executable).is_file():
        resolved = str(Path(executable).resolve())
    if resolved is None:
        raise RuntimeError("Android SDK apkanalyzer was not found on PATH")

    apk = str(path.resolve())
    dex_files = parse_dex_file_list(_run(resolved, ["dex", "list", apk], timeout))
    if not dex_files:
        return {
            "format": "apnawin-apk-dex-v1",
            "dex_files": [],
            "dex_file_count": 0,
            "defined_class_count": 0,
            "method_references": {},
            "candidate_classes": [],
            "manifest_service_classes": [
                {
                    "manifest_name": service,
                    "resolved_class_name": _resolve_manifest_class(service, package_name),
                    "defined_in_dex": False,
                    "defined_method_count": None,
                    "referenced_method_count": None,
                    "byte_count": None,
                    "native_method_count": None,
                    "native_method_inspection_completed": False,
                }
                for service in (manifest_services or [])
            ],
            "native_linkage_evidence": [],
            "linkage_scan_classes_inspected": 0,
            "linkage_scan_truncated": False,
            "source": "apkanalyzer",
            "raw_dex_output_included": False,
        }

    class_output = _run(resolved, ["dex", "packages", "--defined-only", apk], timeout)
    class_count, candidates, class_metadata = _parse_defined_class_metadata(class_output)
    service_matches = []
    native_method_counts: dict[str, int] = {}
    linkage_by_class: dict[str, dict[str, Any]] = {}
    for service in manifest_services or []:
        resolved_name = _resolve_manifest_class(service, package_name)
        evidence = class_metadata.get(resolved_name) if resolved_name else None
        native_count = None
        inspection_completed = False
        if evidence is not None and resolved_name is not None:
            if resolved_name not in native_method_counts:
                code_output = _run(
                    resolved,
                    ["dex", "code", "--class", resolved_name, apk],
                    timeout,
                )
                native_method_counts[resolved_name] = _parse_native_method_count(code_output)
                linkage_by_class[resolved_name] = _parse_dex_linkage_evidence(code_output)
            native_count = native_method_counts[resolved_name]
            inspection_completed = True
        service_matches.append({
            "manifest_name": service,
            "resolved_class_name": resolved_name,
            "defined_in_dex": evidence is not None,
            "defined_method_count": evidence["defined_method_count"] if evidence else None,
            "referenced_method_count": evidence["referenced_method_count"] if evidence else None,
            "byte_count": evidence["byte_count"] if evidence else None,
            "native_method_count": native_count,
            "native_method_inspection_completed": inspection_completed,
        })
    # Scan a bounded set of network/service candidate classes for process-launch,
    # native-loader and secondary-DEX-loader callsites. This is static evidence,
    # not proof that any callsite executes at runtime.
    scan_targets, linkage_scan_truncated = _select_linkage_scan_targets(
        candidates, service_matches
    )
    for class_name in scan_targets:
        if class_name in linkage_by_class:
            continue
        code_output = _run(
            resolved,
            ["dex", "code", "--class", class_name, apk],
            min(timeout, _MAX_LINKAGE_SCAN_TIMEOUT_SECONDS),
        )
        linkage_by_class[class_name] = _parse_dex_linkage_evidence(code_output)
    linkage_evidence = [
        {"class_name": name, **linkage_by_class[name]}
        for name in scan_targets
        if any((
            linkage_by_class[name]["runtime_exec_calls"],
            linkage_by_class[name]["process_builder_calls"],
            linkage_by_class[name]["system_load_calls"],
            linkage_by_class[name]["system_load_library_calls"],
            linkage_by_class[name]["dynamic_dex_loader_calls"],
            any(row["native_library_literals"] for row in linkage_by_class[name]["methods_with_evidence"]),
        ))
    ]

    reference_output = _run(resolved, ["dex", "references", apk], timeout)
    references = parse_reference_counts(reference_output)
    if set(references) - set(dex_files):
        raise ValueError("DEX reference output contains an unknown DEX file")
    return {
        "format": "apnawin-apk-dex-v1",
        "dex_files": dex_files,
        "dex_file_count": len(dex_files),
        "defined_class_count": class_count,
        "method_references": references,
        "candidate_classes": candidates,
        "manifest_service_classes": service_matches,
        "native_linkage_evidence": linkage_evidence,
        "linkage_scan_classes_inspected": len(scan_targets),
        "linkage_scan_truncated": linkage_scan_truncated,
        "source": "apkanalyzer",
        "raw_dex_output_included": False,
    }
