from pathlib import Path

from tools.compare_go_elf import (
    compare,
    extract_fingerprints,
    parse_go_symbols,
    parse_readelf,
)


def test_parse_readelf_extracts_elf_pie_metadata_and_dependencies():
    result = parse_readelf(
        """
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           AArch64
  Entry point address:               0x1be520
      [Requesting program interpreter: /system/bin/linker64]
  Build ID:                          abcdef1234
 0x0000000000000001 (NEEDED)             Shared library: [liblog.so]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so]
"""
    )
    assert result["elf_class"] == "ELF64"
    assert result["type"].startswith("DYN")
    assert result["machine"] == "AArch64"
    assert result["entry_point"] == "0x1be520"
    assert result["interpreter"] == "/system/bin/linker64"
    assert result["build_id"] == "abcdef1234"
    assert result["needed_libraries"] == ["liblog.so", "libc.so"]


def test_parse_go_symbols_keeps_go_functions_and_types():
    symbols = parse_go_symbols(
        """
000000000001 T main.main
000000000002 T github.com/example/pkg.run
000000000003 R type:main.clientHello
000000000004 T runtime.main
000000000005 T _start
"""
    )
    assert symbols == {
        "main.main",
        "github.com/example/pkg.run",
        "type:main.clientHello",
        "runtime.main",
    }


def test_extract_fingerprints_detects_starudp_wire_and_config_markers():
    data = b"""
github.com/quic-go/quic-go
github.com/pion/dtls/v2
clientHello serverHello clientRequest serverResponse udpMessage
json:"auth_str" json:"server_name" json:"socks5" json:"up_mbps"
"""
    result = extract_fingerprints(data)
    assert "github.com/quic-go/quic-go" in result["go_packages"]
    assert "github.com/pion/dtls/v2" in result["go_packages"]
    assert result["wire_struct_names"] == [
        "clientHello", "clientRequest", "serverHello", "serverResponse", "udpMessage"
    ]
    assert result["config_json_tags"] == ["auth_str", "server_name", "socks5", "up_mbps"]


def test_compare_reports_similarity_without_claiming_protocol_identity():
    left = {
        "sha256": "a",
        "go_symbols": ["main.main", "pkg.one", "pkg.two"],
        "fingerprints": {
            "go_packages": ["github.com/quic-go/quic-go"],
            "go_json_tags": ['json:"socks5"', 'json:"auth_str"'],
            "wire_struct_names": ["clientHello", "udpMessage"],
            "config_json_tags": ["socks5", "auth_str"],
        },
    }
    right = {
        "sha256": "b",
        "go_symbols": ["main.main", "pkg.two", "pkg.three"],
        "fingerprints": {
            "go_packages": ["github.com/quic-go/quic-go"],
            "go_json_tags": ['json:"socks5"', 'json:"auth_str"'],
            "wire_struct_names": ["clientHello", "serverHello"],
            "config_json_tags": ["socks5", "server_name"],
        },
    }
    result = compare(left, right)
    assert result["same_sha256"] is False
    assert result["common_go_symbol_count"] == 2
    assert result["go_symbol_jaccard"] == 0.5
    assert result["common_wire_struct_names"] == ["clientHello"]
    assert "not proof" in result["interpretation"]
