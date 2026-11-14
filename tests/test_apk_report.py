from apnawin.services import apk_report


def test_native_engine_candidates_are_filename_only_heuristics():
    libraries = [
        {"abi": "arm64-v8a", "library_name": "libxray.so", "file_size_bytes": 10},
        {"abi": "x86_64", "library_name": "libhev-socks5-tunnel.so", "file_size_bytes": 20},
        {"abi": "arm64-v8a", "library_name": "libordinary.so", "file_size_bytes": 30},
    ]

    result = apk_report._native_engine_candidates(libraries)

    assert result == [
        {
            "abi": "arm64-v8a",
            "library_name": "libxray.so",
            "candidate": "xray",
            "candidate_only": True,
        },
        {
            "abi": "x86_64",
            "library_name": "libhev-socks5-tunnel.so",
            "candidate": "tun2socks",
            "candidate_only": True,
        },
    ]
    assert all("file_size_bytes" not in item for item in result)


def test_native_engine_candidates_do_not_mutate_inventory():
    libraries = [
        {"abi": "arm64-v8a", "library_name": "libwireguard.so", "file_size_bytes": 42}
    ]
    original = [dict(item) for item in libraries]

    apk_report._native_engine_candidates(libraries)

    assert libraries == original
