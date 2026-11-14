# Profile model and endpoint validation

Connection profiles contain non-secret display metadata: name, transport,
endpoint host and endpoint port. Host values are validated as either an IP
literal (IPv4 or IPv6) or a DNS hostname. DNS labels are checked after IDNA
conversion, including label length and leading/trailing hyphens. URL syntax,
userinfo, paths, query fragments and embedded ports are rejected; the port
must be entered in its separate field.

This is input-shape validation, not a network reachability or server-identity
check. It does not resolve DNS or connect to the endpoint. Credentials and
private keys remain outside the profile format.
