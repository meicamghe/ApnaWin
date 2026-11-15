import pytest

from apnawin.services.windows_network_plan import DnsSpec, RouteSpec, WindowsNetworkPlan


def plan():
    return WindowsNetworkPlan(
        200, 100,
        RouteSpec("198.51.100.25/32", "192.0.2.1", 100, 5),
        (RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 10),
         RouteSpec("::/0", "::", 200, 10)),
        DnsSpec(200, ("10.8.0.1", "2001:db8::53")),
    )


def test_immutable_plan_pins_endpoint_before_tunnel_defaults():
    value = plan()
    assert value.ordered_routes == (value.endpoint_bypass_route, *value.tunnel_default_routes)
    assert [route.network.version for route in value.ordered_routes] == [4, 4, 6]
    with pytest.raises((AttributeError, TypeError)):
        value.tunnel_interface_luid = 300


@pytest.mark.parametrize("luid", [0, -1, True, 1.0, 1 << 64])
def test_route_rejects_invalid_luid(luid):
    with pytest.raises(ValueError, match="interface LUID"):
        RouteSpec("0.0.0.0/0", "0.0.0.0", luid, 1)


@pytest.mark.parametrize("metric", [-1, True, 1.5, 1 << 32])
def test_route_rejects_invalid_metric(metric):
    with pytest.raises(ValueError, match="metric"):
        RouteSpec("0.0.0.0/0", "0.0.0.0", 1, metric)


@pytest.mark.parametrize("destination", ["0.0.0.1/0", "10.0.0.1/24", "bad"])
def test_route_rejects_noncanonical_cidr(destination):
    with pytest.raises(ValueError, match="destination"):
        RouteSpec(destination, "0.0.0.0", 1, 1)


def test_route_rejects_mixed_address_families():
    with pytest.raises(ValueError, match="families"):
        RouteSpec("0.0.0.0/0", "::", 1, 1)


def test_dns_requires_bounded_unique_ip_literal_tuple():
    with pytest.raises(ValueError, match="tuple"):
        DnsSpec(1, ["10.0.0.1"])
    with pytest.raises(ValueError, match="1 to"):
        DnsSpec(1, ())
    with pytest.raises(ValueError, match="unique"):
        DnsSpec(1, ("1.1.1.1", "1.1.1.1"))
    with pytest.raises(ValueError, match="valid IP"):
        DnsSpec(1, ("dns.example.test",))


def test_plan_rejects_same_physical_and_tunnel_interface():
    value = plan()
    with pytest.raises(ValueError, match="must differ"):
        WindowsNetworkPlan(100, 100, value.endpoint_bypass_route,
                           value.tunnel_default_routes, DnsSpec(100, ("10.0.0.1",)))


def test_plan_rejects_endpoint_bypass_not_on_physical_interface_or_not_host_route():
    with pytest.raises(ValueError, match="physical interface"):
        WindowsNetworkPlan(200, 100, RouteSpec("198.51.100.25/32", "192.0.2.1", 200, 5),
                           (RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 10),),
                           DnsSpec(200, ("10.8.0.1",)))
    with pytest.raises(ValueError, match="single-host"):
        WindowsNetworkPlan(200, 100, RouteSpec("198.51.100.0/24", "192.0.2.1", 100, 5),
                           (RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 10),),
                           DnsSpec(200, ("10.8.0.1",)))


def test_plan_rejects_nondefault_or_wrong_interface_routes():
    with pytest.raises(ValueError, match="default routes"):
        WindowsNetworkPlan(200, 100, RouteSpec("198.51.100.25/32", "192.0.2.1", 100, 5),
                           (RouteSpec("10.0.0.0/8", "0.0.0.0", 200, 10),),
                           DnsSpec(200, ("10.8.0.1",)))
    with pytest.raises(ValueError, match="tunnel interface"):
        WindowsNetworkPlan(200, 100, RouteSpec("198.51.100.25/32", "192.0.2.1", 100, 5),
                           (RouteSpec("0.0.0.0/0", "0.0.0.0", 100, 10),),
                           DnsSpec(200, ("10.8.0.1",)))


def test_plan_rejects_duplicate_default_family_and_dns_on_wrong_interface():
    with pytest.raises(ValueError, match="one default route"):
        WindowsNetworkPlan(200, 100, RouteSpec("198.51.100.25/32", "192.0.2.1", 100, 5),
                           (RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 10),
                            RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 20)),
                           DnsSpec(200, ("10.8.0.1",)))
    with pytest.raises(ValueError, match="DNS servers"):
        WindowsNetworkPlan(200, 100, RouteSpec("198.51.100.25/32", "192.0.2.1", 100, 5),
                           (RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 10),),
                           DnsSpec(100, ("10.8.0.1",)))


def test_plan_rejects_more_than_two_default_routes():
    with pytest.raises(ValueError, match="one or two"):
        WindowsNetworkPlan(200, 100, RouteSpec("198.51.100.25/32", "192.0.2.1", 100, 5),
                           (RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 10),
                            RouteSpec("::/0", "::", 200, 10),
                            RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 20)),
                           DnsSpec(200, ("10.8.0.1",)))



@pytest.mark.parametrize("server", ["0.0.0.0", "224.0.0.1", "::", "ff02::1"])
def test_dns_rejects_unspecified_or_multicast_servers(server):
    with pytest.raises(ValueError, match="unicast"):
        DnsSpec(1, (server,))


def test_plan_rejects_dns_family_without_matching_tunnel_route():
    with pytest.raises(ValueError, match="address family"):
        WindowsNetworkPlan(
            200, 100,
            RouteSpec("198.51.100.25/32", "192.0.2.1", 100, 5),
            (RouteSpec("0.0.0.0/0", "0.0.0.0", 200, 10),),
            DnsSpec(200, ("2001:db8::53",)),
        )
