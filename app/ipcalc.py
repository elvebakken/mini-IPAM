from __future__ import annotations
import ipaddress
import random
from typing import Dict, Any, List, Optional, Tuple

def parse_network(cidr: str) -> ipaddress.IPv4Network:
    net = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 is supported in this prototype.")
    return net

def usable_range(net: ipaddress.IPv4Network) -> Tuple[str, str, int]:
    # /31 and /32 have no usable host range in the traditional sense
    if net.prefixlen >= 31:
        return (str(net.network_address), str(net.broadcast_address), 0)

    start = net.network_address + 1
    end = net.broadcast_address - 1
    total = int(end) - int(start) + 1
    return (str(start), str(end), total)

def gateway_suggestion(net: ipaddress.IPv4Network) -> Optional[str]:
    if net.prefixlen >= 31:
        return None
    return str(net.network_address + 1)

def ip_in_subnet(ip: str, cidr: str) -> bool:
    net = parse_network(cidr)
    addr = ipaddress.ip_address(ip)
    return addr in net

def is_network_or_broadcast(ip: str, cidr: str) -> Dict[str, bool]:
    net = parse_network(cidr)
    addr = ipaddress.ip_address(ip)
    return {
        "is_network": addr == net.network_address,
        "is_broadcast": addr == net.broadcast_address,
    }

def next_available_ip(cidr: str, used: set[str], reserved: set[str]) -> Optional[str]:
    net = parse_network(cidr)
    if net.prefixlen >= 31:
        return None

    start = net.network_address + 1
    end = net.broadcast_address - 1

    cur = int(start)
    last = int(end)
    while cur <= last:
        candidate = str(ipaddress.IPv4Address(cur))
        if candidate not in used and candidate not in reserved:
            return candidate
        cur += 1
    return None

def random_available_ip(cidr: str, used: set[str], reserved: set[str]) -> Optional[str]:
    net = parse_network(cidr)
    if net.prefixlen >= 31:
        return None

    start = net.network_address + 1
    end = net.broadcast_address - 1

    # Collect all available IPs
    available = []
    cur = int(start)
    last = int(end)
    while cur <= last:
        candidate = str(ipaddress.IPv4Address(cur))
        if candidate not in used and candidate not in reserved:
            available.append(candidate)
        cur += 1
    
    if not available:
        return None
    
    # Return a random IP from the available pool
    return random.choice(available)
