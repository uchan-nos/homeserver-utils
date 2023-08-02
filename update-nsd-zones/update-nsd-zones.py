#!/usr/bin/python3
import argparse
from collections import namedtuple
import io
import ipaddress
import json
import os
import subprocess
from tempfile import NamedTemporaryFile
from textwrap import dedent
import unittest

# Types
HOST = namedtuple('HOST', 'ip_last name')

# Helper functions for configuration files
def read_hosts(f):
    hosts = []
    for line in f:
        line = line.strip()
        if len(line) == 0:
            continue
        addr, hostname = line.split()
        hosts.append(HOST(int(addr), hostname))
    return hosts

def read_zone(f):
    j = json.load(f)
    ma = j['soa']['mailaddr']
    if '@' in ma:
        name, domain = ma.split('@')
        if '.' in name:
            raise ValueError("mail address can't contain '.' in the username part")
        j['soa']['mailaddr'] = f'{name}.{domain}.'
    v = j.get('ipv4_prefix')
    if v is not None:
        j['ipv4_prefix'] = ipaddress.IPv4Network(v)
    v = j.get('ipv6_prefix')
    if v is not None:
        j['ipv6_prefix'] = ipaddress.IPv6Network(v)
    return j

# Helper functions
def get_ipv4_prefix(zone):
    p = zone['ipv4_prefix']
    if (p.prefixlen % 8) != 0:
        raise NotImplementedError('currently supports /8n networks for IPv4')
    num_octets = p.prefixlen // 8
    return p.network_address.exploded.split('.', maxsplit=num_octets)[:num_octets]

def get_ipv6_prefix(zone):
    p = zone['ipv6_prefix']
    if (p.prefixlen % 16) != 0:
        raise NotImplementedError('currently supports /16n networks for IPv6')
    num_parts = p.prefixlen // 16
    return p.network_address.exploded.split(':', maxsplit=num_parts)[:num_parts]

def remove_ipv6_last_zeros(ipv6_prefix):
    while ipv6_prefix[-1] == '0000':
        ipv6_prefix = ipv6_prefix[:-1]
    return ipv6_prefix

# Zone file generation
def gen_origin_ipv4_reverse(zone):
    return '.'.join(reversed(get_ipv4_prefix(zone))) + '.in-addr.arpa.'

def gen_origin_ipv6_reverse(zone):
    addr_digits = list(''.join(get_ipv6_prefix(zone)))
    return '.'.join(reversed(addr_digits)) + '.ip6.arpa.'

def gen_zone_soa_ns(zone):
    return f'''\
@                  IN  SOA     {zone['soa']['primary_ns']} {zone['soa']['mailaddr']} (
                               {zone['soa']['serial']:<8}    ;Serial
                               7200        ;Refresh
                               3600        ;Retry
                               1209600     ;Expire
                               3600        ;Negative response caching TTL
                               )

                   IN  NS      {zone['soa']['primary_ns']}.{zone['fqdn_suffix']}
'''

def gen_zone_ipv4_forward(zone, hosts):
    ip_prefix = '.'.join(get_ipv4_prefix(zone))
    a_records_str = '\n'.join(
        f'{h.name:18} IN  A       {ip_prefix}.{h.ip_last}'
        for h in hosts
        )
    forward_zone = f'''\
$ORIGIN {zone['fqdn_suffix']}
$TTL 3600

{gen_zone_soa_ns(zone)}

{a_records_str}
'''
    return forward_zone

def gen_zone_ipv4_reverse(zone, hosts):
    origin = gen_origin_ipv4_reverse(zone)
    ptr_records_str = '\n'.join(
            f'{h.ip_last:<18} IN  PTR     {h.name}.{zone["fqdn_suffix"]}'
            for h in hosts
            )
    reverse_zone = f'''\
$ORIGIN {origin}
$TTL 3600

{gen_zone_soa_ns(zone)}

{ptr_records_str}
'''
    return reverse_zone

def gen_zone_ipv6_forward(zone, hosts):
    ip_prefix = ':'.join(get_ipv6_prefix(zone))
    def make_addr(h):
        return ipaddress.IPv6Address(f'{ip_prefix}::{hex(h.ip_last)[2:]}')

    aaaa_records_str = '\n'.join(
        f'{h.name:18} IN  AAAA    {make_addr(h).compressed}'
        for h in hosts
        )
    forward_zone = f'''\
$ORIGIN {zone['fqdn_suffix']}
$TTL 3600

{gen_zone_soa_ns(zone)}

{aaaa_records_str}
'''
    return forward_zone

def gen_zone_ipv6_reverse(zone, hosts):
    origin = gen_origin_ipv6_reverse(zone)
    def make_rev_addr(h):
        ip_last_hex = hex(h.ip_last)[2:]
        if h.ip_last < 16:
            first2 = ip_last_hex + '.0'
        else:
            first2 = '.'.join(reversed(ip_last_hex))
        num_digits = (128 - zone['ipv6_prefix'].prefixlen) // 4
        return first2 + '.0' * (num_digits - 2)

    ptr_records_str = '\n'.join(
            f'{make_rev_addr(h)}  IN  PTR     {h.name}.{zone["fqdn_suffix"]}'
            for h in hosts
            )
    reverse_zone = f'''\
$ORIGIN {origin}
$TTL 3600

{gen_zone_soa_ns(zone)}

{ptr_records_str}
'''
    return reverse_zone

def read_zone_and_hosts(dirpath, zone_filename):
    with open(os.path.join(dirpath, zone_filename)) as f:
        zone = read_zone(f)
    with open(os.path.join(dirpath, zone['hosts_file'])) as f:
        hosts = read_hosts(f)
    return (zone, hosts)

def gen_zone(zonedir, filename, gen_func, zone, hosts, force):
    print(f'\033[31m* Processing {filename}\033[0m')
    zone = gen_func(zone, hosts)
    filepath = os.path.join(zonedir, filename)

    with NamedTemporaryFile(dir=zonedir, prefix=filename+'.', delete=False) as f:
        new_filepath = f.name
        f.write(zone.encode('utf-8'))
    new_filename = os.path.basename(new_filepath)

    p = subprocess.run(['diff', '-u', filepath, new_filepath])
    if p.returncode == 0:
        print(f'no difference between {filename} and {new_filename}')
        os.remove(new_filepath)
        return

    if force:
        write = True
    else:
        ans = input(f'save to "{filepath}"? [y/N]')
        write = ans.lower() in ['y', 'yes']

    if write:
        os.rename(new_filepath, filepath)
        print(f'saved!')
    else:
        os.remove(new_filepath)
        print(f'canceled to save.')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('zone_json')
    p.add_argument('-d', '--zonedir', default='/etc/nsd/zone',
                   help='path to a directory holding zone files')
    p.add_argument('-f', '--force', action='store_true',
                   help='save a zone file without confirmation')
    args = p.parse_args()

    zone, hosts = read_zone_and_hosts(os.path.dirname(args.zone_json),
                                      os.path.basename(args.zone_json))

    fqdn_suffix = zone['fqdn_suffix']
    gen_zone(args.zonedir, f'{fqdn_suffix}zone',
             gen_zone_ipv4_forward, zone, hosts, args.force)
    gen_zone(args.zonedir, f'{gen_origin_ipv4_reverse(zone)}zone',
             gen_zone_ipv4_reverse, zone, hosts, args.force)
    gen_zone(args.zonedir, f'{fqdn_suffix}ip6.zone',
             gen_zone_ipv6_forward, zone, hosts, args.force)
    gen_zone(args.zonedir, f'{gen_origin_ipv6_reverse(zone)}zone',
             gen_zone_ipv6_reverse, zone, hosts, args.force)

if __name__ == '__main__':
    main()


# Unit tests
class TestFuncs(unittest.TestCase):
    def test_read_hosts(self):
        src = dedent('''
                100 dead
                254 beef
                ''')
        self.assertEqual(read_hosts(io.StringIO(src)), [
            HOST(100, 'dead'),
            HOST(254, 'beef'),
        ])

    def test_read_zone(self):
        src = dedent('''
                { "soa": { "serial": 6, "primary_ns": "ns1", "mailaddr": "foo@bar.com" },
                  "fqdn_suffix": "example.com.",
                  "ipv4_prefix": "192.168.10.0/24",
                  "ipv6_prefix": "fe80:dead:beef:0::0/64",
                  "hosts_file": "hogera"
                }
                ''')
        self.assertEqual(read_zone(io.StringIO(src)), {
            'soa': {
                'serial': 6,
                'primary_ns': 'ns1',
                'mailaddr': 'foo.bar.com.',
            },
            'fqdn_suffix': 'example.com.',
            'ipv4_prefix': ipaddress.IPv4Network('192.168.10.0/24'),
            'ipv6_prefix': ipaddress.IPv6Network('fe80:dead:beef::/64'),
            'hosts_file': 'hogera'
        })

    def test_get_ip_prefix(self):
        zone = { 'ipv4_prefix': ipaddress.IPv4Network('10.0.0.0/16'),
                 'ipv6_prefix': ipaddress.IPv6Network('fe80:dead::/48') }
        self.assertEqual(get_ipv4_prefix(zone), ['10', '0'])
        self.assertEqual(get_ipv6_prefix(zone), ['fe80', 'dead', '0000'])

    def test_gen_origin(self):
        zone = { 'ipv4_prefix': ipaddress.IPv4Network('192.168.10.0/24'),
                 'ipv6_prefix': ipaddress.IPv6Network('fe80:dead:beef::/64') }
        self.assertEqual(gen_origin_ipv4_reverse(zone),
                         '10.168.192.in-addr.arpa.')
        self.assertEqual(gen_origin_ipv6_reverse(zone),
                         '0.0.0.0.f.e.e.b.d.a.e.d.0.8.e.f.ip6.arpa.')
