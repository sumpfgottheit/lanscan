"""
setcap cap_net_raw=eip /usr/bin/pythonX.X
setcap cap_net_raw=eip /usr/bin/tcpdump
"""

import os

os.environ['PATH'] = os.environ['PATH'] + ':/usr/sbin:/sbin'

import subprocess
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import math
import sys
import re
import netaddr
import errno
import click
from os.path import realpath, basename, isdir
import netifaces

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def exit_n(message, exitcode=1):
    click.echo("{} {}".format(click.style('Failed', fg='red'), message), err=True)
    sys.exit(exitcode)

def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warn("%s is too big. skipping" % net)
        return None

    return net


def scan_and_print_neighbors(net, interface, timeout=1):
    logger.info("arping %s on %s" % (net, interface))
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
        for s, r in ans.res:
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                # failed to resolve
                pass
            logger.info(line)
    except socket.error as e:
        if e.errno == errno.EPERM:  # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise


def get_driver(name):
    try:
        d = basename(realpath('/sys/class/net/{}/device/driver'.format(name)))
        if d == 'driver':
            return ''
        else:
            return d
    except Exception:
        return ''


def get_hardware(driver):
    if driver == '':
        return ''
    try:
        r = subprocess.check_output(['modinfo', driver]).decode('utf-8')
        return re.search(r'^description:\s*(.*)', r, re.M).groups()[0]
    except Exception:
        return ''


class Networks:
    def __init__(self):
        self.networks = []

    def initialize(self):
        interfaces = {}

        try:
            default_gateway_ip, default_interface_name = netifaces.gateways()['default'][netifaces.AF_INET]
        except Exception:
            default_gateway_ip, default_interface_name = None, None

        for interface_name in netifaces.interfaces():

            if interface_name not in interfaces:
                __driver = get_driver(interface_name)
                __hardware = get_hardware(__driver)
                interfaces[interface_name] = {'driver': __driver, 'hardware': __hardware}

            if netifaces.AF_INET in netifaces.ifaddresses(interface_name):
                for network in netifaces.ifaddresses(interface_name)[netifaces.AF_INET]:
                    ipnet = netaddr.IPNetwork("{}/{}".format(network['addr'], network['netmask']))
                    network_ip = ipnet.network
                    netmask = ipnet.netmask
                    prefix = ipnet.prefixlen
                    driver = interfaces[interface_name]['driver']
                    hardware = interfaces[interface_name]['hardware']

                    is_default_network = interface_name == default_interface_name and default_gateway_ip in ipnet

                    self.networks.append(
                        Network(interface_name, network_ip, netmask, prefix, driver, hardware, is_default_network))

    @property
    def len(self):
        return len(self.networks)

    @property
    def default_network_id(self):
        for i, network in enumerate(self.networks):  # type: Network
            if network.is_default_network:
                return i

    @property
    def default_network(self):
        return self.networks[self.default_network_id]

    def get_network_for_netaddr_ip(self, netaddr_ip: netaddr.IPNetwork):
        for network in self.networks:   # type: Network
            if network.netaddr_ip == netaddr_ip:
                return network
        else:
            raise KeyError("No local network for {} found.".format(str(netaddr_ip.cidr)))


class Network:
    def __init__(self, interface_name, network_ip, netmask, prefix, driver, hardware, is_default_network):
        self.interface_name = interface_name
        self.network_ip = network_ip
        self.netmask = netmask
        self.prefix = prefix
        self.driver = driver
        self.hardware = hardware
        self.is_default_network = is_default_network
        self.sort_value = netaddr.IPAddress(self.network_ip).value
        self.netaddr_ip = netaddr.IPNetwork("{}/{}".format(self.network_ip, self.netmask))

    @property
    def cidr(self):
        return str(self.netaddr_ip.cidr)

    def __repr__(self):
        return ("<Network:{s.network_ip}, Netmask:{s.netmask}, Prefix:{s.prefix}, "
                "Default:{s.is_default_network}, Interface_Name:{s.interface_name}, "
                "Driver:{s.driver}, Hardware:{s.hardware}, "
                "sort_value:{s.sort_value}>").format(s=self)


class Interface():
    @classmethod
    def get_driver(cls, name):
        try:
            d = basename(realpath('/sys/class/net/{}/device/driver'.format(name)))
            if d == 'driver':
                return ''
            else:
                return d
        except Exception:
            return ''

    @classmethod
    def get_hardware(cls, driver):
        if driver == '':
            return ''
        try:
            r = subprocess.check_output(['modinfo', driver]).decode('utf-8')
            return re.search(r'^description:\s*(.*)', r, re.M).groups()[0]
        except Exception:
            return ''

    def __init__(self, name, i):
        self.i = i[netifaces.AF_INET]
        self.name = name
        self.driver = Interface.get_driver(name)
        self.hardware = Interface.get_hardware(self.driver)

    def __repr__(self):
        return "<Name:{s.name},Driver:{s.driver},Hardware:{s.hardware},i:{s.i}".format(s=self)


class Route:
    def __init__(self, net, mask, gw, iface, addr):
        if mask == 0:
            self.mask = '0.0.0.0'
        else:
            self.mask = long2net(mask)
        self.net = scapy.utils.ltoa(net)
        self.gw = gw
        self.iface = iface
        self.addr = addr
        self.is_default = False

    def __repr__(self):
        return "<Net:{s.net},Mask:{s.mask},GW:{s.gw},Iface:{s.iface},Addr:{s.addr},Default:{s.is_default}".format(
            s=self)


def routes():
    """
    Return the list of current routes of the machine
    :return: list of Route()
    """
    default_route = None
    routes = []
    for route in scapy.config.conf.route.routes:
        route = Route(*route)
        if route.net == '0.0.0.0':
            default_route = route
            continue
        if route.iface == 'lo':
            continue
        routes.append(route)
    for route in routes:  # type: Route
        if route.iface == default_route.iface and route.addr == default_route.addr:
            route.is_default = True
    return routes


@click.group('main')
@click.pass_context
def main(ctx):
    networks = Networks()
    networks.initialize()
    ctx.obj = {'networks': networks}


@main.command('networks', help='Display a list of available networks.')
@click.pass_obj
def networks(o):
    for i, network in enumerate(o['networks'].networks, start=1):  # type: Network
        first = '*' if network.is_default_network else ' '
        print("{}: {} {}/{} on {}".format(i, first, network.network_ip, network.prefix, network.interface_name))


@main.command('scan', help='Scan a network, defaults to default network.')
@click.option('--network', '-n', 'arg_network', required=False,
              help="The network to scan in CIDR notation or the network number from 'lanscan networks'")
@click.pass_obj
def scan(o, arg_network):
    networks = o['networks']    # type: Networks
    n = None
    if arg_network is None:
        n = networks.default_network
    else:
        try:
            i = int(arg_network)
            if 1 <= i <= len(networks.networks):
                n = networks.networks[i - 1]
            else:
                exit_n("No network for id {} found. Try 'lanscan networks' to get networks.".format(i))
        except ValueError:
            try:
                _n = netaddr.IPNetwork(arg_network)
                click.echo("Scan for: {}".format(_n.cidr))
                n = networks.get_network_for_netaddr_ip(_n)
            except (KeyError, netaddr.AddrFormatError) as e:
                exit_n(str(e))

    click.echo("Network: {}".format(n.cidr))

