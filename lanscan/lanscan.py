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
import re
import errno
import click
from os.path import realpath, basename, isdir
import netifaces

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


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
        self.i = i
        self.name = name
        self.driver = Interface.get_driver(name)
        self.hardware = Interface.get_hardware(self.driver)

    def __repr__(self):
        return "<Name:{s.name},Driver:{s.driver},Hardware:{s.hardware}".format(s=self)


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
    _routes = routes()
    _interfaces = []
    for i in netifaces.interfaces():
        if netifaces.AF_INET in netifaces.ifaddresses(i):
            _interfaces.append(Interface(i, netifaces.ifaddresses(i)))
    ctx.obj = {'routes': _routes, 'interfaces': _interfaces}


@main.command('interfaces')
@click.pass_context
def interfaces(ctx):
    o = ctx.obj
    for interface in o['interfaces']:
        print(interface)


@main.command('scan')
@click.pass_context
def scan(ctx):
    o = ctx.obj
    for route in o['routes']:  # type: Route
        net = "{}/{}".format(route.net, route.mask)
        scan_and_print_neighbors(net, route.iface)
        # if net:
        #    scan_and_print_neighbors(net, interface)
