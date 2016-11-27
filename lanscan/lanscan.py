"""
setcap cap_net_raw=eip /usr/bin/pythonX.X
setcap cap_net_raw=eip /usr/bin/tcpdump
"""

import os
import click
import sys

os.environ['PATH'] = os.environ['PATH'] + ':/usr/sbin:/sbin'


def exit_n(message, exitcode=1):
    click.echo("{} {}".format(click.style('Failed', fg='red'), message), err=True)
    sys.exit(exitcode)


import shutil

for progs in ('nmap', 'tcpdump'):
    all_found = True
    if shutil.which('tcpdump') is None:
        print("tcpdump is not found in the path. Please install it.")
        all_found = False
    if shutil.which('nmap') is None:
        print("nmap is not found in the path. Please install it.")
        all_found = False
    if not all_found:
        exit_n("The necessary programs are not available.")

import subprocess
import logging
import logging.config
import nmap
import scapy.config
import scapy.layers.l2
import scapy.route
import texttable
import socket
from queue import Queue
import re
import netaddr
import errno
from os.path import realpath, basename, isdir, isfile
import netifaces
import requests
import threading
import yaml
from appdirs import AppDirs
import json

APP_NAME = 'lanscan'
APPDIRS = AppDirs(APP_NAME)
LOGFILE = os.path.join(APPDIRS.user_log_dir, 'lanscan.log')
VENDOR_CACHE = os.path.join(APPDIRS.user_cache_dir, 'vendors')

NMAP_SCANNER = nmap.PortScanner()

# logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


def initialize_directories():
    if not isdir(APPDIRS.user_cache_dir):
        os.makedirs(APPDIRS.user_cache_dir, mode=0o755, exist_ok=True)
    if not isdir(APPDIRS.user_log_dir):
        os.makedirs(APPDIRS.user_log_dir, mode=0o755, exist_ok=True)


def configure_logger(debug_to_stdout):
    filename = os.path.join(os.path.dirname(__file__), 'logging.yaml')
    with open(filename) as fp:
        config_dict = yaml.load(fp)
    config_dict['handlers']['logfile']['filename'] = LOGFILE
    if debug_to_stdout:
        config_dict['handlers']['console']['level'] = logging.DEBUG
    logging.config.dictConfig(config_dict)


def ping(ip):
    """
    Returns True if host responds to a ping request
    """
    return os.system("ping -c 1 " + ip + " >/dev/null") == 0


def get_vendor(mac):
    try:
        url = 'http://www.macvendorlookup.com/api/v2/' + mac
        return requests.get(url).json()[0]['company']
    except Exception as e:
        logger.warning(e)
        return ""


def get_driver(name):
    try:
        d = basename(realpath('/sys/class/net/{}/device/driver'.format(name)))
        if d == 'driver':
            return ''
        else:
            return d
    except Exception as e:
        logger.error(e)
        return ''


def get_hardware(driver):
    if driver == '':
        return ''
    try:
        logger.debug("Call: modinfo {}".format(driver))
        r = subprocess.check_output(['modinfo', driver]).decode('utf-8')
        hardware = re.search(r'^description:\s*(.*)', r, re.M).groups()[0]
        logger.debug("Hardware for %s is %s", driver, hardware)
        return hardware
    except Exception as e:
        logger.error(e)
        return ''


def get_all_vendors(macs):
    input_queue = Queue()
    result_hash = {}
    cache = {}
    logger.debug("Get all vendor informations")
    if isfile(VENDOR_CACHE):
        try:
            cache = json.load(open(VENDOR_CACHE))
            logger.debug("Vendor cachefile %s loaded", VENDOR_CACHE)
        except Exception:
            cache = {}

    class GetVendorThread(threading.Thread):
        def __init__(self, input_queue, result_hash):
            super().__init__()
            self.input_queue = input_queue
            self.result_hash = result_hash

        def run(self):
            while True:
                mac = self.input_queue.get()
                if mac in cache:
                    vendor = cache[mac]
                    logger.debug("CacheHit: mac=%s, vendor=%s", mac, vendor)
                else:
                    vendor = get_vendor(mac)
                    logger.debug("CacheMiss - Queried: mac=%s, vendor=%s", mac, vendor)
                self.result_hash[mac] = vendor
                self.input_queue.task_done()

    # Start 20 Threads, all are waiting in run -> self.input_queue.get()
    for i in range(20):
        thread = GetVendorThread(input_queue, result_hash)
        thread.setDaemon(True)
        thread.start()

    # Fill the input queue
    for mac in macs:
        input_queue.put(mac)

    input_queue.join()
    cache.update(result_hash)
    json.dump(cache, open(VENDOR_CACHE, 'w'), indent=2)
    return result_hash

def ping_ips(ips):
    input_queue = Queue()
    result_hash = {}
    logger.debug("Pinging IPs")

    class PingHostThread(threading.Thread):
        def __init__(self, input_queue, result_hash):
            super().__init__()
            self.input_queue = input_queue
            self.result_hash = result_hash

        def run(self):
            while True:
                _ip = self.input_queue.get()
                is_alive = ping(_ip)
                if is_alive:
                    logger.debug("Host %s is alive" % _ip)
                else:
                    logger.debug("Host %s is not alive" % _ip)
                self.result_hash[_ip] = is_alive
                self.input_queue.task_done()

    # Start 20 Threads, all are waiting in run -> self.input_queue.get()
    for i in range(20):
        thread = PingHostThread(input_queue, result_hash)
        thread.setDaemon(True)
        thread.start()

    # Fill the input queue
    for ip in ips:
        input_queue.put(ip)

    input_queue.join()
    return result_hash


def get_open_ports(ip):
    result = {}
    scan = NMAP_SCANNER.scan(hosts=ip, arguments='-sT')
    try:
        tcp_ports = scan.get('scan')[ip]['tcp']
        for port, extra in tcp_ports.items():
            result[port] = extra['name']
    except Exception:
        pass
    return result


def get_all_open_ports(ips):
    input_queue = Queue()
    result_hash = {}
    logger.debug("Get all port information")

    class GetNmapThread(threading.Thread):
        def __init__(self, input_queue, result_hash):
            super().__init__()
            self.input_queue = input_queue
            self.result_hash = result_hash

        def run(self):
            while True:
                ip = self.input_queue.get()
                open_ports = get_open_ports(ip)
                self.result_hash[ip] = open_ports
                self.input_queue.task_done()

    # Start 20 Threads, all are waiting in run -> self.input_queue.get()
    for i in range(20):
        thread = GetNmapThread(input_queue, result_hash)
        thread.setDaemon(True)
        thread.start()

    # Fill the input queue
    for ip in ips:
        input_queue.put(ip)

    input_queue.join()
    return result_hash


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
            self.networks.sort(key=lambda x: x.sort_value)

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
        for network in self.networks:  # type: Network
            if network.netaddr_ip == netaddr_ip:
                return network
        else:
            raise KeyError("No local network for {} found.".format(str(netaddr_ip.cidr)))

    @property
    def interfaces(self):
        _interfaces = {}
        for network in self.networks:  # type: Network
            if network.interface_name not in _interfaces:
                _interfaces[network.interface_name] = {'driver': network.driver, 'hardware': network.hardware,
                                                       'name': network.interface_name}
        interfaces = list(_interfaces.values())  # type: list
        interfaces.sort(key=lambda x: x['name'])
        return interfaces


class Host:
    def __init__(self, ip_address, mac_address):
        self.ip = ip_address
        self.mac = mac_address
        self.sort_value = netaddr.IPAddress(self.ip).value
        try:
            self.hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            # failed to resolve
            self.hostname = ''
        self.vendor = ''
        self.is_alive = False
        self.open_ports = {}

    @property
    def open_port_numbers(self):
        return sorted(list(self.open_ports.keys()))

    def __repr__(self):
        return "<IP:{s.ip}, Mac:{s.mac}, Name:{s.hostname}, Vendor:{s.vendor}, is_alive:{s.is_alive}, OpenPorts:{s.open_port_numbers}>".format(
            s=self)


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
        self.neighbours = []

    def print_neighbours(self):
        for host in self.neighbours:
            print(host)

    @property
    def cidr(self):
        return str(self.netaddr_ip.cidr)

    def scan(self, get_vendor, do_portscan, timeout=1):
        try:
            ans, unans = scapy.layers.l2.arping(self.cidr, iface=self.interface_name, timeout=timeout, verbose=False)
            for s, r in ans.res:
                self.neighbours.append(Host(r.psrc, r.src))
        except socket.error as e:
            if e.errno == errno.EPERM:  # Operation not permitted
                message = ("Error: {}\n"
                           "Run as root or - better - set the necessary capabilities for the python interpreter used and tcpdump.\n"
                           "Example: setcap cap_net_raw=eip /usr/bin/python3\n"
                           "Example: setcap cap_net_raw=eip $(which tcpdump)\n"
                           "You may need to install the libcap-progs package").format(e.strerror)
                exit_n(message, 2)
            else:
                raise

        self.neighbours.sort(key=lambda x: x.sort_value)
        if get_vendor:
            self.set_vendor_in_neighbours()
        if do_portscan:
            self.set_open_ports_in_neigbours()
        self.set_is_alive_in_neigbours()

    def set_vendor_in_neighbours(self):
        macs = [host.mac for host in self.neighbours]
        h = get_all_vendors(macs)
        for host in self.neighbours:  # type: Host
            if host.mac in h:
                host.vendor = h[host.mac]

    def set_is_alive_in_neigbours(self):
        ips = [host.ip for host in self.neighbours]
        h = ping_ips(ips)
        for host in self.neighbours:  # type: Host
            host.is_alive = h.get(host.ip, False)

    def set_open_ports_in_neigbours(self):
        ips = [host.ip for host in self.neighbours]
        h = get_all_open_ports(ips)
        for host in self.neighbours:  # type: Host
            if host.ip in h:
                host.open_ports = h[host.ip]

    def __repr__(self):
        return ("<Network:{s.network_ip}, Netmask:{s.netmask}, Prefix:{s.prefix}, "
                "Default:{s.is_default_network}, Interface_Name:{s.interface_name}, "
                "Driver:{s.driver}, Hardware:{s.hardware}, "
                "sort_value:{s.sort_value}>").format(s=self)


@click.group('main')
@click.option('-d', 'debug', is_flag=True, default=False, help="Print debug messages to stdout.")
@click.pass_context
def main(ctx, debug):
    initialize_directories()
    configure_logger(debug)
    networks = Networks()
    networks.initialize()
    ctx.obj = {'networks': networks}


@main.command('networks', help='Display a list of available networks.')
@click.pass_obj
def networks(o):
    content = []
    for i, network in enumerate(o['networks'].networks, start=1):  # type: Network
        first = '*' if network.is_default_network else ' '
        content.append((i, first, network.netaddr_ip.cidr, network.interface_name))
    header = ['#', 'default', 'cidr', 'interface']
    width, height = click.get_terminal_size()
    table = texttable.Texttable(max_width=width)
    table.set_deco(table.HEADER)
    table.header(header)
    table.add_rows(content, header=False)
    print(table.draw())


@main.command('interfaces', help='Display a list available interfaces')
@click.pass_obj
def interfaces(o):
    networks = o['networks']  # type: Networks
    content = []
    for i, interface in enumerate(networks.interfaces, start=1):
        content.append((i, interface['name'], interface['driver'], interface['hardware']))
    header = ['#', 'interface', 'driver', 'hardware']
    width, height = click.get_terminal_size()
    table = texttable.Texttable(max_width=width)
    table.set_deco(table.HEADER)
    table.header(header)
    table.add_rows(content, header=False)
    print(table.draw())


@main.command('scan', help='Scan a network, defaults to default network.')
@click.option('--network', '-n', 'arg_network', required=False,
              help="The network to scan in CIDR notation or the network number from 'lanscan networks'")
@click.option('--vendor/--no-vendor', default=True,
              help="Vendor lookup based on Mac addres. Requires internet connection.")
@click.option('--portscan/--no-portscan', default=True, help="Let nmap do a simple connect-portscan.")
@click.pass_obj
def scan(o, arg_network, vendor, portscan):
    networks = o['networks']  # type: Networks
    n = None  # type: Network
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

    logger.debug("Network: {}".format(n.cidr))
    n.scan(vendor, portscan)
    header = ['ip', 'name', 'mac', 'alive', 'vendor', 'open ports']
    content = [(host.ip, host.hostname, host.mac, str(host.is_alive), host.vendor, ", ".join(map(str, host.open_port_numbers))) for host in
               n.neighbours]
    width, height = click.get_terminal_size()
    table = texttable.Texttable(max_width=width)
    table.set_deco(table.HEADER)
    table.header(header)
    table.add_rows(content, header=False)
    print(table.draw())
