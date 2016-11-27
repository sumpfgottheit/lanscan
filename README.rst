lanscan
=======

::

     # lanscan  scan
          ip                    name                     mac          alive                vendor                                        open ports
    =======================================================================================================================================================================
    192.168.50.1     router.asus.com              54:a0:50:5b:32:81   True    ASUSTek COMPUTER INC.              53, 8443
    192.168.50.97                                 1c:5a:6b:78:48:52   True    Philips Electronics Nederland BV   2323, 8000, 49154
    192.168.50.107   kindle-4bef0bcfc             74:c2:46:12:5b:01   True    Amazon Technologies Inc.           5000, 5555, 7000, 7100, 8008
    192.168.50.124   YotaPhone-1b4fe319cb0f71a1   28:c6:71:01:3a:6d   True    Yota Devices OY

``lanscan`` is a Python 3 module, that provides the ``lanscan`` console
command. It scans a given local network and presents all devices on this
network. It also gives information about present network interfaces and
networks. ``lanscan`` uses the ``nmap``, ``tcpdump`` and ``ping``
commands.

Usage::

    $ lanscan
    Usage: lanscan [OPTIONS] COMMAND [ARGS]...

    Options:
      -d      Print debug messages to stdout.
      --help  Show this message and exit.

    Commands:
      interfaces  Display a list available interfaces
      networks    Display a list of available networks.
      scan        Scan a network, defaults to default network.

Show interfaces
---------------

A list of all current interfaces::

    $ lanscan interfaces
    #      interface      driver                         hardware
    ===================================================================================
    1   br-e0e27b4e551f
    2   docker0
    3   enp0s20f0u1u4     r8152     Realtek RTL8152/RTL8153 Based USB Ethernet Adapters
    4   lo
    5   wlp1s0            iwlwifi   Intel(R) Wireless WiFi driver for Linux

Show local networks
-------------------

A list of all local networks::

    $ lanscan networks
    #   default        cidr            interface
    ===============================================
    1             127.0.0.0/8       lo
    2             172.17.0.0/16     docker0
    3             172.18.0.0/16     br-e0e27b4e551f
    4   *         192.168.50.0/24   enp0s20f0u1u4

Scan a local network
--------------------

The ``lanscan scan`` command has a few parameters::

    $ lanscan scan --help
    Usage: lanscan scan [OPTIONS]

      Scan a network, defaults to default network.

    Options:
      -n, --network TEXT          The network to scan in CIDR notation or the
                                  network number from 'lanscan networks'
      --vendor / --no-vendor      Vendor lookup based on Mac addres. Requires
                                  internet connection.
      --portscan / --no-portscan  Let nmap do a simple connect-portscan.
      --help                      Show this message and exit.

Let's scan the default network::

     # lanscan  scan
          ip                    name                     mac          alive                vendor                                        open ports
    =======================================================================================================================================================================
    192.168.50.1     router.asus.com              54:a0:50:5b:32:81   True    ASUSTek COMPUTER INC.              53, 8443
    192.168.50.97                                 1c:5a:6b:78:48:52   True    Philips Electronics Nederland BV   2323, 8000, 49154
    192.168.50.107   kindle-4bef0bcfc             74:c2:46:12:5b:01   True    Amazon Technologies Inc.           5000, 5555, 7000, 7100, 8008
    192.168.50.124   YotaPhone-1b4fe319cb0f71a1   28:c6:71:01:3a:6d   True    Yota Devices OY

Installation
------------

``lanscan`` has been written using Python 3.5, so the chances are good,
that Python versions from 3.3 may work. It has been written on linux and
I don't think, that it will work on Windows or OS X.

Create a virtualenv and call ``pip install lanscan``. The requirements
will automatically be installed within your virtualen. To make calling
easier, create the file ``/usr/local/bin/lanscan`` with::

     #!/bin/bash
     source ${PATH_TO_YOUR_VIRTUALENV}/bin/activate
     lanscan $@


Necessary permissions
---------------------

``lanscan`` needs special permissions, to be able to open a raw socket. You may run it as root - not recommended - or you set the necessary capabilities (man 7 capabilities). 
The capability needed is ``cap_net_raw=eip`` and this needs to be set on the python interpreter used and the ``tcpdump`` binary using ``setcap``. ``setcap`` cannot work on
symlinks, so the real binary is needed. ``setcap`` needs to be run with superuser privileges::

   setcap cap_net_raw=eip /path/to/virtualenv/bin/python3
   setcap cap_net_raw=eip $(which tcpdump)

You may need to install the necessary packages. On OpenSuse, the package is called ``libcap-progs``. On Arch, everything should be in place.

The github repository can be found at

https://github.com/sumpfgottheit/lanscan
