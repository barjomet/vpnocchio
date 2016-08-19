# -*- coding: utf-8 -*-

import errno
import fcntl
import logging
import os
import random
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

import pexpect
import ptyprocess
import requests
import requests_toolbelt
from user_agent import generate_user_agent


__version__ = '0.0.14'
__author__ = 'Oleksii Ivanchuk (barjomet@barjomet.com)'


logging.getLogger("requests").setLevel(logging.WARNING)

ROUTE_UP_SCRIPT = """#!/bin/sh
table_id=2`echo $dev | cut -c 4-24`
ip route add default via $route_vpn_gateway dev $dev table $table_id
ip rule add from $ifconfig_local table $table_id
ip rule add to $route_vpn_gateway table $table_id
ip route flush cache
exit 0"""




class VPN:

    conf_dir = '/etc/openvpn'
    conf_file = None
    conf_files = None
    conf_match = '\.ovpn'
    connected = 0
    connect_timeout = 15
    instances = []
    interface = None
    interface_addr = None
    ip = None
    ip_services = [
        'http://ipinfo.io/ip',
        'http://ident.me/',
        'http://ip.barjomet.com',
        'http://icanhazip.com',
        'http://checkip.amazonaws.com/'
    ]
    log = logging.getLogger(__name__)
    log.addHandler(logging.NullHandler())
    mask_mtu = False
    min_time_before_reconnect = 30
    one_connection_per_conf = True
    req_timeout = 3
    route_up_script = None
    timeout = 15
    vpn_process = None
    witch_mtu_regex = re.compile('MTU\s+=\s(.*)')
    witch_openvpn_regex = re.compile('(.*OpenVPN detected[^<]*)')


    def __init__(self, username=None,
                       password=None,
                       conf_match=None,
                       default_route=False,
                       mask_mtu=False,
                       timeout=None,
                       id=None,
                       useragent=None):

        if id != None: self.id = id
        else: self.id = self._get_id()
        self.default_route = default_route
        if mask_mtu: self.mask_mtu = True
        if timeout: self.timeout = timeout

        self._init_logging()


        self.username = username
        self.password = password
        self.useragent = useragent

        self._get_conf_files(conf_match or self.conf_match)
        self.connect()

    def __repr__(self):
        return ("<VPNocchio id:%s conf:%s ip:%s>"
                % (self.id, self.conf_file, self.ip))


    @property
    def _is_running(self):
        try:
            os.kill(self.vpn_process.pid, 0)
        except OSError as err:
            if err.errno == errno.ESRCH:
                return False
            elif err.errno == errno.EPERM:
                return True
        else:
            return True


    @property
    def cmd(self):
        return ('sudo openvpn --config %s%s%s'
                % (self.conf_file,
                   ' --mssfix 1363' if self.mask_mtu \
                   else '',
                   ' --route-noexec --auth-nocache '
                   '--script-security 2 --route-up %s'
                   % self.route_up_script if not self.default_route \
                   else ''))


    def _get_id(self):
        ids = [one.id for one in self.__class__.instances]
        new_possible_id = len(ids)
        for who in range(new_possible_id-1):
            if who != ids[who]:
                return who
        return new_possible_id


    def _get_conf_files(self, match=''):
        filename_regex = re.compile(match, re.IGNORECASE)
        self.conf_files = [f for f in os.listdir(self.conf_dir)
                           if os.path.isfile(os.path.join(self.conf_dir, f))
                           and filename_regex.search(f)]
        return self.conf_files


    def _get_interface_addr(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.interface_addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s',
            self.interface[:15])
        )[20:24])


    def _init_logging(self):
        self.log = logging.getLogger('%s_%s' % (__name__, self.id))
        self.log.addHandler(logging.NullHandler())


    def _init_requests(self):
        self.session = requests.Session()
        self.session.headers.update({
            'user-agent' : self.useragent or generate_user_agent()})
        source = requests_toolbelt.adapters.source\
                                  .SourceAddressAdapter(self.interface_addr)
        self.session.mount('http://', source)
        self.session.mount('https://', source)


    def _select_conf_file(self):
        if not self.conf_files:
            self.log.error("There's no config files found dir:%s, pattern:%s",
                           self.conf_dir, self.conf_match)
            return False
        if self.one_connection_per_conf:
            conf_files = [f for f in self.conf_files
                          if f not in [i.conf_file for i in self.instances]]
            if not conf_files:
                self.log.error("There's no available vpn servers left")
                return False
        else:
            conf_files = self.conf_files
        self.conf_file = random.choice(conf_files)
        return True


    def check_ip(self):
        for attempt in range(len(self.ip_services)):
            try:
                self.ip = self.get(self.ip_services[0],
                                   timeout=self.req_timeout).text.rstrip()
                self.log.debug('External IP:%s', self.ip)
                return self.ip
            except:
                self.ip_services.append(self.ip_services.pop(0))


    def check_witch(self):
        r = self.get('http://witch.valdikss.org.ru/', timeout=self.timeout)
        try:
            mtu = self.witch_mtu_regex.search(r.text).group(1)
            message = self.witch_openvpn_regex.search(r.text).group(1)
            is_openvpn_detected  = False if u'No OpenVPN detected' \
                                         in message \
                                         else True
            return dict(mtu=mtu, detected=is_openvpn_detected, msg=message)
        except AttributeError:
            self.log.warning('Failed to parse W I T C H response')


    def connect(self):
        if self.connected: self.disconnect()
        if not self.default_route: self.create_route_up_script()
        while not self.connected and self._select_conf_file():
            self.vpn_process = pexpect.spawn(self.cmd,
                                             cwd=self.conf_dir,
                                             timeout=self.connect_timeout)

            try:
                if self.username and self.password:
                    self.vpn_process.expect('Enter Auth Username:')
                    self.vpn_process.sendline(self.username)
                    self.vpn_process.expect('Enter Auth Password:')
                    self.vpn_process.sendline(self.password)

                self.log.info('Connecting using config:%s', self.conf_file)
                self.vpn_process.expect('.* TUN/TAP device (.*) opened')
                self.interface = self.vpn_process.match.group(1)
                self.log.debug('Interface: %s', self.interface)
                self.vpn_process.expect('Initialization Sequence Completed')
                self.log.info('Connected')
                self._get_interface_addr()
                self.log.debug('Interface addr: %s', self.interface_addr)
                self.connected = time.time()
            except pexpect.EOF:
                self.log.debug(self.vpn_process.before)
                self.log.error('Invalid username and/or password')
            except pexpect.TIMEOUT:
                self.log.debug(self.vpn_process.before)
                self.log.error('Connection failed!')
        if not self.default_route: self.delete_route_up_script()
        self.instances.insert(self.id, self)
        self._init_requests()
        self.check_ip()


    def create_route_up_script(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            self.route_up_script = f.name
            f.write(ROUTE_UP_SCRIPT)
        st = os.stat(self.route_up_script)
        os.chmod(self.route_up_script, st.st_mode |\
                                       stat.S_IXUSR |\
                                       stat.S_IXGRP |\
                                       stat.S_IXOTH)


    def delete_route_up_script(self):
        os.remove(self.route_up_script)
        self.route_up_script = None


    def get(self, *args, **kwargs):
        return self.session.get(*args, **kwargs)


    def disconnect(self):
        if self.vpn_process is not None:
            try:
                self.vpn_process.sendcontrol('c')
                time.sleep(0.5)
                while self._is_running:
                    try:
                        self.vpn_process.close()
                    except ptyprocess.ptyprocess.PtyProcessError:
                        pass
                    time.sleep(0.1)
                self.connected = 0
                self.instances.remove(self)
                self.log.info('Disconnected')
            except ValueError:
                subprocess.call(['sudo', 'kill', str(self.vpn_process.pid)])


    def new_ip(self):
        if self.min_time_before_reconnect:
            seconds_since_last_connect = time.time() - self.connected
            if seconds_since_last_connect < self.min_time_before_reconnect:
                seconds_to_wait = self.min_time_before_reconnect \
                                  - seconds_since_last_connect
                self.log.warning("We'll wait %3.1f seconds before reconnect",
                                 seconds_to_wait)
                time.sleep(seconds_to_wait)
        self.disconnect()
        self.connect()



    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs)




def init_logging(level=logging.DEBUG):
    root = logging.getLogger()
    root.setLevel(level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatter)
    root.addHandler(ch)
