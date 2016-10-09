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


__version__ = '0.0.24'
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

    auth_user_pass = None
    conf_dir = '/etc/openvpn'
    conf_file = None
    conf_files = None
    conf_match = '\.ovpn'
    conf_exclude = 'Virtual'
    connected = False
    connected_at = 0
    connect_timeout = 60
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
    management_unix_socket = None
    mssfix = None
    min_time_before_reconnect = 30
    one_connection_per_conf = True
    req_timeout = 3
    route_up_script = None
    timeout = 30
    tun_mtu = None
    vpn_process = None
    witch_mtu_regex = re.compile('MTU\s+=\s(.*)')
    witch_openvpn_regex = re.compile('(.*(?:OpenVPN detected|'
                                     'Probably OpenVPN)[^<^\n]*)')
    use_pexpect = False
    use_sudo = True


    def __init__(self, username=None,
                       password=None,
                       conf_match=None,
                       conf_exclude = None,
                       default_route=False,
                       mssfix=None,
                       tun_mtu=None,
                       timeout=None,
                       id=None,
                       useragent=None):

        if id != None: self.id = id
        else: self.id = self._get_id()
        self.default_route = default_route
        if mssfix: self.mssfix = mssfix
        if tun_mtu: self.tun_mtu = tun_mtu
        if timeout: self.timeout = timeout

        self._init_logging()


        self.username = username
        self.password = password
        self.useragent = useragent

        if conf_exclude : self.conf_exclude = conf_exclude
        self._get_conf_files(conf_match or self.conf_match)
        self.connect()

    def __repr__(self):
        return ("<VPNocchio id:%s conf:%s ip:%s>"
                % (self.id, self.conf_file, self.ip))


    @staticmethod
    def killall():
        if subprocess.call(['sudo', 'killall', 'openvpn']) == 0:
            return True
        else:
            return False


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
        return ' '.join(self.cmd_list)


    @property
    def cmd_list(self):
        self.management_unix_socket = tempfile.mkstemp()[1]
        return [str(i) for i in
                    (['sudo'] if self.use_sudo else []) +\
                    ['openvpn', '--config', self.conf_file] +\
                    (['--auth-user-pass', self.auth_user_pass]
                    if self.auth_user_pass else []) +\
                    (['--tun-mtu', self.tun_mtu] if self.tun_mtu else []) +\
                    (['--mssfix', self.mssfix] if self.mssfix else []) +\
                    (['--route-noexec',
                    '--script-security', '2',
                    '--route-up', self.route_up_script]
                    if not self.default_route else []) +\
                    ['--management', self.management_unix_socket, 'unix']]


    def _connect_method(self):
        if self.use_pexpect:
            return self._connect_pexepect()
        else:
            return self._connect_subprocess()


    def _connect_pexepect(self):
        self.vpn_process = pexpect.spawn(self.cmd,
                                         cwd=self.conf_dir,
                                         timeout=self.connect_timeout)
        try:
            if self.username and self.password:
                self.vpn_process.expect('Enter Auth Username:')
                self.vpn_process.sendline(self.username)
                self.vpn_process.expect('Enter Auth Password:')
                self.vpn_process.sendline(self.password)

            self.vpn_process.expect('.* TUN/TAP device (.*) opened')
            self.interface = self.vpn_process.match.group(1)
            self.vpn_process.expect('Initialization Sequence Completed')
            return True
        except pexpect.EOF:
            self.log.debug(self.vpn_process.before)
            self.log.error('Connection refused.')
        except pexpect.TIMEOUT:
            try:
                self.log.debug(self.vpn_process.before)
            except AttributeError:
                pass
            self.log.error('Connection failed! Time is out.')
        self.disconnect()
        return False


    def _connect_subprocess(self):
        error_regex = re.compile('error', re.IGNORECASE)
        interface_regex = re.compile('.* TUN/TAP device (.*) opened')
        success_regex = re.compile('Initialization Sequence Completed')
        self._create_auth_file()
        self.vpn_process = subprocess.Popen(self.cmd_list,
                                            cwd=self.conf_dir,
                                            stdout=subprocess.PIPE,
                                            universal_newlines=True)

        vpn_launched = time.time()
        try:
            while True:
                if time.time() - vpn_launched > self.connect_timeout:
                    self.log.error('Connection failed! Time is out.')
                    self.disconnect()
                    return False
                stdout = self.vpn_process.stdout.readline()
                interface_match = interface_regex.match(stdout)
                if interface_match:
                    self.interface = interface_match.group(1)
                if error_regex.search(stdout):
                    self.log.error('OpenVPN: %s', stdout)
                if success_regex.search(stdout):
                    return True
                time.sleep(.1)
        except ValueError as e:
            self.log.debug('Connection failed.')
            self.disconnect()
            return False
        finally:
            self._delete_auth_file()


    def _create_auth_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as _file:
            self.auth_user_pass = _file.name
            _file.write("%s\n%s" % (self.username, self.password))


    def _create_route_up_script(self):
        with tempfile.NamedTemporaryFile(delete=False) as _file:
            self.route_up_script = _file.name
            _file.write(ROUTE_UP_SCRIPT)
        st = os.stat(self.route_up_script)
        os.chmod(self.route_up_script, st.st_mode |\
                                       stat.S_IXUSR |\
                                       stat.S_IXGRP |\
                                       stat.S_IXOTH)


    def _delete_auth_file(self):
        os.remove(self.auth_user_pass)
        self.auth_user_pass = None


    def _delete_route_up_script(self):
        os.remove(self.route_up_script)
        self.route_up_script = None


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
        if self.conf_exclude:
            self.conf_files = [f for f in self.conf_files
                               if not self.conf_exclude in f]
        return self.conf_files


    def _get_interface_addr(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.interface_addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s',
            self.interface[:15])
        )[20:24])
        s.close()


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


    def _kill(self):
        try:
            if self.use_sudo:
                subprocess.call(['sudo', 'kill', str(self.vpn_process.pid)])
            else:
                os.kill(self.vpn_process.pid, 9)
        except Exception as e:
            self.log.warning('Unable to kill openvpn: %r', e)


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


    def _terminate(self):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.management_unix_socket)
            sock.send('signal SIGTERM\r\n')
            sock.recv(1)
        except Exception as e:
            self.log.warning('Failed to terminate OpenVPN process: %r', e)

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
        if not self.default_route: self._create_route_up_script()
        while not self.connected and self._select_conf_file():
            self.log.info('Connecting using config:%s', self.conf_file)
            if self._connect_method():
                self.log.info('Connected')
                self.log.debug('Interface: %s', self.interface)
                self._get_interface_addr()
                self.log.debug('Interface addr: %s', self.interface_addr)
                self.connected = True
                self.connected_at = time.time()
        if not self.default_route: self._delete_route_up_script()
        self.instances.insert(self.id, self)
        self._init_requests()
        self.check_ip()


    def get(self, *args, **kwargs):
        return self.session.get(*args, **kwargs)


    def disconnect(self):
        if self.vpn_process is not None:
            try:
                self._terminate()
            except ValueError:
                self._kill()
            time.sleep(0.5)
            while self._is_running:
                if self.use_pexpect:
                    try:
                        self.vpn_process.close(True)
                    except ptyprocess.ptyprocess.PtyProcessError:
                        pass
                else:
                    self.vpn_process.wait()
                time.sleep(0.1)
            self.connected = False
            try:
                self.instances.remove(self)
            except ValueError:
                pass
            self.vpn_process = self.ip = self.conf_file = None
            self.log.info('Disconnected')
        else:
            self.log.warning('Not connected')


    def new_ip(self):
        self.disconnect()
        if self.min_time_before_reconnect:
            seconds_since_last_connect = time.time() - self.connected_at
            if seconds_since_last_connect < self.min_time_before_reconnect:
                seconds_to_wait = self.min_time_before_reconnect \
                                  - seconds_since_last_connect
                self.log.warning("We'll wait %3.1f seconds before reconnect",
                                 seconds_to_wait)
                time.sleep(seconds_to_wait)
        self.connect()


    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs)




def init_logging(level=logging.DEBUG):
    root = logging.getLogger()
    root.setLevel(level)
    consolehandler = logging.StreamHandler(sys.stdout)
    consolehandler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    consolehandler.setFormatter(formatter)
    root.addHandler(consolehandler)
