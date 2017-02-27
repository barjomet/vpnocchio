VPNocchio
=========

Just a Python module suitable to use multiple [OpenVPN](https://openvpn.net/) connections at the same time

Installation
============

    pip install vpnocchio

Usage
=====
hint: you should run this as root or set NOPASSWD sudo to run openvpn
```
from vpnocchio import VPN, init_logging
from threading import Thread

init_logging()

# set your dir with ovpn files, default is:
VPN.conf_dir = '/etc/openvpn'
# set minimum seconds must elapse between reconnects
VPN.min_time_before_reconnect = 30

credentials = [('usr1', 'pwd1', 'Germany'),
               ('usr1', 'pwd2', 'Spain')]

def do_something(*args):
    vpn = VPN(*args)
    for one in range(2):
        # it has requests inside
        response = vpn.get('http://ip.barjomet.com')
        vpn.log.info('Hooray, here is desired data: %s',  response.text)
        vpn.new_ip()
    vpn.disconnect()

for username, password, match_config_name in credentials:
    Thread(target=do_something,
           args=(username,
                 password,
                 match_config_name)).start()
```
