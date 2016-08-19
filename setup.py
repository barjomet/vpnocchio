from distutils.core import setup

VERSION = "0.0.16"

long_description = """How to use::


    from vpnocchio import VPN, init_logging
    from threading import Thread
    
    init_logging()
    
    # set your dir with ovpn files, default is:
    VPN.conf_dir = '/etc/openvpn
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
                     match_config_name)).start()"""



setup(name='VPNocchio',
    version=VERSION,
    description='Just a Python module suitable to use multiple OpenVPN connections at same time',
    long_description=long_description,
    url="https://github.com/barjomet/vpnocchio",
    license="BSD",
    author = "Oleksii Ivanchuk",
    author_email = "barjomet@barjomet.com",
    keywords = ["vpn", "proxy"],
    py_modules=['vpnocchio'],
    install_requires=['pexpect',
                      'requests',
                      'requests_toolbelt',
                      'user_agent'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        ]
    )
