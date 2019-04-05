#!/usr/bin/python

'''

Provides a suite of unit tests for CS6250 Project 7



Author: Paul Triantafyllou (trianta2@gatech.edu)



Usage:

    1. Set pwd to project root directory: cd Project-7/

    2. Run your firewall: ./run-firewall.sh firewall-config.pol

    3. Launch the unit test runner: sudo python ./test_firewall.py

'''

from __future__ import print_function



import time

import contextlib

from threading import Thread

from itertools import repeat



from mininet.topo import Topo

from mininet.net  import Mininet

from mininet.node import  RemoteController

from mininet.link import TCLink





IPS = {

   'e1': '10.0.0.1',

   'e2': '10.0.0.2',

   'e3': '10.0.0.3',

   'mobile1': '10.0.0.4',

   'server1': '10.0.0.5',

   'server2': '10.0.0.6',

   'server3': '10.0.0.7',

   'w1': '10.0.0.8',

   'w2': '10.0.0.9',

   'w3': '10.0.0.10',

   }



SUCCESS = 0

FAILURE = 1

TIMEOUT = 124





def _create_timed_cmd(cmd, timeout=3):

    '''Creates a shell command string with a timeout'''

    return "timeout {} {}".format(timeout, _create_cmd(cmd))





def _create_cmd(cmd):

    '''Creates a shell command string that appends exit status'''

    return "{}; echo $?".format(cmd).format(**IPS)





@contextlib.contextmanager

def run_background_cmd(net, hostname, cmd, startup=1):

    '''Runs a command in the background'''

    thread = Thread(target=lambda: run_cmd(net, hostname, cmd, return_status=False))

    thread.start()



    time.sleep(startup)

    try:

        yield

    finally:

        net.get(hostname).sendInt()

        thread.join(timeout=5)





def run_cmd(net, hostname, cmd, timeout=None, return_status=True):

    '''Runs a command and returns the exit status. Blocking'''

    host = net.get(hostname)

    cmd_final = _create_cmd(cmd) if timeout is None else _create_timed_cmd(cmd, timeout)

    stdout = host.cmd(cmd_final)

    return _get_status(stdout) if return_status else stdout





def _get_status(stdout):

    '''Returns the exit status of a host command'''

    status_str = stdout.strip().split('\r\n')[-1]

    return int(status_str)





def test_req1(net, client_timeout=1.5):

    '''Runs tests for requirement 1'''

    clients = ('w1', 'w2', 'w3', 'e1', 'e2', 'e3', 'mobile1', 'server1', 'server3')



    # UDP should be fine

    with run_background_cmd(net, 'server2', 'python test-udp-server.py {server2} 1723'):

        cmd = 'python test-udp-client.py {server2} 1723'

        cmds = zip(clients, repeat(cmd), repeat(SUCCESS))

        run_test_cmds(net, cmds, 'Requirement 1: Show UDP 1723 still works on server2', client_timeout)



    # TCP should be blocked

    with run_background_cmd(net, 'server2', 'python test-tcp-server.py {server2} 1723'):

        cmd = 'python test-tcp-client.py {server2} 1723'

        cmds = zip(clients, repeat(cmd), repeat(TIMEOUT))

        run_test_cmds(net, cmds, 'Requirement 1: Show TCP 1723 is blocked on server2', client_timeout)





def test_req2(net, client_timeout=1.5):

    '''Runs tests for requirement 2'''

    clients = ('w1', 'w2', 'w3', 'server1', 'server2', 'server3')  # mobile1 is excluded due to req 6



    for proto in ('tcp', 'udp'):

        for dsthost in ('e1', 'e2', 'e3'):

            dsthost_template = '{' + dsthost + '}'

            client_cmd = "python test-{}-client.py {} 22".format(proto, dsthost_template)

            server_cmd = "python test-{}-server.py {} 22".format(proto, dsthost_template)

            with run_background_cmd(net, dsthost, server_cmd):

                cmds = zip(clients, repeat(client_cmd), repeat(TIMEOUT))

                run_test_cmds(net, cmds, "Requirement 2: {} port 22 should be blocked on host {}".format(proto, dsthost), client_timeout)



    for proto in ('tcp', 'udp'):

        for dsthost in ('e1', 'e2', 'e3'):

            dsthost_template = '{' + dsthost + '}'

            client_cmd = "python test-{}-client.py {} 23".format(proto, dsthost_template)

            server_cmd = "python test-{}-server.py {} 23".format(proto, dsthost_template)

            with run_background_cmd(net, dsthost, server_cmd):

                cmds = zip(clients, repeat(client_cmd), repeat(SUCCESS))

                run_test_cmds(net, cmds, "Requirement 2: {} on another port (e.g. 23) should still work on host {}".format(proto, dsthost), client_timeout)





def test_req3(net, client_timeout=1.5):

    '''Runs tests for requirement 3'''

    clients = ('w1', 'w2', 'w3', 'e1', 'e2', 'e3', 'mobile1', 'server1', 'server2', 'server3')



    for dsthost in ('server1', 'server2'):

        dsthost_template = '{' + dsthost + '}'

        for port in (123, 53):

            client_cmd = "python test-udp-client.py {} {}".format(dsthost_template, port)

            server_cmd = "python test-udp-server.py {} {}".format(dsthost_template, port)

            with run_background_cmd(net, dsthost, server_cmd):

                cmds = zip((c for c in clients if c != dsthost), repeat(client_cmd), repeat(TIMEOUT))

                run_test_cmds(net, cmds, "Requirement 3: udp port {} should be blocked on host {}".format(port, dsthost), client_timeout)



    dsthost = 'server3'

    dsthost_template = '{' + dsthost + '}'

    for port in (123, 53):

        client_cmd = "python test-udp-client.py {} {}".format(dsthost_template, port)

        server_cmd = "python test-udp-server.py {} {}".format(dsthost_template, port)

        with run_background_cmd(net, dsthost, server_cmd):

            cmds = zip((c for c in clients if c != dsthost), repeat(client_cmd), repeat(SUCCESS))

            run_test_cmds(net, cmds, "Requirement 3: udp port {} should still work on host {}".format(port, dsthost), client_timeout)





def test_req4(net):

    '''Runs tests for requirement 4'''

    cmd = 'ping -c 1 -W 1 {mobile1}'



    cmds = zip(('w1', 'w2'), repeat(cmd), repeat(FAILURE))

    run_test_cmds(net, cmds, 'Requirement 4: w1 and w2 cant ping mobile1')



    cmds = zip(('w3', 'e1', 'e2', 'e3', 'server1', 'server2', 'server3'), repeat(cmd), repeat(SUCCESS))

    run_test_cmds(net, cmds, 'Requirement 4: other hosts can ping mobile1')





def test_req5(net, client_timeout=1.5):

    '''Runs tests for requirement 5'''

    for port in (9950, 9951, 9952):

        client_cmd = "python test-tcp-client.py {{e3}} {}".format(port)

        server_cmd = "python test-tcp-server.py {{e3}} {}".format(port)

        with run_background_cmd(net, 'e3', server_cmd):

            cmds = (('e1', client_cmd, TIMEOUT), )

            run_test_cmds(net, cmds, "Requirement 5: tcp port {} traffic for e1 --> e3 should be blocked".format(port), client_timeout)



    for port in (9949, 9953):

        client_cmd = "python test-tcp-client.py {{e3}} {}".format(port)

        server_cmd = "python test-tcp-server.py {{e3}} {}".format(port)

        with run_background_cmd(net, 'e3', server_cmd):

            cmds = (('e1', client_cmd, SUCCESS), )

            run_test_cmds(net, cmds, "Requirement 5: tcp port {} traffic for e1 --> e3 should still work".format(port), client_timeout)





def test_req6(net, client_timeout=1.5):

    '''Runs tests for requirement 6'''

    port = 1234

    for proto in ('tcp', 'udp'):

        for dsthost in ('e1', 'e2', 'e3'):

            dsthost_template = '{' + dsthost + '}'

            client_cmd = "python test-{}-client.py {} {}".format(proto, dsthost_template, port)

            server_cmd = "python test-{}-server.py {} {}".format(proto, dsthost_template, port)

            with run_background_cmd(net, dsthost, server_cmd):

                cmds = (('mobile1', client_cmd, TIMEOUT), )

                run_test_cmds(net, cmds, "Requirement 6: {} traffic (e.g. port {}) for mobile1 --> {} should be blocked".format(proto, port, dsthost), client_timeout)



    for proto in ('tcp', 'udp'):

        for dsthost in ('w1', 'w2', 'w3', 'server1', 'server2', 'server3'):

            dsthost_template = '{' + dsthost + '}'

            client_cmd = "python test-{}-client.py {} {}".format(proto, dsthost_template, port)

            server_cmd = "python test-{}-server.py {} {}".format(proto, dsthost_template, port)

            with run_background_cmd(net, dsthost, server_cmd):

                cmds = (('mobile1', client_cmd, SUCCESS), )

                run_test_cmds(net, cmds, "Requirement 6: {} traffic (e.g. port {}) for mobile1 --> {} should still work".format(proto, port, dsthost), client_timeout)





def run_test_cmds(net, cmds, test_title, timeout=None):

    '''Console-friendly test runner'''

    print("=== Running Tests: {} ===".format(test_title))

    for hostname, cmd, expected in cmds:

        print("Running {}.cmd('{}') ...".format(hostname, cmd), end=' ')

        status = run_cmd(net, hostname, cmd, timeout)

        assert status == expected, "Failure! Status={} Expected={}".format(status, expected)

        print("Success! Status={} Expected={}".format(status, expected))

    print()





class FWTopo(Topo):

    '''Creates the following topoplogy:

                 e1   e2   e3

    server1  \     |    |    |

              \     \   |   /

    server2 ----  firewall (s1) --- mobile1

              /    /   |   \

    server3  /    |    |    |

                 w1    w2   w3

    '''

    def __init__(self, cpu=.1, bw=10, delay=None, **params):

        super(FWTopo,self).__init__()



        # Host in link configuration

        hconfig = {'cpu': cpu}

        lconfig = {'bw': bw, 'delay': delay}



        # Create the firewall switch

        s1 = self.addSwitch('s1')



        # Create East hosts and links)

        e1 = self.addHost('e1', **hconfig)

        e2 = self.addHost('e2', **hconfig)

        e3 = self.addHost('e3', **hconfig)

        self.addLink(s1, e1, port1=1, port2=1, **lconfig)

        self.addLink(s1, e2, port1=2, port2=1, **lconfig)

        self.addLink(s1, e3, port1=3, port2=1, **lconfig)



        # Create West hosts and links)

        w1 = self.addHost('w1', **hconfig)

        w2 = self.addHost('w2', **hconfig)

        w3 = self.addHost('w3', **hconfig)

        self.addLink(s1, w1, port1=4, port2=1, **lconfig)

        self.addLink(s1, w2, port1=5, port2=1, **lconfig)

        self.addLink(s1, w3, port1=6, port2=1, **lconfig)



        # Add 'host1' for packet flood testing

        mobile1 = self.addHost('mobile1', **hconfig)

        self.addLink(s1, mobile1, port1=7, port2=1, **lconfig)



        # Create Server hosts and links)

        server1 = self.addHost('server1', **hconfig)

        server2 = self.addHost('server2', **hconfig)

        server3 = self.addHost('server3', **hconfig)

        self.addLink(s1, server1, port1=8, port2=1, **lconfig)

        self.addLink(s1, server2, port1=9, port2=1, **lconfig)

        self.addLink(s1, server3, port1=10, port2=1, **lconfig)





if __name__ == '__main__':

    '''Main'''



    print("Starting topology")



    topo = FWTopo()

    net = Mininet(topo=topo, link=TCLink, controller=RemoteController, autoSetMacs=True)

    net.start()

    

    # thanks Emile!

    net.waitConnected()

    net.pingAll()

    

    test_req1(net)

    test_req2(net)

    test_req3(net)

    test_req4(net)

    test_req5(net)

    test_req6(net)
