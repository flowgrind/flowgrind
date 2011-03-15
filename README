                                  Flowgrind
                                  =========

flowgrind grinds flows among hosts in your network.

See INSTALL for instructions how to build flowgrind.

Execute 'flowgrind -h' for a list of supported options.

Instructions to run a test
==========================

1. Start  flowgrindd  on all machines that should be the endpoint of a flow.
2. Execute  flowgrind  on some machine (not necessarily one of the endpoints)
   with the host names of the endpoints passed through the -H option.

Example
-------

Assume we have 4 machines, host0, host1, host2 and host3 and flowgrind has
been installed on all of them.
We want to measure flows from host1 to host2 and from host1 to host3 in
parallel, controlled from host0.
First start flowgrindd on host1-host3. 
On host0 we execute:

# flowgrind -n 2 -F 0 -H s=host1,d=host2 -F 1 -H s=host1,d=host3

Host argument
=============

Flowgrind uses two connections:
- The test connection for the flows
- The RPC connections for the communication between flowgrind and flowgrindd

In order to not influence the test connection, the RPC control connection
can be sent over different interfaces/routes. A typical scenario: Test WiFi
connection and control over wired connection.
Therefore there are two addresses:
The test address and the control address. An unspecified control address
address falls back to the test address.

This is important for the host argument:
  -H x=HOST[/CONTROL[:PORT]]

Example
-------

Assume two machines running flowgrindd, each having two network adapters, one
wired, one wireless. We run flowgrind on a machine that is connected by wire
to the test machines.
First machine has addresses 10.0.0.1 and 192.168.0.1, the other has addresses
10.0.0.2 and 192.168.0.1

So our host argument will be this:
  -H s=192.168.0.1/10.0.0.1,d=192.168.0.2/10.0.0.2

In words: Test from 192.168.0.1 to 192.168.0.2 on the nodes identified by
10.0.0.1 and 10.0.0.2 respectively.

