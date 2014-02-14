Flowgrind - TCP traffic generator
=================================

Flowgrind is an advanced TCP traffic generator for testing and benchmarking **Linux**, **FreeBSD**, and **Mac OS X** TCP/IP stacks. In contrast to similar tools like iperf or netperf it features a distributed architecture, where throughput and other metrics are measured between arbitrary flowgrind server processes.

* Website: [www.flowgrind.com](http://www.flowgrind.com)
* Issues: [GitHub Issues](https://github.com/flowgrind/flowgrind/issues)
* API documentation: [Doxygen](http://flowgrind.github.io/flowgrind)


What It Can Do ?
================

Flowgrind measures besides goodput (throughput), the application layer interarrival time (IAT) and 2-way delay (RTT), blockcount and network transactions/s. Unlike most cross-platform testing tools, flowgrind can output some transport layer information, which are usually internal to the TCP/IP stack. For example, on Linux this includes among others the kernel's estimation of the end-to-end RTT and the size of the TCP congestion window (CWND) and slow start threshold (SSTHRESH).

Flowgrind has a distributed architecture. It is split into two components: the flowgrind daemon and the flowgrind controller. Using the controller, flows between any two systems running the flowgrind daemon can be setup (third party tests). At regular intervals during the test the controller collects and displays the measured results from the daemons. It can run multiple flows at once with the same or different settings and individually schedule every one. Test and control connection can optionally be diverted to different interfaces.

The traffic generation itself is either bulk transfer, rate-limited, or sophisticated request/response tests. Flowgrind uses libpcap to automatically dump traffic for qualitative analysis.


Building flowgrind
==================

Flowgrind builds cleanly on Linux, FreeBSD, and Mac OS X. Other operating systems are currently not planned to be supported. See INSTALL for instructions how to build flowgrind.


Instructions to run a test
==========================

1. Start `flowgrindd` on all machines that should be the endpoint of a flow.
2. Execute `flowgrind` on some machine (not necessarily one of the endpoints) with the host names of the endpoints passed through the -H option.

Example
-------
Assume we have 4 machines, host0, host1, host2 and host3 and flowgrind has been installed on all of them. We want to measure flows from host1 to host2 and from host1 to host3 in parallel, controlled from host0. First, we start `flowgrindd` on host1 to host3. On host0 we execute:

	# flowgrind -n 2 -F 0 -H s=host1,d=host2 -F 1 -H s=host1,d=host3


Host argument
=============

Flowgrind uses two connections:
* The test connection for the flows
* The RPC connections for the communication between `flowgrind` and `flowgrindd`

In order to not influence the test connection, the RPC control connection can be sent over different interfaces/routes. A typical scenario: Test WiFi connection and control over wired connection. Therefore there are two addresses: the test address and the control address. An unspecified control address address falls back to the test address.

Example
-------

Assume two machines running flowgrindd, each having two network adapters, one wired, one wireless. We run flowgrind on a machine that is connected by wire to the test machines. First machine has addresses 10.0.0.1 and 192.168.0.1, the other has addresses 10.0.0.2 and 192.168.0.1

So our host argument will be this:

	# flowgrind -H s=192.168.0.1/10.0.0.1,d=192.168.0.2/10.0.0.2

In words: Test from 192.168.0.1 to 192.168.0.2 on the nodes identified by 10.0.0.1 and 10.0.0.2 respectively.
