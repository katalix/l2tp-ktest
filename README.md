# L2TP KTest

l2tp-ktest is a suite of tools for testing the Linux kernel
[L2TP](https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol) dataplane.

The suite is designed to exercise the
[kernel's APIs](https://github.com/torvalds/linux/blob/master/Documentation/networking/l2tp.txt)
for creating and destroying tunnel and session contexts, to validate the data path
itself by sending and receiving session data, and to provide some stress tests to
attempt to trigger race conditions or
[oopses](https://en.wikipedia.org/wiki/Linux_kernel_oops) in the kernel itself.

Most of the tools are written in C.  A shell script, l2tp_ktest, combines most
of the tools into a test suite, and this is the easiest way to run them.

## Features

Currently l2tp-ktest provides tests for the following kernel features:

* [L2TPv2 (RFC2661)](https://tools.ietf.org/html/rfc2661)
* [L2TPv3 (RFC3931)](https://tools.ietf.org/html/rfc3931)
* AF_INET and AF_INET6 tunnel addresses
* UDP and L2TPIP tunnel encapsulation
* managed and unmanaged/static tunnel instances
* data path validation for PPP pseudowires

At present the following is unsupported:

* data path validation for Ethernet pseudowires

And the following tests are limited in scope:

* the stress-test applications don't cover a lot of scenarios
* the data path tests don't cover the various data path options such as UDP checksums,
  fragmentation/MTU, cookies, sequence numbers, or L2-Specific Sublayer

## Building the test suite

The test tools are built using a simple Makefile.

Build requirements are:

* GNU make,
* the GCC C toolchain,
* Linux system headers for L2TP,
* development headers and runtime libraries for [libnl](https://www.infradead.org/~tgr/libnl/),
  specifically libnl-3 and libnl-genl-3

To build the tools:

    $ make

The build outputs are combined in a tarball, l2tp-ktest.tgz, for easy copying
to a test machine.

On some older systems the syzbot applications (see below) fail to build:
in this situation they can be disabled in the makefile using the variable
OPT_NO_SYZBOT_APPS:

    $ make OPT_NO_SYZBOT_APPS=1

## Running the test suite

Once built, the test tools can be run in-place in the build directory, or
more usually copied to a test machine or VM for execution there.

The test machine will require:

* the GNU bash shell,
* root permissions to run the test suite,
* runtime libraries for libnl-3 and libnl-genl-3
* a version of [iproute2](https://github.com/shemminger/iproute2) supporting the
  l2tp subcommand: most Linux distributions include this by default

You can then run the test suite using the l2tp_ktest bash script.  The script offers
various options to control what it does: you can see documentation for these by
passing it the -h command line option.

Alternatively, to simply run the suite of tests, execute the script with no arguments:

    $ sudo ./l2tp_ktest

The script will probe the system for its capabilities prior to running the tests,
and will exclude any tests which aren't supported by the system.  For example,
tests using AF_INET6 addresses won't be run on a system that lacks IPv6 support.

## Running individual components

The test tools can be run on their own as well as by the test script:

* kcreate can be used to create tunnel and session instances in the kernel,
  and to explore kernel context lifetimes,
* datapath_verify can be used to send data over L2TP sessions in order to
  test the data path,
* tunl_delete_race and tunl_query_race are designed to provoke race conditions
  in the kernel,
* the syzbot applications are [sysbot](https://github.com/google/syzkaller)
  reproducers for bugs reported to the [netdev](http://vger.kernel.org/vger-lists.html#netdev)
  mailing list for the L2TP subsystem.

All tools except the syzbot reproducers offer interactive usage information via.
the -h command line option.

### syszbot reproducers

The [syzkaller/syzbot](https://github.com/google/syzkaller) project fuzz tests the
Linux kernel's system call interface to try to provoke oopses.  These are then reported
to the [netdev](http://vger.kernel.org/vger-lists.html#netdev) mailing list.

l2tp-ktest contains some historical syzbot reproducer applications which have
been reported to the mailing list: the src/syzbot directory contains the details of
these reports for reference.

Since the syzbot reproducer applications generally run in a never-ending loop, they
are not executed by l2tp_ktest.

Instead, run them directly, watching a serial console for any oopses.

## Environmental variables

Most of the test applications generate some logging, which can be controlled using
environmental variables:

* OPT_DEBUG should be defined in order to make logging more verbose
* OPT_QUIET should be defined in order to suppress all non error-related messages
* OPT_SILENT should be defined in order to suppress error messages

# History and context

We ([Katalix Systems Ltd.](https://katalix.com)) created l2tp-ktest as an internal project
supporting our work on the Linux L2TP subsystem and our [ProL2TP](https://prol2tp.com)
product which makes use of it.

Some of our [ProL2TP](https://prol2tp.com) customers deploy to embedded systems using
older kernels, and in such situations l2tp-ktest is useful to validate back-ported patches.

l2tp-ktest is also intended, in part, to act as a reference to the Linux L2TP API, which
is only partially covered by existing projects such as [iproute2](https://github.com/shemminger/iproute2).

Since 2019 the Linux kernel has included built-in L2TP tests in the
[kernel source tree](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/l2tp.sh).
