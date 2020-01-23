# L2TP KTest

l2tp_ktest is a suite of tools for testing the Linux kernel L2TP dataplane.

Most of the tools are written in C.  A shell script, l2tp_ktest, combines most
of the tools into a test suite, and this is the easiest way to run them.

## Building the test suite

The test tools are built using a simple Makefile.  Build and test machines will
need to have libnl-3 installed.

To build:

    $ make

The build outputs are combined in a tarball, l2tp-ktest.tgz, for easy copying
to a test machine.

## Running the test suite

Once built, the test tools can be run in-place in the build directory, or
more usually copied to a test machine or VM for execution there.

The test machine will require:

* root permissions to run the test suite,
* libnl-3,
* a version of [iproute2](https://github.com/shemminger/iproute2) supporting the
  l2tp subcommand: most Linux distributions include this by default

You can then run the test suite using the script:

    $ sudo ./l2tp_ktest

This will iterate through all the unit tests and generate a summary of results
at the end.  Pay attention to any failing test cases, and watch a serial console
for any kernel oopses.

## Running individual components

The test tools can be run on their own as well as by the test script:

* kcreate can be used to create tunnel and session instances in the kernel,
  and to explore kernel context lifetimes,
* datapath_verify can be used to send data over L2TP sessions in order to
  test the data path,
* tunl_delete_race and tunl_query_race are designed to provoke race conditions
  in the kernel,
* the syzbot_* applications are [sysbot](https://github.com/google/syzkaller)
  reproducers for bugs reported to the [netdev](http://vger.kernel.org/vger-lists.html#netdev)
  mailing list for the L2TP subsystem.

All tools except the syzbot reproducers offer interactive usage information via.
the -h command line option.

The syzbot reproducer applications generally just need running to try to provoke the
bug associated with them.  They typically run a never-ending loop.

## Environmental variables

Most of the test applications generate some logging, which can be controlled using
environmental variables:

* OPT_DEBUG should be defined in order to make logging more verbose
* OPT_QUIET should be defined in order to suppress all non error-related messages
* OPT_SILENT should be defined in order to suppress error messages
