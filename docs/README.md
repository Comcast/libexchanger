libExchanger() implements SPAKE2+ protocol.

It is an PBKDF2-based implementation of a SPAKE2+ protocol. It has
followin features.

1) The code is be written in ANSI C.

2) The code compiles and run on Linux (64 bit) and OSX.

3) The code contains unit tests that can run independent of functional
tests.

4) The code uses CMake as the build system.

5) Compile time flags are added to the CMake files to treat compiler
warnings as errors. When compiling, there must be no warnings and/or
errors.

6) There are no memory leaks. The code passes through Valgrind.

7) The CMake files enable Address Sanitizer and there are no errors when
executed.

8) The code must be built as a shared library and contain a separate
stand alone main program that links to this library.

9) If cryptographic functions are used, the code MUST link to OpenSSL
1.1.1 or above.

10) The main program demonstrates how the library could be instantiated
as a server / client on two ends.

11) On the client side, a 6-8 digit pin should be used, then both sides
exchange messages to compute a shared secret.

HOW TO
======

Prerequisites
=============

To build the library you need following tools and libraries installed in
your system:

-   CMake v.3.12 or higher

-   OpenSSL development library, version 1.1.0g or 1.1.1f

-   Valgrind 3.13.0 or higher

-   Doxygen 1.8.13 or higher

Download the source code
========================

    git clone <Repo:libexchanger.git>

    cd libexchanger

    git submodule update --init

Compile the library
===================

CMake is used as a build system for this project. Using CMake all build
artifacts like object files, binaries, logs, etc., are stored in a
folder where the CMake is being run. Thus, a recommended way of using
CMake is to create a new directory and to run CMake from there. This
allows to completely separate original sources from building artifacts
and makes cleaning process as easy as possible. To cleanup the project
it’s enough to remove the build files in the folder where CMake was run.

The project supports following build configurations:

-   Release - build project with compiler optimization and without debug
    information

-   Debug - build project with debug information (valgrind must be
    installed)

-   asan - build with Address Sanitizer features for real-time address
    checking

-   lsan - build with Address Sanitizer features for real-time memory
    leaks checking

-   ubsan - build with Address Sanitizer features for real-time checking
    for undefined behavior

To build the library using Release configuration use following commands:

    mkdir Release
    cd Release
    cmake --DCMAKE_BUILD_TYPE=Release ..
    cmake --build .

To compile the documentation use the following command instead of the
last command above: doxygen must be installed to build docs

    cmake --build . --target docs

Now the **Release** directory contains `client` and `server` example
binaries and `unity_tests` for testing the code.

All configurations use compiler flags `-Wall -Wextra -Werror` that
enforce the compiler escalate all warnings as errors.

The library provides debug facilities via enabling numerous debug
messages. This messages can be enabled by passing any combination of the
following cmake parameters:

`-DFATAL_DEBUG=1`  
enables error messages and warnings in the library

`-DCOMMON_DEBUG=1`  
enables the most other messages in the library

`-DCONCATENATE_ARRAYS_DEBUG=1`  
enables debug messages while concatenating arrays for creating TT and
input for PBKDF2 function; its purpose is to separate output from
concatenate arrays function from COMMON\_DEBUG messages.

So, if all possible tracing is required, invoke cmake with the following
parameters:

    mkdir Debug
    cd Debug
    cmake --DCMAKE_BUILD_TYPE=Debug -DFATAL_DEBUG=1 -DCOMMON_DEBUG=1 -DCONCATENATE_ARRAYS_DEBUG=1 ..
    cmake --build .

`-DOPENSSL_ROOT_DIR=/path/to/OpenSSL/installation/directory`  
specifies different from system-wide installation path for OpenSSL
Library.

`-DOPENSSL_VERSION=1.1.0`  
specifies exact numeric version of OpenSSL to be used and stops building
in case of version mismatch.

Run examples
============

Example applications are provided after building the project with
\`\`\`cmake --build .\`\`\` in the build directory. To create secret
credentials on the server’s side invoke a server with a password
parameter (-p parameter):

    ./server -p 345542

Now the secret data was stored in files `w0.dat` and `L.dat` in a Base64
format.

To start acepting incoming connections run the server without the
password:

    ./server

The client might be called in the following way, with only server IP
address (-A parameter) and password (-p parameter):

    ./client -A 127.0.0.1  -p 345543

Below are another three example commands that show how to customize
SPAKE2+ key derivation with example applications. Their order and
meaning correspond to the three simple commands above:

    ./server -p '1234567' -s server -c client -a "Some additional data" -G P-384 -H SHA512 -M HMAC -P 12345
    ./server -s server -c client -a "Some additional data" -G P-384 -H SHA512 -M HMAC -P 12345 -d ./
    ./client -A 127.0.0.1 -P 12345 -p '1234567' -s server -c client -a "Some additional data" -G P-384 -H SHA512 -M HMAC -m "Message to be sent" -f ./file_to_be_sent

Usage
=====

`server`
--------

Below is the full list of `server` options

    ./server usage:
      ./server <options>
      a) used only to initialize server with new password and exit:
        -p <password> - password, mandatory
      b) used only to accept connection:
        [-P <server port>] - UDP port number to open, default is 12345
        [-i <interface name>] - name of interface to be used, by default are used all interfaces (Linux only)
        [-d <directory>] - directory to store files and messages, default is /tmp
      c) used for both cases above and with identical set of options from below per "init & accept-connections" pair:
        [-a <additional string>] - default is "Use SPAKE2+ latest version."
        [-s <server id>] - default is "server"
        [-c <client id>] - default is "client"
        [-G <EC group name>] - One of "P-256", "P-384", "P-521", default is P-256
        [-H <hash function name>] - "SHA256" or "SHA512", default is SHA256
        [-M <MAC function name>] - "HMAC" or "CMAC", default is HMAC
        [-n <max number of processed clients>] - maximal number of processed clients,  default is 0 (unlimited)

Option `-p` switches the `server` into password initialization mode for
`w0.dat` and `L.dat` creation. Without this option the `server` starts
accepting connections, if `w0.dat` and `L.dat` are provided and
correspond to the chosen cryptographic parameters.

Option `-d` specifies directory for storing received and decrypted files
and messages under timestamped names `client_file_YYYYMMDD_HHMMSS` and
`client_message_YYYYMMDD_HHMMSS` respectively.

Options `-a`, `-s` and `-d` accept arbitrary strings as parameters,
while each of the options `-G`, `-H` and `-M` accepts only one of the
allowed values.

Option `-P` specifies port used for accepting connections. Option `-i`
specifies interface to be used for listening, if not specified all
interfaces are listened.

`client`
--------

Below is the full list of `client` options

    ./client usage:
      ./client <options>
        -p <password> - Password
        -A <Server address> - IP address to connect to
        [-P <server port>] - UDP port number to conect to, default is 12345
        [-s <server id>] - default is server
        [-c <client id>] - default is client
        [-m <message>]   - message to be sent, default is 'Super secret data from client'
        [-f <path to file>] - file to be sent
        [-a <additional string>] - default is Use SPAKE2+ latest version.
        [-G <EC group name>] - One of P-256, P-384, P-521, default is P-256
        [-H <hash function name>] - SHA256 or SHA512, default is SHA256
        [-M <MAC function name>] - HMAC or CMAC, default is HMAC

Options `-p`, `-P`, `-a`, `-s`, `-c`, `-G`, `-H` and `-M` must coincide
with corresponding `server` invocation and have the same meaning as for
the `server`. Protocol errors occur otherwise.

Option `-A` represents IP address of the `server`.

Option `-m` specifies a text message to be encrypted with the derived
key and sent to the server. Supported length is 1000 symbols including
mandatory terminating zero. If no option is specified, a default message
is encrypted and sent.

Option `-f` specifies a file to be read, encrypted with the derived key
and sent to the server. The file is processed in chunks of no more than
1000 bytes. No file is transmitted if the option is not specified.

Run tests
=========

To run Unity and Vector (64-bit OS only) tests simply start the
`unity_tests` application or `ctest` without parameters.

Run `ctest -T memcheck` to run Valgrind.

Alternatively
`valgrind -v --tool=memcheck --track-origins=yes --leak-check=full --show-leak-kinds=all ./unity_tests`
can be run.

To start stress-test, run `./test_server_client_exhausting.sh` from the
build directory. This script initializes server, runs it ready for 1000
connections under Valgrind and runs 1000 clients for the server. This is
a BASH script and is not included into Valgrind as a whole since BASH
itself has Valgrind defects. However, this script enables running the
server in processing phase under Valgrind and see if there are any
leaks. Moreover the script supports nearly all options of client and
server example applications like in the usage below

    Usage: ./test_server_client_exhausting.sh <options>
        [-h] - print this Usage information
        [-v] - enable Valgrind memcheck for server invocation for multiple client processing
        [-p <password>] - Password
        [-A <Server address>] - IP address to connect to
        [-P <server port>] - UDP port number to conect to, default is 12345
        [-s <server id>] - default is server
        [-c <client id>] - default is client
        [-a <additional string>] - default is Use SPAKE2+ latest version.
        [-G <EC group name>] - One of P-256, P-384, P-521, default is P-256
        [-H <hash function name>] - SHA256 or SHA512, default is SHA256
        [-M <MAC function name>] - HMAC or CMAC, default is HMAC
        [-n <max number of processed clients>] - maximal number of processed clients,  default is 0 (unlimited)
        [-i <interface name>] - name of interface to be used, by default are used all interfaces (Linux only)
        [-d <directory>] - directory to store files and messages, default is /tmp
        [-m <message to server>] - message (default is Client invocation number) to be appended by invocation number

Run Sanitizer
=============

Address Sanitizer works in runtime always if `CMAKE_BUILD_TYPE=asan` is
chosen. Normally Sanitizer produces list of errors after the program
finishes, but all these errors have been fixed and there are no messages
after that. Remember that project built with `CMAKE_BUILD_TYPE=asan`
fails Valgrind tests invoked with the command `ctest -T memcheck`.
