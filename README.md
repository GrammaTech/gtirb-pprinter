GTIRB Pretty Printer
====================

A pretty printer from the [GTIRB](https://github.com/grammatech/gtirb)
intermediate representation for binary analysis and reverse
engineering to gas-syntax assembly code.

## Building

The pretty-printer uses C++17, and requires a compiler which supports
that standard such as gcc 7, clang 6, or MSVC 2017.

Boost (1.59 or later) and [GTIRB](https://github.com/grammatech/gtirb)
are required.

Use the following options to configure cmake:
- You can tell CMake which compiler to use with
  `-DCMAKE_CXX_COMPILER=<compiler>`.
- Normally CMake will find GTIRB automatically, but if it does not you
  can pass `-Dgtirb_DIR=<path-to-gtirb-build>`.

Once the dependencies are installed, you can configure and builds as follows:

```bash
$ cmake ./ -Bbuild
$ cd build
$ make
```

## Usage

Pretty print the GTIRB for a simple hello world executable to an
assembly file named `hello.S`, assemble this file with the GNU
assembler to an object file named `hello.o`, and link this object file
into an executable.

```
$ gtirb-pp hello.gtirb -o hello.S
$ as hello.S -o hello.o
$ ld hello.o -o hello
$ ./hello
Hello, world!
```
