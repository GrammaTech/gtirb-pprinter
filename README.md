Pretty Printer
==============

A pretty printer from the [GTIRB](https://github.com/grammatech/gtirb)
intermediate representation for binary analysis and reverse
engineering to gas-syntax assembly code.

## Building

The pretty-printer uses C++17, and requires a compiler which supports
that standard such as gcc 7, clang 6, or MSVC 2017.

Boost (1.59 or later) and [GTIRB](https://github.com/grammatech/gtirb)
are required.

Once the dependencies are installed, you can configure and builds as follows:

```bash
$ cmake ./ -Bbuild
$ cd build
$ make
```

### CMake Options
You can tell CMake which compiler to use with `-DCMAKE_CXX_COMPILER=<compiler>`.

Normally CMake will find GTIRB automatically, but if it does not you
can pass `-Dgtirb_DIR=<path-to-gtirb-build>`.

