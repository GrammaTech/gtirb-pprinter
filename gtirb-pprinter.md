% gtirb-pp(1) GTIRB
% GrammaTech Inc.
% September 2018

# NAME

gtirb-pp - GTIRB pretty printer to assembly code

# SYNOPSIS

gtirb-pp [*options*...] [*filename*]

# DESCRIPTION

Print GTIRB to assembly code.  Read a serialized instance of GTIRB
from *filename* (or STDIN if not specified) and pretty print assembler
to STDOUT (or the file specified by the **output** option).

# OPTIONS

**--help**
:   Print help and exit

**-i FILE**, **--ir FILE**
:   GTIRB file to print.

**-o FILE**, **--output=FILE**
:   Write assembly output to FILE.  Default to STDOUT.

**-D**, **--debug**
:   Print debug output to STDERR.

# EXAMPLES

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

# SEE ALSO

`gtirb` (1).
GTIRB is the GrammaTech Intermediate Representation for Binaries.

`ddisasm` (1).
The `ddisasm` disassembler may be used to disassemble a binary
executable to GTIRB.
