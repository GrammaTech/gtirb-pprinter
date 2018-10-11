Contributing
============

Code
----

- All code shall be formatted with clang-format.  A '.clang-format' is
  provided in the root directory for the project.

Testing Development
-------------------

- All code you care about should be tested.
- Any code you don't care about should be removed.
- Code testing is done via Google Test.
- Test names are prefixed with thet type of test they are (`Unit_`,
  `System_`, `Integration_`).
- No unit test should take more than 0.5 seconds.
- Do not use 'using namespace' inside test cases.  Fully qualify
  everything.

Documentation
-------------
- Documentation is provided in man-page format in the
  `gtirb-pprinter.md` file in the root of this directory.
