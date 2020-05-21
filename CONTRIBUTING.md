Contributing
============


## Code of Conduct

Please read the [GTIRB-pprinter Code of Conduct](CODE_OF_CONDUCT.md).


## Code

See the Code Requirements in
[gtirb/CONTRIBUTING](https://github.com/GrammaTech/gtirb/blob/master/CONTRIBUTING.md#code-requirements).


## Licensing

We ask that all contributors complete our Contributor License
Agreement (CLA), which can be found at
[GrammaTech-CLA-gtirb-pprinter.pdf](./GrammaTech-CLA-gtirb-pprinter.pdfGTIRB.pdf),
and email the completed form to `CLA@GrammaTech.com`.  Under this
agreement contributors retain the copyright to their work but grants
GrammaTech unlimited license to the work.


## Testing Development

- All code you care about should be tested.
- Any code you don't care about should be removed.
- Code testing is done via Google Test.
- Test names are prefixed with thet type of test they are (`Unit_`,
  `System_`, `Integration_`).
- No unit test should take more than 0.5 seconds.
- Do not use 'using namespace' inside test cases.  Fully qualify
  everything.


## Documentation

- Documentation for the gtirb-pprinter command is provided in
  man-page format in the `gtirb-pprinter.md` file in the root of this
  directory.

- Full gtirb-pprinter documentation consists of complete documentation
  for all components of the gtirb-pprinter API, along with examples and other
  usage information.


### Building Documentation

You will need `cmake` and `Doxygen`.

1. Create and change to a temporary build directory. We will refer to
   this directory as `build`.

   ```sh
   mkdir build
   cd build
   ```

2. Build the documentation.

   ```sh
   cmake ../path/to/gtirb-pprinter/doc/doxy/
   cmake --build . --target doc
   ```

3. Open the documentation home page `build/html/index.html`
   in your browser.


### Contributing Markdown Documentation

To add a new markdown document to the documentation:

1. Create the new document as a child of /doc.
   - File extension is `.md`.
   - Use github markdown syntax.
   - Wrap your markdown documents at 80 columns.

2. Edit `/doc/doxy/Doxyfile.in` to add the basename of your new
   markdown document to the `INPUT` rule setting. Note that the
   ordering of file names here corresponds to table of contents
   ordering.

3. Edit `/doc/doxy/CMakeLists.txt` to add your new markdown document
   to `MDFILES_IN`. Ordering is not important.

4. [Build the documentation](#building-documentation) and check that
   your new page is present and rendered correctly.
   - If it is not rendered correctly, you may need to add a new
     preprocessing step to `doc/doxy/preprocmd.py` to rewrite the
     corresponding github-style markdown into something Doxygen
     can handle correctly.
