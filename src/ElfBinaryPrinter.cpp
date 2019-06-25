//===- ElfBinaryPrinter.cpp ----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "ElfBinaryPrinter.h"

#include <vector>
#include <string>
#include <sstream>
#include <regex>
#include <boost/process.hpp>
#include <boost/process/args.hpp>
#include <experimental/filesystem>

namespace bp = boost::process;
namespace fs = std::experimental::filesystem;

namespace gtirb_bprint {
  
int ElfBinaryPrinter::link(std::string output_filename,
			   const std::vector<std::string>& library_paths,
			   const gtirb_pprint::PrettyPrinter& pp,
			   gtirb::Context& ctx, gtirb::IR& ir) const {
  // Get a temp file to write assembly to
  std::vector<std::string> args;
  char asmPath[] = "/tmp/fileXXXXXX.S";

  std::set<std::string> lib_paths, lib_flags;

  close(mkstemps(asmPath, 2)); // Create and open temp file

  // Write the assembly to a temp file
  std::ofstream ofs(asmPath);

  if (ofs) {
    pp.print(ofs, ctx, ir);
    ofs.close();
  } else {
    std::cout << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  // Start constructing the compile command, of the form
  // gcc -o <output_filename> fileAXADA.S
  //  /path/to/Bar/libBar.so /path/to/FOO/libFOO.so
  args.insert(args.end(), { "-v", "-o", output_filename, std::string(asmPath)});
  
  // Get a list of dependent library paths to link with
  std::regex r("^(.*)\\.so.*");
  if (const auto* libraries =
      ir.modules().begin()->getAuxData<std::vector<std::string>>(
              "libraries")) {
    for (const auto& library : *libraries) {
      fs::path given_library_path = fs::path(library);
      const std::string& library_name = given_library_path.filename().string();
      std::cout << given_library_path << std::endl;
      for(const auto& library_path : library_paths) {
	for(auto& p: fs::directory_iterator(library_path)) {
	  if(fs::is_regular_file(p) && p.path().filename().string() == library_name) {
	      given_library_path = p.path();
	      break;
	    
	  }
	}
      }

      if(fs::is_regular_file(given_library_path) || fs::is_symlink(given_library_path))
	args.push_back(given_library_path.string());
    }
  }

  std::vector<std::string> lines;

  bp::ipstream is; // reading pipe-stream
  bp::child c(bp::search_path("gcc"), bp::args(args), bp::std_err > is);

  std::string line;

  while (c.running() && std::getline(is, line) && !line.empty())
    lines.push_back(line);

  c.wait();
  int status = c.exit_code();

  unlink(asmPath);
  
  if (status < 0) {
    perror(NULL);
    std::cout << "The gcc command failed with return code : " << status
              << std::endl;
    for (const auto& line : lines)
      std::cout << line << std::endl;
    return status;
  }

  return 0;
}
  
} // namespace gtirb_bprint
