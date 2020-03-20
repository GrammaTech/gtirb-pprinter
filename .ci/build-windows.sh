#!/bin/bash

set -o xtrace
set -o nounset
set -o errexit
set -o pipefail

# Called directly by the windows build jobs in gitlab-ci.yml

BUILD_TYPE=$1

# Install gtirb
GTIRB_BRANCH=$(grep -Eo "check_gtirb_branch\([^)]+" CMakeLists.txt | sed 's/check_gtirb_branch(//')
curl -L https://git.grammatech.com/rewriting/gtirb/-/jobs/artifacts/${GTIRB_BRANCH}/download?job=build-windows-msvc-${BUILD_TYPE,,} --output "gtirb-artifacts.zip"
unzip gtirb-artifacts.zip
tar xzf GTIRB-*-win64.tar.gz

# Build gtirb-pprinter
GTIRB_DIR=$(cygpath -m $(realpath $(find ./ -type d -name GTIRB-*-win64)/lib/gtirb))
mkdir build
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DBOOST_ROOT=\"C:\\Boost\" -DCMAKE_CXX_FLAGS=\"/DBOOST_ALL_DYN_LINK\" -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=1 -DCAPSTONE=\"C:\\capstone-${BUILD_TYPE}\\lib\\capstone.lib\" -DCAPSTONE_INCLUDE_DIRS=\"C:\\capstone-${BUILD_TYPE}\\include\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -Dgtirb_DIR=$GTIRB_DIR .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
