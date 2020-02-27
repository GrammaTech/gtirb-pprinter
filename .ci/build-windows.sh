#!/bin/bash

set -o xtrace
set -o nounset
set -o errexit
set -o pipefail

# Called directly by the windows build jobs in gitlab-ci.yml

BUILD_TYPE=$1

# Install gtirb
mkdir gtirb/build
pushd gtirb/build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G "Ninja" -DBOOST_ROOT=\"C:\\Boost\" -DCMAKE_PREFIX_PATH=\"C:\\Program Files (x86)\\protobuf\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja -j 1"
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja install"
popd

# Build gtirb-pprinter
mkdir build
cd build
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && C:\\PROGRA~1\\CMake\\bin\\cmake.exe -G \"Ninja\" -DBOOST_ROOT=\"C:\\Boost\" -DCMAKE_CXX_FLAGS=\"/DBOOST_ALL_DYN_LINK\" -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=1 -DCAPSTONE=\"C:\\capstone-${BUILD_TYPE}\\lib\\capstone.lib\" -DCAPSTONE_INCLUDE_DIRS=\"C:\\capstone-${BUILD_TYPE}\\include\" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} .."
cmd.exe /C "C:\\VS\\VC\\Auxiliary\\Build\\vcvars64.bat && ninja"
