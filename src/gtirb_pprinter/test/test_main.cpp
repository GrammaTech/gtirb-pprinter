#include <gtest/gtest.h>
#include <gtirb/AuxDataContainer.hpp>
#include <gtirb/AuxDataSchema.hpp>
#include <gtirb_pprinter/AuxDataSchema.hpp>

int main(int argc, char** argv) {
  gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::Libraries>();
  gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::LibraryPaths>();

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
