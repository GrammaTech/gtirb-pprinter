#pragma once

#include <boost/lexical_cast.hpp>
#include <boost/serialization/string.hpp>
#include <cstdint>
#include <gtirb/EA.hpp>
#include <gtirb/Section.hpp>
#include <string>
#include <vector>

///
///
///
struct DecodedInstruction {
  DecodedInstruction() = default;

  DecodedInstruction(const std::vector<std::string>& x) {
    assert(x.size() == 8);

    this->EA = boost::lexical_cast<uint64_t>(x[0]);
    this->Size = boost::lexical_cast<uint64_t>(x[1]);
    this->Prefix = x[2];
    this->Opcode = x[3];
    this->Op1 = boost::lexical_cast<uint64_t>(x[4]);
    this->Op2 = boost::lexical_cast<uint64_t>(x[5]);
    this->Op3 = boost::lexical_cast<uint64_t>(x[6]);
    this->Op4 = boost::lexical_cast<uint64_t>(x[7]);
  };

  uint64_t getEndAddress() const { return this->EA + this->Size; }

  std::string Prefix;
  std::string Opcode;
  uint64_t EA{0};
  uint64_t Size{0};
  uint64_t Op1{0};
  uint64_t Op2{0};
  uint64_t Op3{0};
  uint64_t Op4{0};
};

///
///
///
struct OpIndirect {
  OpIndirect() = default;

  OpIndirect(const std::vector<std::string>& x) {
    assert(x.size() == 7);

    this->N = boost::lexical_cast<decltype(OpIndirect::N)>(x[0]);
    this->SReg = x[1];
    this->Reg1 = x[2];
    this->Reg2 = x[3];
    this->Multiplier = boost::lexical_cast<decltype(OpIndirect::Multiplier)>(x[4]);
    this->Offset = boost::lexical_cast<decltype(OpIndirect::Offset)>(x[5]);
    this->Size = boost::lexical_cast<decltype(OpIndirect::Size)>(x[6]);
  };

  uint64_t N{0};
  std::string SReg;
  std::string Reg1;
  std::string Reg2;
  int64_t Multiplier{0};
  int64_t Offset{0};
  uint64_t Size{0};
};

///
///
///
struct OpRegdirect {
  OpRegdirect() = default;

  OpRegdirect(const std::vector<std::string>& x) {
    assert(x.size() == 2);

    this->N = boost::lexical_cast<uint64_t>(x[0]);
    this->Register = x[1];
  };

  uint64_t N{0};
  std::string Register;
};

///
///
///
struct OpImmediate {
  OpImmediate() = default;

  OpImmediate(const std::vector<std::string>& x) {
    assert(x.size() == 2);

    this->N = boost::lexical_cast<uint64_t>(x[0]);
    this->Immediate = boost::lexical_cast<int64_t>(x[1]);
  };

  uint64_t N{0};
  int64_t Immediate{0};
};
