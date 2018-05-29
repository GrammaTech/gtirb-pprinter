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
struct PLTReference
{
    PLTReference() = default;

    PLTReference(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Name = x[1];
    };

    std::string Name;
    uint64_t EA{0};
};

///
///
///
struct DecodedInstruction
{
    DecodedInstruction() = default;

    DecodedInstruction(const std::vector<std::string>& x)
    {
        assert(x.size() == 7);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Size = boost::lexical_cast<uint64_t>(x[1]);
        this->Prefix = x[2];
        this->Opcode = x[3];
        this->Op1 = boost::lexical_cast<uint64_t>(x[4]);
        this->Op2 = boost::lexical_cast<uint64_t>(x[5]);
        this->Op3 = boost::lexical_cast<uint64_t>(x[6]);
    };

    uint64_t getEndAddress() const
    {
        return this->EA + this->Size;
    }

    std::string Prefix;
    std::string Opcode;
    uint64_t EA{0};
    uint64_t Size{0};
    uint64_t Op1{0};
    uint64_t Op2{0};
    uint64_t Op3{0};
};

///
///
///
struct OpIndirect
{
    OpIndirect() = default;

    OpIndirect(const std::vector<std::string>& x)
    {
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
struct CodeInBlock
{
    CodeInBlock() = default;

    CodeInBlock(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<decltype(CodeInBlock::EA)>(x[0]);
        this->BlockAddress = boost::lexical_cast<decltype(CodeInBlock::BlockAddress)>(x[1]);
    };

    uint64_t EA{0};
    uint64_t BlockAddress{0};
};

///
///
///
struct OpRegdirect
{
    OpRegdirect() = default;

    OpRegdirect(const std::vector<std::string>& x)
    {
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
struct OpImmediate
{
    OpImmediate() = default;

    OpImmediate(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->N = boost::lexical_cast<uint64_t>(x[0]);
        this->Immediate = boost::lexical_cast<int64_t>(x[1]);
    };

    uint64_t N{0};
    int64_t Immediate{0};
};

///
///
///
struct DirectCall
{
    DirectCall() = default;

    DirectCall(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Destination = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t EA{0};
    uint64_t Destination{0};
};

///
///
///
struct MovedLabel
{
    MovedLabel() = default;

    MovedLabel(const std::vector<std::string>& x)
    {
        assert(x.size() == 4);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->N = boost::lexical_cast<uint64_t>(x[1]);
        this->Offset1 = boost::lexical_cast<int64_t>(x[2]);
        this->Offset2 = boost::lexical_cast<int64_t>(x[3]);
    };

    uint64_t EA{0};
    uint64_t N{0};
    int64_t Offset1{0};
    int64_t Offset2{0};
};

///
///
///
struct SymbolicOperand
{
    SymbolicOperand() = default;

    SymbolicOperand(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->OpNum = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t EA{0};
    uint64_t OpNum{0};
};

///
///
///
struct SymbolicData
{
    SymbolicData() = default;

    SymbolicData(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->GroupContent = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t EA{0};
    uint64_t GroupContent{0};
};

///
///
///
struct SymbolMinusSymbol
{
    SymbolMinusSymbol() = default;

    SymbolMinusSymbol(const std::vector<std::string>& x)
    {
        assert(x.size() == 3);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Symbol1 = boost::lexical_cast<uint64_t>(x[1]);
        this->Symbol2 = boost::lexical_cast<uint64_t>(x[2]);
    };

    uint64_t EA{0};
    uint64_t Symbol1{0};
    uint64_t Symbol2{0};
};

///
///
///
struct MovedDataLabel
{
    MovedDataLabel() = default;

    MovedDataLabel(const std::vector<std::string>& x)
    {
        assert(x.size() == 3);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Old = boost::lexical_cast<uint64_t>(x[1]);
        this->New = boost::lexical_cast<uint64_t>(x[2]);
    };

    uint64_t EA{0};
    uint64_t Old{0};
    uint64_t New{0};
};

///
/// "String" is a bad name for this data type.
///
struct String
{
    String() = default;

    String(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->End = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t size() const
    {
        return this->End - this->EA;
    }

    uint64_t EA{0};
    uint64_t End{0};
};
