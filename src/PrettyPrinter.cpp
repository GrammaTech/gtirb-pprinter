#include "PrettyPrinter.h"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <gsl/gsl>
#include <gtirb/ImageByteMap.hpp>
#include <gtirb/Instruction.hpp>
#include <gtirb/Module.hpp>
#include <gtirb/Symbol.hpp>
#include <gtirb/SymbolicOperand.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include "DisasmData.h"

///
/// Pring a comment that automatically scopes.
///
class BlockAreaComment
{
public:
    BlockAreaComment(std::stringstream& ss, std::string m = std::string{},
                     std::function<void()> f = []() {})
        : ofs{ss}, message{std::move(m)}, func{std::move(f)}
    {
        ofs << std::endl;

        if(message.empty() == false)
        {
            ofs << "# BEGIN - " << this->message << std::endl;
        }

        func();
    }

    ~BlockAreaComment()
    {
        func();

        if(message.empty() == false)
        {
            ofs << "# END   - " << this->message << std::endl;
        }

        ofs << std::endl;
    }

    std::stringstream& ofs;
    const std::string message;
    std::function<void()> func;
};

std::string str_tolower(std::string s)
{
    std::transform(
        s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); } // correct
        );
    return s;
}

PrettyPrinter::PrettyPrinter()
{
}

void PrettyPrinter::setDebug(bool x)
{
    this->debug = x;
}

bool PrettyPrinter::getDebug() const
{
    return this->debug;
}

std::string PrettyPrinter::prettyPrint(DisasmData* x)
{
    this->disasm = x;
    this->ofs.clear();

    this->printHeader();

    // Note: making a copy due to AdjustPadding below.
    auto blocks = *this->disasm->ir.getMainModule().getBlocks();

    if(this->getDebug() == true)
    {
        DisasmData::AdjustPadding(blocks);
    }

    for(const auto& b : blocks)
    {
        this->printBlock(b);
    }

    this->printDataGroups();

    this->printBSS();

    return this->ofs.str();
}

void PrettyPrinter::printHeader()
{
    this->printBar();
    this->ofs << ".intel_syntax noprefix" << std::endl;
    this->printBar();
    this->ofs << "" << std::endl;

    for(int i = 0; i < 8; i++)
    {
        this->ofs << PrettyPrinter::StrNOP << std::endl;
    }
}

void PrettyPrinter::printBlock(const gtirb::Block& x)
{
    if(this->skipEA(x.getStartingAddress()) == false)
    {
        if(x.getInstructions().empty() == false)
        {
            this->condPrintSectionHeader(x);
            this->printFunctionHeader(x.getStartingAddress());
            this->printLabel(x.getStartingAddress());
            this->ofs << std::endl;

            for(const auto& inst : x.getInstructions())
            {
                this->printInstruction(inst);
            }
        }
        else
        {
            const auto nopCount = x.getEndingAddress() - x.getStartingAddress();
            this->ofs << std::endl;

            const auto bac = BlockAreaComment(this->ofs, "No instruciton padding.");

            // Fill in the correct number of nops.
            for(uint64_t i = 0; i < nopCount; ++i)
            {
                this->printInstructionNop();
            }
        }
    }
}

void PrettyPrinter::condPrintSectionHeader(const gtirb::Block& x)
{
    const auto name = this->disasm->getSectionName(gtirb::EA{x.getStartingAddress()});

    if(!name.empty())
    {
        this->printSectionHeader(name);
        return;
    }
}

void PrettyPrinter::printSectionHeader(const std::string& x, uint64_t alignment)
{
    ofs << std::endl;
    this->printBar();

    if(x == PrettyPrinter::StrSectionText)
    {
        ofs << PrettyPrinter::StrSectionText << std::endl;
    }
    else if(x == PrettyPrinter::StrSectionBSS)
    {
        ofs << PrettyPrinter::StrSectionBSS << std::endl;
        this->ofs << ".align " << alignment << std::endl;
    }
    else
    {
        this->ofs << PrettyPrinter::StrSection << " " << x << std::endl;

        if(alignment != 0)
        {
            this->ofs << ".align " << alignment << std::endl;
        }
    }

    this->printBar();
    ofs << std::endl;
}

void PrettyPrinter::printBar(bool heavy)
{
    if(heavy == true)
    {
        this->ofs << "#===================================" << std::endl;
    }
    else
    {
        this->ofs << "#-----------------------------------" << std::endl;
    }
}

void PrettyPrinter::printFunctionHeader(uint64_t ea)
{
    const auto name = this->disasm->getFunctionName(gtirb::EA{ea});

    if(name.empty() == false)
    {
        const auto bac =
            BlockAreaComment(this->ofs, "Function Header", [this]() { this->printBar(false); });

        // enforce maximum alignment
        if(ea % 8 == 0)
        {
            this->ofs << ".align 8" << std::endl;
        }
        else if(ea % 2 == 0)
        {
            this->ofs << ".align 2" << std::endl;
        }

        this->ofs << PrettyPrinter::StrSectionGlobal << " " << name << std::endl;
        this->ofs << PrettyPrinter::StrSectionType << " " << name << ", @function" << std::endl;
        this->ofs << name << ":" << std::endl;
    }
}

void PrettyPrinter::printLabel(uint64_t ea)
{
    this->condPrintGlobalSymbol(ea);
    this->ofs << ".L_" << std::hex << ea << ":" << std::dec;
}

void PrettyPrinter::condPrintGlobalSymbol(uint64_t ea)
{
    auto name = this->disasm->getGlobalSymbolName(ea);

    if(name.empty() == false)
    {
        this->ofs << name << ":" << std::endl;
    }
}

void PrettyPrinter::printInstruction(const gtirb::Instruction& instruction)
{
    // TODO // Maybe print random nop's.
    auto ea = instruction.getEA();

    this->printEA(ea);
    auto inst = this->disasm->getDecodedInstruction(ea);
    auto prefix = inst->Prefix;
    auto opcode = str_tolower(inst->Opcode);
    uint64_t operands[4] = {inst->Op1, inst->Op2, inst->Op3, inst->Op4};

    ////////////////////////////////////////////////////////////////////
    // special cases

    if(opcode == std::string{"nop"})
    {
        for(uint64_t i = 0; i < inst->Size; ++i)
            this->ofs << " " << opcode << std::endl;
        return;
    }

    // MOVS and CMPS have the operand implicit but size suffix
    if((boost::algorithm::ends_with(opcode, std::string{"movs"})
        || boost::algorithm::ends_with(opcode, std::string{"cmps"}))
       && operands[1] == 0 && operands[2] == 0)
    {
        auto opInd = this->disasm->getOpIndirect(operands[0]);

        if(opInd != nullptr)
        {
            // do not print the first operand
            operands[0] = 0;
            opcode = opcode + disasm->GetSizeSuffix(*opInd);
        }
    }

    // FDIV_TO, FMUL_TO, FSUBR_TO, etc.
    if(boost::algorithm::ends_with(opcode, std::string{"_to"}))
    {
        opcode = boost::replace_all_copy(opcode, "_to", "");
        operands[1] = operands[0];
        operands[0] = disasm->getOpRegdirectCode("ST");
    }
    if(boost::algorithm::starts_with(opcode, std::string{"fcmov"}))
    {
        operands[1] = operands[0];
        operands[0] = disasm->getOpRegdirectCode("ST");
    }
    // for 'loop' with rcx, the operand is implicit
    if(boost::algorithm::starts_with(opcode, std::string{"loop"}))
    {
        auto reg = disasm->getOpRegdirect(operands[0]);
        if(reg != nullptr && reg->Register == std::string{"RCX"})
        {
            operands[0] = 0;
        }
    }
    // print a new line if there is a lock prefix
    if(prefix == std::string{"lock"})
    {
        prefix = "lock\n";
    }
    //////////////////////////////////////////////////////////////////////
    opcode = DisasmData::AdaptOpcode(opcode);
    this->ofs << " " << prefix << " " << opcode << " ";
    this->printOperandList(opcode, instruction, operands);

    /// TAKE THIS OUT ///
    this->ofs << std::endl;
}

void PrettyPrinter::printInstructionNop()
{
    this->ofs << PrettyPrinter::StrNOP << std::endl;
}

void PrettyPrinter::printEA(uint64_t ea)
{
    this->ofs << "          ";

    if(this->getDebug() == true)
    {
        this->ofs << std::hex << ea << ": " << std::dec;
    }
}

template <typename T>
static const T* get(const gtirb::SymbolicOperand& symbolic)
{
    try
    {
        return &boost::get<T>(symbolic);
    }
    catch(boost::bad_get)
    {
        return nullptr;
    }
}

void PrettyPrinter::printOperandList(const std::string& opcode,
                                     const gtirb::Instruction& instruction,
                                     const uint64_t* const operands)
{
    std::string str_operands[4];
    auto ea = instruction.getEA();

    const auto& symbolic = this->disasm->ir.getMainModule().getSymbolicOperands();
    auto findSymbolic = [symbolic, ea](int index) {
        // FIXME: we're faking the operand offset here, assuming it's equal
        // to index. This works as long as the disassembler does the same
        // thing, but it isn't right.
        auto found = symbolic.find(gtirb::EA(ea.get() + index));

        if(found != symbolic.end())
        {
            return &found->second;
        }
        else
        {
            return static_cast<const gtirb::SymbolicOperand*>(nullptr);
        }
    };

    str_operands[0] = this->buildOperand(opcode, findSymbolic(1), operands[0], ea, 1);
    str_operands[1] = this->buildOperand(opcode, findSymbolic(2), operands[1], ea, 2);
    str_operands[2] = this->buildOperand(opcode, findSymbolic(3), operands[2], ea, 3);
    str_operands[3] = this->buildOperand(opcode, findSymbolic(4), operands[3], ea, 4);

    uint dest_op_idx = 0;
    for(int i = 3; i >= 0; --i)
    {
        if(str_operands[i].empty() == false)
        {
            dest_op_idx = i;
            break;
        }
    }
    // print destination operand
    if(str_operands[dest_op_idx].empty() == false)
        this->ofs << str_operands[dest_op_idx];
    // print source operands
    for(uint i = 0; i < dest_op_idx; ++i)
        if(str_operands[i].empty() == false)
            this->ofs << "," << str_operands[i];
}

std::string PrettyPrinter::buildOperand(const std::string& opcode,
                                        const gtirb::SymbolicOperand* symbolic, uint64_t operand,
                                        uint64_t ea, uint64_t index)
{
    auto opReg = this->disasm->getOpRegdirect(operand);
    if(opReg != nullptr)
    {
        return this->buildOpRegdirect(opReg, ea, index);
    }

    auto opImm = this->disasm->getOpImmediate(operand);
    if(opImm != nullptr)
    {
        return this->buildOpImmediate(opcode, symbolic, opImm, ea, index);
    }

    auto opInd = this->disasm->getOpIndirect(operand);
    if(opInd != nullptr)
    {
        return this->buildOpIndirect(symbolic, opInd, ea, index);
    }

    return std::string{};
}

std::string PrettyPrinter::buildOpRegdirect(const OpRegdirect* const op, uint64_t /*ea*/,
                                            uint64_t /*index*/)
{
    return DisasmData::AdaptRegister(op->Register);
}

std::string PrettyPrinter::buildOpImmediate(const std::string& opcode,
                                            const gtirb::SymbolicOperand* symbolic,
                                            const OpImmediate* const op, uint64_t ea,
                                            uint64_t index)
{
    if(symbolic)
    {
        const auto& pltReferences = boost::get<gtirb::Table::InnerMapType>(
            this->disasm->ir.getTable("DisasmData")->contents["pltCodeReferences"]);
        const auto p = pltReferences.find(gtirb::EA(ea));
        if(p != pltReferences.end())
        {
            return PrettyPrinter::StrOffset + " " + boost::get<std::string>(p->second);
        }

        try
        {
            const gtirb::SymAddrConst s = boost::get<gtirb::SymAddrConst>(*symbolic);
            if(opcode == "call")
            {
                assert(s.displacement == 0);
                if(this->skipEA(op->Immediate))
                {
                    return std::to_string(op->Immediate);
                }
                else
                {
                    return s.symbol->getName();
                }
            }

            if(s.displacement == 0)
            {
                if(index == 1)
                {
                    auto ref = this->disasm->getGlobalSymbolReference(op->Immediate);
                    if(ref.empty() == false)
                    {
                        return PrettyPrinter::StrOffset + " " + ref;
                    }
                    else
                    {
                        return PrettyPrinter::StrOffset + " " + GetSymbolToPrint(op->Immediate);
                    }
                }

                return GetSymbolToPrint(op->Immediate);
            }
            else
            {
                std::stringstream ss;
                ss << PrettyPrinter::StrOffset << " " << s.symbol->getName() << "+"
                   << s.displacement;
                return ss.str();
            }
        }
        catch(boost::bad_get&)
        {
        }
    }

    return std::to_string(op->Immediate);
}

std::string PrettyPrinter::buildOpIndirect(const gtirb::SymbolicOperand* symbolic,
                                           const OpIndirect* const op, uint64_t ea, uint64_t index)
{
    const auto sizeName = DisasmData::GetSizeName(op->Size);

    auto putSegmentRegister = [op](const std::string& term) {
        if(PrettyPrinter::GetIsNullReg(op->SReg) == false)
        {
            return op->SReg + ":[" + term + "]";
        }

        return "[" + term + "]";
    };

    // Case 1
    if(op->Offset == 0)
    {
        if(PrettyPrinter::GetIsNullReg(op->SReg) && PrettyPrinter::GetIsNullReg(op->Reg1)
           && PrettyPrinter::GetIsNullReg(op->Reg2))
        {
            return sizeName + std::string{" [0]"};
        }
    }

    // Case 2
    if(op->Reg1 == std::string{"RIP"} && op->Multiplier == 1)
    {
        if(PrettyPrinter::GetIsNullReg(op->SReg) && PrettyPrinter::GetIsNullReg(op->Reg2))
        {
            try
            {
                boost::get<gtirb::SymAddrConst>(*symbolic);
                auto instruction = this->disasm->getDecodedInstruction(ea);
                auto address = ea + op->Offset + instruction->Size;
                auto symbol = this->disasm->getGlobalSymbolReference(address);

                if(!symbol.empty())
                {
                    return sizeName + " " + symbol + PrettyPrinter::StrRIP;
                }
                else
                {
                    auto symbolToPrint = GetSymbolToPrint(address);
                    return sizeName + " " + symbolToPrint + PrettyPrinter::StrRIP;
                }
            }
            catch(boost::bad_get&)
            {
            }
        }
    }

    // Case 3
    if(PrettyPrinter::GetIsNullReg(op->Reg1) == false
       && PrettyPrinter::GetIsNullReg(op->Reg2) == true && op->Offset == 0)
    {
        auto adapted = DisasmData::AdaptRegister(op->Reg1);
        return sizeName + " " + putSegmentRegister(adapted);
    }

    // Case 4
    if(PrettyPrinter::GetIsNullReg(op->Reg1) == true
       && PrettyPrinter::GetIsNullReg(op->Reg2) == true)
    {
        auto symbol = this->disasm->getGlobalSymbolReference(op->Offset);
        if(symbol.empty() == false)
        {
            return sizeName + putSegmentRegister(symbol);
        }

        auto offsetAndSign = this->getOffsetAndSign(symbolic, op->Offset, ea, index);
        std::string term = std::string{offsetAndSign.second} + offsetAndSign.first;
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 5
    if(PrettyPrinter::GetIsNullReg(op->Reg2) == true)
    {
        auto adapted = DisasmData::AdaptRegister(op->Reg1);
        auto offsetAndSign = this->getOffsetAndSign(symbolic, op->Offset, ea, index);
        std::string term = adapted + std::string{offsetAndSign.second} + offsetAndSign.first;
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 6
    if(PrettyPrinter::GetIsNullReg(op->Reg1) == true)
    {
        auto adapted = DisasmData::AdaptRegister(op->Reg2);
        auto offsetAndSign = this->getOffsetAndSign(symbolic, op->Offset, ea, index);
        std::string term = adapted + "*" + std::to_string(op->Multiplier)
                           + std::string{offsetAndSign.second} + offsetAndSign.first;
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 7
    if(op->Offset == 0)
    {
        auto adapted1 = DisasmData::AdaptRegister(op->Reg1);
        auto adapted2 = DisasmData::AdaptRegister(op->Reg2);
        std::string term = adapted1 + "+" + adapted2 + "*" + std::to_string(op->Multiplier);
        return sizeName + " " + putSegmentRegister(term);
    }

    // Case 8
    auto adapted1 = DisasmData::AdaptRegister(op->Reg1);
    auto adapted2 = DisasmData::AdaptRegister(op->Reg2);
    auto offsetAndSign = this->getOffsetAndSign(symbolic, op->Offset, ea, index);
    std::string term = adapted1 + "+" + adapted2 + "*" + std::to_string(op->Multiplier)
                       + std::string{offsetAndSign.second} + offsetAndSign.first;
    return sizeName + " " + putSegmentRegister(term);
}

void PrettyPrinter::printDataGroups()
{
    auto* dataTable = this->disasm->ir.getTable("DisasmData");

    const auto& pltReferences =
        boost::get<gtirb::Table::InnerMapType>(dataTable->contents["pltDataReferences"]);
    const auto& stringEAs = boost::get<std::vector<gtirb::EA>>(dataTable->contents["stringEAs"]);
    const auto& symbolic = this->disasm->ir.getMainModule().getSymbolicOperands();
    const auto& symbolSet = this->disasm->ir.getMainModule().getSymbolSet();

    for(gtirb::Table::InnerMapType& ds : this->disasm->getDataSections())
    {
        auto sectionPtr = this->disasm->getSection(boost::get<std::string>(ds["name"]));

        std::vector<const gtirb::Data*> dataGroups;
        const auto& moduleData = this->disasm->ir.getMainModule().getData();
        for(auto i : boost::get<std::vector<uint64_t>>(ds["dataGroups"]))
        {
            dataGroups.push_back(&moduleData[i]);
        }

        if(isSectionSkipped(sectionPtr->name) && !this->debug)
            continue;

        // Print section header...
        this->printSectionHeader(sectionPtr->name, boost::get<uint64_t>(ds["alignment"]));

        // Print data for this section...
        for(auto dg = std::begin(dataGroups); dg != std::end(dataGroups); ++dg)
        {
            bool exclude = false;
            auto data = dynamic_cast<const gtirb::Data*>(*dg);
            auto foundSymbol = gtirb::findSymbols(symbolSet, data->getEA());

            if(sectionPtr->name == ".init_array" || sectionPtr->name == ".fini_array")
            {
                auto dgNext = dg;
                dgNext++;

                if(dgNext != std::end(dataGroups))
                {
                    exclude = this->getIsPointerToExcludedCode(foundSymbol.empty(), symbolic, *dg,
                                                               *dgNext);
                }
                else
                {
                    exclude = this->getIsPointerToExcludedCode(foundSymbol.empty(), symbolic, *dg,
                                                               nullptr);
                }
            }

            if(exclude == false)
            {
                auto printTab = [this, &data]() {
                    this->ofs << PrettyPrinter::StrTab;

                    if(this->debug == true)
                    {
                        this->ofs << std::hex << data->getEA() << std::dec << ":";
                    }
                };

                // Print all symbols
                for(const auto s : foundSymbol)
                {
                    this->ofs << s->getName() << ":\n";
                }
                // Also print local label just in case. There is still some code that makes up
                // ".L_<ea>" references without having a corresponding symbol.
                if(!foundSymbol.empty())
                {
                    this->ofs << ".L_" << std::hex << data->getEA() << ":\n" << std::dec;
                }

                const auto& foundSymbolic = symbolic.find(data->getEA());
                const auto p = pltReferences.find(data->getEA());
                if(p != pltReferences.end())
                {
                    printTab();
                    this->printEA(boost::get<gtirb::EA>(p->first));
                    this->ofs << ".quad " << boost::get<std::string>(p->second);
                    this->ofs << std::endl;
                }
                else if(std::find(stringEAs.begin(), stringEAs.end(), data->getEA())
                        != stringEAs.end())
                {
                    printTab();
                    this->printString(*data);
                    this->ofs << std::endl;
                }
                else if(foundSymbolic != symbolic.end())
                {
                    try
                    {
                        auto s = boost::get<gtirb::SymAddrConst>(foundSymbolic->second);
                        printTab();
                        this->ofs << ".quad " << s.symbol->getName();
                        this->ofs << std::endl;
                    }
                    catch(boost::bad_get)
                    {
                        try
                        {
                            auto s = boost::get<gtirb::SymAddrAddr>(foundSymbolic->second);
                            printTab();
                            this->printEA(data->getEA());
                            this->ofs << ".long " << s.symbol1->getName() << "-"
                                      << s.symbol2->getName();
                            this->ofs << std::endl;
                        }
                        catch(boost::bad_get)
                        {
                        }
                    }
                }
                else
                {
                    for(auto byte : data->getBytes(this->disasm->ir.getMainModule()))
                    {
                        printTab();
                        this->ofs << ".byte 0x" << std::hex << static_cast<uint32_t>(byte)
                                  << std::dec;
                        this->ofs << std::endl;
                    }
                }
            }
        }

        // End label
        const auto endAddress = sectionPtr->addressLimit();
        std::string next_section = this->disasm->getSectionName(endAddress);
        if(next_section.empty() == true
           || (next_section != StrSectionBSS && getDataSectionDescriptor(next_section) == nullptr))
        {
            // This is no the start of a new section, so print the label.
            this->printLabel(endAddress);
            this->ofs << std::endl;
        }
    }
}

void PrettyPrinter::printString(const gtirb::Data& x)
{
    auto cleanByte = [](uint8_t b) {
        std::string cleaned;
        cleaned += b;
        cleaned = boost::replace_all_copy(cleaned, "\\", "\\\\");
        cleaned = boost::replace_all_copy(cleaned, "\"", "\\\"");
        cleaned = boost::replace_all_copy(cleaned, "\n", "\\n");
        cleaned = boost::replace_all_copy(cleaned, "\t", "\\t");
        cleaned = boost::replace_all_copy(cleaned, "\v", "\\v");
        cleaned = boost::replace_all_copy(cleaned, "\b", "\\b");
        cleaned = boost::replace_all_copy(cleaned, "\r", "\\r");
        cleaned = boost::replace_all_copy(cleaned, "\a", "\\a");
        cleaned = boost::replace_all_copy(cleaned, "\'", "\\'");

        return cleaned;
    };

    this->ofs << ".string \"";

    for(auto& b : x.getBytes(this->disasm->ir.getMainModule()))
    {
        if(b != 0)
        {
            this->ofs << cleanByte(b);
        }
    }

    this->ofs << "\"";
}

void PrettyPrinter::printBSS()
{
    auto bssSection = this->disasm->getSection(PrettyPrinter::StrSectionBSS);

    if(bssSection != nullptr)
    {
        this->printSectionHeader(PrettyPrinter::StrSectionBSS, 16);
        auto bssData = this->disasm->getBSSData();

        // Special case.
        if(bssData->empty() == false && bssData->at(0) != bssSection->startingAddress)
        {
            const auto current = bssSection->startingAddress;
            const auto next = bssData->at(0);
            const auto delta = next - current;

            this->printLabel(current);
            this->ofs << " .zero " << delta;
            this->ofs << std::endl;
        }

        for(size_t i = 0; i < bssData->size(); ++i)
        {
            const auto current = bssData->at(i);
            this->printLabel(current);

            if(i != bssData->size() - 1)
            {
                const auto next = bssData->at(i + 1);
                const auto delta = next - current;

                this->ofs << " .zero " << delta;
            }
            else
            {
                // Print to the end of the section.
                const auto next = bssSection->addressLimit().get();
                const auto delta = next - current;
                if(delta > 0)
                    this->ofs << " .zero " << delta;
            }

            this->ofs << std::endl;
        }

        this->printLabel(bssSection->addressLimit());
        this->ofs << std::endl;
    }
}

bool PrettyPrinter::skipEA(const uint64_t x) const
{
    if(this->debug == false)
    {
        for(const auto& s : this->disasm->getSections())
        {
            const auto found = std::find(std::begin(PrettyPrinter::AsmSkipSection),
                                         std::end(PrettyPrinter::AsmSkipSection), s.name);

            if(found != std::end(PrettyPrinter::AsmSkipSection) && s.contains(gtirb::EA(x)))
            {
                return true;
            }
        }

        uint64_t xFunctionAddress{0};
        const auto functionEntries = this->disasm->getFunctionEntry();

        for(auto fe = std::begin(*functionEntries); fe != std::end(*functionEntries); ++fe)
        {
            auto feNext = fe;
            feNext++;

            if(x >= *fe && x < *feNext)
            {
                xFunctionAddress = *fe;
                continue;
            }
        }

        std::string xFunctionName{};
        for(const auto& sym :
            gtirb::findSymbols(this->disasm->getSymbolSet(), gtirb::EA(xFunctionAddress)))
        {
            if(sym->getDeclarationKind() == gtirb::Symbol::DeclarationKind::Func)
            {
                xFunctionName = sym->getName();
                break;
            }
        }

        // if we have a function address.
        // and that funciton address has a name.
        // is that name in our skip list?

        if(xFunctionName.empty() == false)
        {
            const auto found = std::find(std::begin(PrettyPrinter::AsmSkipFunction),
                                         std::end(PrettyPrinter::AsmSkipFunction), xFunctionName);
            return found != std::end(PrettyPrinter::AsmSkipFunction);
        }
    }

    return false;
}

void PrettyPrinter::printZeros(uint64_t x)
{
    for(uint64_t i = 0; i < x; i++)
    {
        this->ofs << PrettyPrinter::StrZeroByte << std::endl;
    }
}

std::pair<std::string, char> PrettyPrinter::getOffsetAndSign(const gtirb::SymbolicOperand* symbolic,
                                                             int64_t offset, uint64_t ea,
                                                             uint64_t index) const
{
    if(symbolic)
    {
        try
        {
            const gtirb::SymAddrConst s = boost::get<gtirb::SymAddrConst>(*symbolic);

            if(s.displacement == 0)
            {
                return {s.symbol->getName(), '+'};
            }
            else if(s.displacement > 0)
            {
                return {s.symbol->getName() + "+" + std::to_string(s.displacement), '+'};
            }
            else
            {
                return {s.symbol->getName() + std::to_string(s.displacement), '+'};
            }
        }
        catch(boost::bad_get&)
        {
        }
    }

    if(offset < 0)
    {
        return {std::to_string(-offset), '-'};
    }
    return {std::to_string(offset), '+'};
}

bool PrettyPrinter::getIsPointerToExcludedCode(bool hasLabel,
                                               const gtirb::SymbolicOperandSet& symbolic,
                                               const gtirb::Data* dg, const gtirb::Data* dgNext)
{
    // If we have a label followed by a pointer.
    if(hasLabel && dgNext)
    {
        auto foundSymbolic = symbolic.find(dgNext->getEA());
        if(foundSymbolic != symbolic.end())
        {
            auto* sym = get<gtirb::SymAddrConst>(foundSymbolic->second);
            if(sym)
            {
                return this->skipEA(sym->symbol->getEA());
            }
        }
    }

    // Or if we just have a pointer...
    auto foundSymbolic = symbolic.find(dg->getEA());
    if(foundSymbolic != symbolic.end())
    {
        auto* sym = get<gtirb::SymAddrConst>(foundSymbolic->second);
        if(sym)
        {
            return this->skipEA(sym->symbol->getEA());
        }
    }

    return false;
}

std::string PrettyPrinter::GetSymbolToPrint(uint64_t x)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << x << std::dec;
    return ss.str();
}

int64_t PrettyPrinter::GetNeededPadding(int64_t alignment, int64_t currentAlignment,
                                        int64_t requiredAlignment)
{
    if(alignment >= currentAlignment)
    {
        return alignment - currentAlignment;
    }

    return (alignment + requiredAlignment) - currentAlignment;
}

bool PrettyPrinter::GetIsNullReg(const std::string& x)
{
    const std::vector<std::string> adapt{"NullReg64", "NullReg32", "NullReg16", "NullSReg"};

    const auto found = std::find(std::begin(adapt), std::end(adapt), x);
    return (found != std::end(adapt));
}

bool PrettyPrinter::isSectionSkipped(const std::string& name)
{
    const auto foundSkipSection = std::find(std::begin(PrettyPrinter::AsmSkipSection),
                                            std::end(PrettyPrinter::AsmSkipSection), name);
    return foundSkipSection != std::end(PrettyPrinter::AsmSkipSection);
}
