#include "DisasmData.h"
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <fstream>
#include <gsl/gsl>
#include <gtirb/Block.hpp>
#include <gtirb/ImageByteMap.hpp>
#include <gtirb/Instruction.hpp>
#include <gtirb/Module.hpp>
#include <gtirb/Section.hpp>
#include <gtirb/Symbol.hpp>
#include <gtirb/SymbolSet.hpp>
#include <iostream>

void DisasmData::parseDirectory(std::string x)
{
    boost::trim(x);

    this->parseSymbol(x + "/symbol.facts");
    this->parseSection(x + "/section.facts");
    this->parseRelocation(x + "/relocation.facts");
    this->parseDecodedInstruction(x + "/instruction.facts");
    this->parseOpRegdirect(x + "/op_regdirect.facts");
    this->parseOpImmediate(x + "/op_immediate.facts");
    this->parseOpIndirect(x + "/op_indirect.facts");
    this->parseDataByte(x + "/data_byte.facts");

    this->parseBlock(x + "/block.csv");
    this->parseCodeInblock(x + "/code_in_block.csv");
    this->parseRemainingEA(x + "/phase2-remaining_ea.csv");
    this->parseMainFunction(x + "/main_function.csv");
    this->parseStartFunction(x + "/start_function.csv");
    this->parseFunctionEntry(x + "/function_entry2.csv");
    this->parseAmbiguousSymbol(x + "/ambiguous_symbol.csv");
    this->parseDirectCall(x + "/direct_call.csv");
    this->parsePLTCodeReference(x + "/plt_code_reference.csv");
    this->parsePLTDataReference(x + "/plt_data_reference.csv");
    this->parseSymbolicOperand(x + "/symbolic_operand.csv");
    this->parseMovedLabel(x + "/moved_label.csv");
    this->parseLabeledData(x + "/labeled_data.csv");
    this->parseSymbolicData(x + "/symbolic_data.csv");
    this->parseSymbolMinusSymbol(x + "/symbol_minus_symbol.csv");
    this->parseMovedDataLabel(x + "/moved_data_label.csv");
    this->parseString(x + "/string.csv");
    this->parseBSSData(x + "/bss_data.csv");

    this->parseStackOperand(x + "/stack_operand.csv");
    this->parsePreferredDataAccess(x + "/preferred_data_access.csv");
    this->parseDataAccessPattern(x + "/data_access_pattern.csv");

    this->parseDiscardedBlock(x + "/discarded_block.csv");
    this->parseDirectJump(x + "/direct_jump.csv");
    this->parsePCRelativeJump(x + "/pc_relative_jump.csv");
    this->parsePCRelativeCall(x + "/pc_relative_call.csv");
    this->parseBlockOverlap(x + "/block_still_overlap.csv");
    this->parseDefUsed(x + "/def_used.csv");

    this->parsePairedDataAccess(x + "/paired_data_access.csv");
    this->parseValueReg(x + "/value_reg.csv");
    this->parseIncompleteCFG(x + "/incomplete_cfg.csv");
    this->parseNoReturn(x + "/no_return.csv");
    this->parseInFunction(x + "/in_function.csv");

    // Build IR for blocks from parsed data
    this->createCodeBlocks();
    this->buildDataGroups();
}

void DisasmData::createCodeBlocks()
{
    std::vector<gtirb::Block> blocks;

    for(auto& blockAddress : this->block)
    {
        std::vector<gtirb::Instruction> instructions;

        for(auto& cib : this->code_in_block)
        {
            // The instruction's block address == the block's addres.
            if(cib.BlockAddress == blockAddress)
            {
                instructions.push_back(this->buildInstruction(gtirb::EA(cib.EA)));
            }
        }

        std::sort(instructions.begin(), instructions.end(),
                  [](const auto& left, const auto& right) { return left.getEA() < right.getEA(); });

        gtirb::EA end;
        if(!instructions.empty())
        {
            auto address = instructions.back().getEA();
            end = gtirb::EA(address.get() + this->getDecodedInstruction(address)->Size);
        }
        else
        {
            end = gtirb::EA(blockAddress);
        }

        blocks.emplace_back(gtirb::Block(gtirb::EA(blockAddress), end, instructions));
    }

    std::sort(blocks.begin(), blocks.end(), [](const auto& left, const auto& right) {
        return left.getStartingAddress() < right.getStartingAddress();
    });

    this->ir.getMainModule()->setBlocks(blocks);
}

void DisasmData::parseSymbol(const std::string& x)
{
    Table fromFile{5};
    fromFile.parseFile(x);

    int count = 0;
    for(const auto& ff : fromFile)
    {
        count++;

        assert(ff.size() == 5);

        gtirb::EA base{boost::lexical_cast<uint64_t>(ff[0])};
        uint64_t size = boost::lexical_cast<uint64_t>(ff[1]);
        std::string type = ff[2];
        std::string scope = ff[3];
        std::string name = ff[4];

        auto& new_sym = getSymbolSet()->addSymbol(gtirb::Symbol(gtirb::EA(base)));
        new_sym.setElementSize(size);
        new_sym.setName(name);
        // NOTE: don't seem to care about OBJECT or NOTYPE, and not clear how
        // to represent them in gtirb.
        if(type == "FUNC")
        {
            new_sym.setDeclarationKind(gtirb::Symbol::DeclarationKind::Func);
        }
        // NOTE: don't seem to care about LOCAL or WEAK, and not clear how to
        // represent them in gtirb.
        new_sym.setIsGlobal(scope == "GLOBAL");
    }

    std::cerr << " # Number of symbol: " << count << std::endl;
}

void DisasmData::parseSection(const std::string& x)
{
    Table fromFile{3};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        gtirb::EA{boost::lexical_cast<uint64_t>(ff[2])};
        this->ir.getMainModule()->addSection({ff[0], boost::lexical_cast<uint64_t>(ff[1]),
                                              gtirb::EA{boost::lexical_cast<uint64_t>(ff[2])}});
    }

    std::cerr << " # Number of section: " << getSections().size() << std::endl;
}

void DisasmData::parseRelocation(const std::string& x)
{
    Table fromFile{4};
    fromFile.parseFile(x);
    std::vector<gtirb::Relocation> relocations;

    for(const auto& ff : fromFile)
    {
        relocations.push_back(gtirb::Relocation{gtirb::EA(boost::lexical_cast<uint64_t>(ff[0])),
                                                ff[1], ff[2],
                                                boost::lexical_cast<uint64_t>(ff[3])});
    }
    this->ir.getMainModule()->setRelocations(relocations);

    std::cerr << " # Number of relocation: " << this->ir.getMainModule()->getRelocations()->size()
              << std::endl;
}

void DisasmData::parseDecodedInstruction(const std::string& x)
{
    Table fromFile{7};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->instruction.push_back(DecodedInstruction(ff));
    }

    std::cerr << " # Number of instruction: " << this->instruction.size() << std::endl;
}

void DisasmData::parseOpRegdirect(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->op_regdirect.push_back(OpRegdirect(ff));
    }

    std::cerr << " # Number of op_regdirect: " << this->op_regdirect.size() << std::endl;
}

void DisasmData::parseOpImmediate(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->op_immediate.push_back(OpImmediate(ff));
    }

    std::cerr << " # Number of op_immediate: " << this->op_immediate.size() << std::endl;
}

void DisasmData::parseOpIndirect(const std::string& x)
{
    Table fromFile{7};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->op_indirect.push_back(OpIndirect(ff));
    }

    std::cerr << " # Number of op_indirect: " << this->op_indirect.size() << std::endl;
}

void DisasmData::parseDataByte(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    int count = 0;
    for(const auto& ff : fromFile)
    {
        gtirb::EA ea(boost::lexical_cast<uint64_t>(ff[0]));

        // A lexical cast directly to uint8_t failed on double-digit numbers.
        const auto byte = boost::lexical_cast<int>(ff[1]);
        assert(byte >= 0);
        assert(byte < 256);

        auto byteMap = this->ir.getMainModule()->getImageByteMap();
        auto minMax = byteMap->getEAMinMax();
        byteMap->setEAMinMax({std::min(minMax.first, ea), std::max(minMax.second, ea)});
        byteMap->setData(ea, static_cast<uint8_t>(byte));

        count++;
    }

    std::cerr << " # Number of data_byte: " << count << std::endl;
}

void DisasmData::parseBlock(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->block.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of block: " << this->block.size() << std::endl;
}

void DisasmData::parseCodeInblock(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->code_in_block.push_back(CodeInBlock(ff));
    }

    std::cerr << " # Number of code_in_block: " << this->code_in_block.size() << std::endl;
}

void DisasmData::parseRemainingEA(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->remaining_ea.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of remaining_ea: " << this->remaining_ea.size() << std::endl;
}

void DisasmData::parseMainFunction(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->main_function.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of main_function: " << this->main_function.size() << std::endl;
}

void DisasmData::parseStartFunction(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->start_function.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of start_function: " << this->start_function.size() << std::endl;
}

void DisasmData::parseFunctionEntry(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->function_entry.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::sort(std::begin(this->function_entry), std::end(this->function_entry));

    std::cerr << " # Number of function_entry: " << this->function_entry.size() << std::endl;
}

void DisasmData::parseAmbiguousSymbol(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->ambiguous_symbol.push_back(ff[0]);
    }

    std::cerr << " # Number of ambiguous_symbol: " << this->ambiguous_symbol.size() << std::endl;
}

void DisasmData::parseDirectCall(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->direct_call.push_back(DirectCall(ff));
    }

    std::cerr << " # Number of direct_call: " << this->direct_call.size() << std::endl;
}

void DisasmData::parsePLTCodeReference(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->plt_code_reference.push_back(PLTReference(ff));
    }

    std::cerr << " # Number of plt_code_reference: " << this->plt_code_reference.size()
              << std::endl;
}
void DisasmData::parsePLTDataReference(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->plt_data_reference.push_back(PLTReference(ff));
    }

    std::cerr << " # Number of plt_data_reference: " << this->plt_data_reference.size()
              << std::endl;
}

void DisasmData::parseSymbolicOperand(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->symbolic_operand.push_back(SymbolicOperand(ff));
    }

    std::cerr << " # Number of symbolic_operand: " << this->symbolic_operand.size() << std::endl;
}

void DisasmData::parseMovedLabel(const std::string& x)
{
    Table fromFile{4};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->moved_label.push_back(MovedLabel(ff));
    }

    std::cerr << " # Number of moved_label: " << this->moved_label.size() << std::endl;
}

void DisasmData::parseLabeledData(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->labeled_data.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of labeled_data: " << this->labeled_data.size() << std::endl;
}

void DisasmData::parseSymbolicData(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->symbolic_data.push_back(SymbolicData(ff));
    }

    std::cerr << " # Number of symbolic_data: " << this->symbolic_data.size() << std::endl;
}

void DisasmData::parseSymbolMinusSymbol(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->symbol_minus_symbol.push_back(SymbolMinusSymbol(ff));
    }

    std::cerr << " # Number of symbol_minus_symbol: " << this->symbol_minus_symbol.size()
              << std::endl;
}

void DisasmData::parseMovedDataLabel(const std::string& x)
{
    Table fromFile{3};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->moved_data_label.push_back(MovedDataLabel(ff));
    }

    std::cerr << " # Number of moved_data_label: " << this->moved_data_label.size() << std::endl;
}

void DisasmData::parseString(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->string.push_back(String(ff));
    }

    std::cerr << " # Number of string: " << this->string.size() << std::endl;
}

void DisasmData::parseBSSData(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->bss_data.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::sort(std::begin(this->bss_data), std::end(this->bss_data));

    std::cerr << " # Number of bss_data: " << this->bss_data.size() << std::endl;
}

void DisasmData::parseStackOperand(const std::string& x)
{
    this->stack_operand.parseFile(x);
    std::cerr << " # Number of stack_operand: " << this->stack_operand.size() << std::endl;
}

void DisasmData::parsePreferredDataAccess(const std::string& x)
{
    this->preferred_data_access.parseFile(x);
    std::cerr << " # Number of preferred_data_access: " << this->preferred_data_access.size()
              << std::endl;
}

void DisasmData::parseDataAccessPattern(const std::string& x)
{
    this->data_access_pattern.parseFile(x);
    std::cerr << " # Number of data_access_pattern: " << this->data_access_pattern.size()
              << std::endl;
}

void DisasmData::parseDiscardedBlock(const std::string& x)
{
    this->discarded_block.parseFile(x);
    std::cerr << " # Number of discarded_block: " << this->discarded_block.size() << std::endl;
}

void DisasmData::parseDirectJump(const std::string& x)
{
    this->direct_jump.parseFile(x);
    std::cerr << " # Number of direct_jump: " << this->direct_jump.size() << std::endl;
}

void DisasmData::parsePCRelativeJump(const std::string& x)
{
    this->pc_relative_jump.parseFile(x);
    std::cerr << " # Number of pc_relative_jump: " << this->pc_relative_jump.size() << std::endl;
}

void DisasmData::parsePCRelativeCall(const std::string& x)
{
    this->pc_relative_call.parseFile(x);
    std::cerr << " # Number of pc_relative_call: " << this->pc_relative_call.size() << std::endl;
}

void DisasmData::parseBlockOverlap(const std::string& x)
{
    this->block_overlap.parseFile(x);
    std::cerr << " # Number of block_overlap: " << this->block_overlap.size() << std::endl;
}

void DisasmData::parseDefUsed(const std::string& x)
{
    this->def_used.parseFile(x);
    std::cerr << " # Number of def_used: " << this->def_used.size() << std::endl;
}

void DisasmData::parsePairedDataAccess(const std::string& x)
{
    this->paired_data_access.parseFile(x);
    std::cerr << " # Number of paired_data_access: " << this->paired_data_access.size()
              << std::endl;
}

void DisasmData::parseValueReg(const std::string& x)
{
    this->value_reg.parseFile(x);
    std::cerr << " # Number of value_reg: " << this->value_reg.size() << std::endl;
}

void DisasmData::parseIncompleteCFG(const std::string& x)
{
    this->incomplete_cfg.parseFile(x);
    std::cerr << " # Number of incomplete_cfg: " << this->incomplete_cfg.size() << std::endl;
}

void DisasmData::parseNoReturn(const std::string& x)
{
    this->no_return.parseFile(x);
    std::cerr << " # Number of no_return: " << this->no_return.size() << std::endl;
}

void DisasmData::parseInFunction(const std::string& x)
{
    this->in_function.parseFile(x);
    std::cerr << " # Number of in_function: " << this->in_function.size() << std::endl;
}

const std::vector<gtirb::Section>& DisasmData::getSections() const
{
    return this->ir.getMainModule()->getSections();
}

std::vector<DecodedInstruction>* DisasmData::getDecodedInstruction()
{
    return &this->instruction;
}

std::vector<OpRegdirect>* DisasmData::getOPRegdirect()
{
    return &this->op_regdirect;
}

std::vector<OpImmediate>* DisasmData::getOPImmediate()
{
    return &this->op_immediate;
}

std::vector<OpIndirect>* DisasmData::getOPIndirect()
{
    return &this->op_indirect;
}

std::vector<uint64_t>* DisasmData::getRemainingEA()
{
    return &this->remaining_ea;
}

std::vector<uint64_t>* DisasmData::getMainFunction()
{
    return &this->main_function;
}

std::vector<uint64_t>* DisasmData::getStartFunction()
{
    return &this->start_function;
}

std::vector<uint64_t>* DisasmData::getFunctionEntry()
{
    return &this->function_entry;
}

std::vector<std::string>* DisasmData::getAmbiguousSymbol()
{
    return &this->ambiguous_symbol;
}

std::vector<DirectCall>* DisasmData::getDirectCall()
{
    return &this->direct_call;
}

std::vector<PLTReference>* DisasmData::getPLTCodeReference()
{
    return &this->plt_code_reference;
}

std::vector<PLTReference>* DisasmData::getPLTDataReference()
{
    return &this->plt_data_reference;
}

std::vector<SymbolicOperand>* DisasmData::getSymbolicOperand()
{
    return &this->symbolic_operand;
}

std::vector<MovedLabel>* DisasmData::getMovedLabel()
{
    return &this->moved_label;
}

std::vector<uint64_t>* DisasmData::getLabeledData()
{
    return &this->labeled_data;
}

std::vector<SymbolicData>* DisasmData::getSymbolicData()
{
    return &this->symbolic_data;
}

std::vector<SymbolMinusSymbol>* DisasmData::getSymbolMinusSymbol()
{
    return &this->symbol_minus_symbol;
}

std::vector<MovedDataLabel>* DisasmData::getMovedDataLabel()
{
    return &this->moved_data_label;
}

std::vector<String>* DisasmData::getString()
{
    return &this->string;
}

std::vector<uint64_t>* DisasmData::getBSSData()
{
    return &this->bss_data;
}

std::vector<gtirb::Table::InnerMapType>& DisasmData::getDataSections()
{
    auto& v = this->ir.getMainModule()->getTable("DisasmData")->contents["dataSections"];
    return boost::get<std::vector<gtirb::Table::InnerMapType>>(v);
}

Table* DisasmData::getStackOperand()
{
    return &this->stack_operand;
}

Table* DisasmData::getPreferredDataAccess()
{
    return &this->preferred_data_access;
}

Table* DisasmData::getDataAccessPattern()
{
    return &this->data_access_pattern;
}

Table* DisasmData::getDiscardedBlock()
{
    return &this->discarded_block;
}

Table* DisasmData::getDirectJump()
{
    return &this->direct_jump;
}

Table* DisasmData::getPCRelativeJump()
{
    return &this->pc_relative_jump;
}

Table* DisasmData::getPCRelativeCall()
{
    return &this->pc_relative_call;
}

Table* DisasmData::getBlockOverlap()
{
    return &this->block_overlap;
}

Table* DisasmData::getDefUsed()
{
    return &this->def_used;
}

Table* DisasmData::getPairedDataAccess()
{
    return &this->paired_data_access;
}

Table* DisasmData::getValueReg()
{
    return &this->value_reg;
}

Table* DisasmData::getIncompleteCFG()
{
    return &this->incomplete_cfg;
}

Table* DisasmData::getNoReturn()
{
    return &this->no_return;
}

Table* DisasmData::getInFunction()
{
    return &this->in_function;
}

gtirb::Instruction::SymbolicOperand DisasmData::buildSymbolic(gtirb::Instruction& inst,
                                                              uint64_t operand,
                                                              uint64_t index) const
{
    auto opImm = this->getOpImmediate(operand);
    if(opImm != nullptr)
    {
        auto pltReference = this->getPLTCodeReference(inst.getEA());
        if(pltReference != nullptr)
        {
            return {{pltReference->Name}, {}, {}, {}};
        }

        auto directCall = this->getDirectCall(inst.getEA());
        if(directCall != nullptr)
        {
            return {{}, {gtirb::EA(directCall->Destination)}, {}, {}};
        }

        auto movedLabel = this->getMovedLabel(inst.getEA(), index);
        if(movedLabel != nullptr)
        {
            return {{}, {}, {{movedLabel->Offset1, movedLabel->Offset2}}, {}};
        }

        if(this->getSymbolicOperand(inst.getEA(), index) != nullptr)
        {
            return {{}, {}, {}, true};
        }
    }

    if(this->getOpIndirect(operand))
    {
        auto movedLabel = this->getMovedLabel(inst.getEA(), index);
        if(movedLabel != nullptr)
        {
            return {{}, {}, {{movedLabel->Offset1, movedLabel->Offset2}}, {}};
        }

        if(this->getSymbolicOperand(inst.getEA(), index))
        {
            return {{}, {}, {}, true};
        }
    }
    return {};
}

gtirb::Instruction DisasmData::buildInstruction(gtirb::EA ea) const
{
    auto inst = this->getDecodedInstruction(ea);
    gtirb::Instruction gtInst(ea);

    auto& symbolic = gtInst.getSymbolicOperands();

    symbolic.push_back(this->buildSymbolic(gtInst, inst->Op1, 1));
    symbolic.push_back(this->buildSymbolic(gtInst, inst->Op2, 2));
    symbolic.push_back(this->buildSymbolic(gtInst, inst->Op3, 3));

    return gtInst;
}

void DisasmData::buildDataGroups()
{
    std::vector<gtirb::Table::InnerMapType> dataSections;

    for(auto& s : this->getSections())
    {
        auto foundDataSection = getDataSectionDescriptor(s.name);

        if(foundDataSection != nullptr)
        {
            gtirb::Table::InnerMapType dataSection;
            dataSection["name"] = s.name;
            dataSection["alignment"] = foundDataSection->second;

            std::vector<uint64_t> dataGroupIndices;

            auto module = this->ir.getMainModule();
            std::vector<uint8_t> bytes =
                module->getImageByteMap()->getData(s.startingAddress, s.size);

            for(auto currentAddr = s.startingAddress.get(); currentAddr < s.addressLimit();
                currentAddr++)
            {
                // Insert a marker for labeled data?
                const auto foundLabeledData =
                    std::find(std::begin(*this->getLabeledData()),
                              std::end(*this->getLabeledData()), currentAddr);
                if(foundLabeledData != std::end(*this->getLabeledData()))
                {
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup =
                        std::make_unique<gtirb::DataLabelMarker>(gtirb::EA(currentAddr));
                    module->addData(std::move(dataGroup));
                }

                // Case 1, 2, 3
                const auto symbolic = this->getSymbolicData(currentAddr);
                if(symbolic != nullptr)
                {
                    // Case 1
                    const auto pltReference = this->getPLTDataReference(gtirb::EA(currentAddr));
                    if(pltReference != nullptr)
                    {
                        dataGroupIndices.push_back(module->getData().size());
                        auto dataGroup =
                            std::make_unique<gtirb::DataPLTReference>(gtirb::EA(currentAddr));
                        dataGroup->function = pltReference->Name;
                        module->addData(std::move(dataGroup));

                        currentAddr += 7;
                        continue;
                    }

                    // Case 2, 3
                    // There was no PLT Reference and there was no label found.
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup = std::make_unique<gtirb::DataPointer>(gtirb::EA(currentAddr));
                    dataGroup->content = gtirb::EA(symbolic->GroupContent);
                    module->addData(std::move(dataGroup));

                    currentAddr += 7;
                    continue;
                }

                // Case 4, 5
                const auto symMinusSym = this->getSymbolMinusSymbol(currentAddr);
                if(symMinusSym != nullptr)
                {
                    // Case 4, 5
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup =
                        std::make_unique<gtirb::DataPointerDiff>(gtirb::EA(currentAddr));
                    dataGroup->symbol1 = gtirb::EA(symMinusSym->Symbol1);
                    dataGroup->symbol2 = gtirb::EA(symMinusSym->Symbol2);
                    module->addData(std::move(dataGroup));

                    currentAddr += 3;
                    continue;
                }

                // Case 6
                const auto str = this->getString(currentAddr);
                if(str != nullptr)
                {
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup = std::make_unique<gtirb::DataString>(gtirb::EA(currentAddr));
                    dataGroup->size = str->End - currentAddr;

                    // Because the loop is going to increment this counter, don't skip a byte.
                    currentAddr = str->End - 1;
                    module->addData(std::move(dataGroup));
                    continue;
                }

                // Store raw data
                dataGroupIndices.push_back(module->getData().size());
                auto dataGroup = std::make_unique<gtirb::DataRawByte>(gtirb::EA(currentAddr));
                module->addData(std::move(dataGroup));
            }

            dataSection["dataGroups"] = dataGroupIndices;
            dataSections.push_back(std::move(dataSection));
        }
    }

    auto table = this->ir.getMainModule()->addTable("DisasmData", std::make_unique<gtirb::Table>());
    table->contents["dataSections"] = dataSections;
}

const std::vector<gtirb::Block>* DisasmData::getCodeBlocks() const
{
    return this->ir.getMainModule()->getBlocks();
}

std::string DisasmData::getSectionName(uint64_t x) const
{
    const auto& sections = this->getSections();
    const auto& match = find_if(sections.begin(), sections.end(),
                                [x](const auto& s) { return s.startingAddress == x; });

    if(match != sections.end())
    {
        return match->name;
    }

    return std::string{};
}

static bool isFunction(const gtirb::Symbol& sym)
{
    return sym.getDeclarationKind() == gtirb::Symbol::DeclarationKind::Func;
}

// function_complete_name
std::string DisasmData::getFunctionName(gtirb::EA x) const
{
    for(auto& s : this->getSymbolSet()->getSymbols(x))
    {
        if(isFunction(*s))
        {
            std::stringstream name;
            name << s->getName();

            if(this->getIsAmbiguousSymbol(s->getName()) == true)
            {
                name << "_" << std::hex << x;
            }

            return name.str();
        }
    }

    if(x == this->main_function[0])
    {
        return "main";
    }
    else if(x == this->start_function[0])
    {
        return "_start";
    }

    // or is this a funciton entry?
    for(auto f : this->function_entry)
    {
        if(x == f)
        {
            std::stringstream ss;
            ss << "unknown_function_" << std::hex << x;
            return ss.str();
        }
    }

    return std::string{};
}

std::string DisasmData::getGlobalSymbolReference(uint64_t ea) const
{
    for(const auto& sym : getSymbolSet()->getSymbols())
    {
        /// \todo This will need looked at again to cover the logic
        if(sym.getEA().get() <= ea
           && sym.getEA().get() + sym.getElementSize() > ea) // fall within the symbol
        {
            uint64_t displacement = ea - sym.getEA().get();

            // in a function with non-zero displacement we do not use the relative addressing
            if(displacement > 0 && isFunction(sym))
            {
                return std::string{};
            }
            if(sym.getIsGlobal())
            {
                // %do not print labels for symbols that have to be relocated
                const auto name = DisasmData::CleanSymbolNameSuffix(sym.getName());

                if(DisasmData::GetIsReservedSymbol(name) == false)
                {
                    if(displacement > 0)
                    {
                        return DisasmData::AvoidRegNameConflicts(name) + "+"
                               + std::to_string(displacement);
                    }
                    else
                    {
                        return DisasmData::AvoidRegNameConflicts(name);
                    }
                }
            }
        }
    }

    // check the relocation table
    for(const auto& r : *this->ir.getMainModule()->getRelocations())
    {
        if(r.ea == ea)
        {
            if(r.type == std::string{"R_X86_64_GLOB_DAT"})
                return DisasmData::AvoidRegNameConflicts(r.name) + "@GOTPCREL";
            else
                return DisasmData::AvoidRegNameConflicts(r.name);
        }
    }
    return std::string{};
}

std::string DisasmData::getGlobalSymbolName(uint64_t ea) const
{
    for(const auto& sym : getSymbolSet()->getSymbols())
    {
        if(sym.getEA().get() == ea)
        {
            if(sym.getIsGlobal())
            {
                // %do not print labels for symbols that have to be relocated
                const auto name = DisasmData::CleanSymbolNameSuffix(sym.getName());

                // if it is not relocated...
                if(this->getRelocation(name) == nullptr)
                {
                    if(DisasmData::GetIsReservedSymbol(name) == false)
                    {
                        return std::string{DisasmData::AvoidRegNameConflicts(name)};
                    }
                }
            }
        }
    }

    return std::string{};
}

const PLTReference* const DisasmData::getPLTCodeReference(uint64_t ea) const
{
    const auto found =
        std::find_if(std::begin(this->plt_code_reference), std::end(this->plt_code_reference),
                     [ea](const auto& element) { return element.EA == ea; });

    if(found != std::end(this->plt_code_reference))
    {
        return &(*found);
    }

    return nullptr;
}

const PLTReference* const DisasmData::getPLTDataReference(uint64_t ea) const
{
    const auto found =
        std::find_if(std::begin(this->plt_data_reference), std::end(this->plt_data_reference),
                     [ea](const auto& element) { return element.EA == ea; });

    if(found != std::end(this->plt_data_reference))
    {
        return &(*found);
    }

    return nullptr;
}

const SymbolicData* const DisasmData::getSymbolicData(uint64_t ea) const
{
    const auto found = std::find_if(std::begin(this->symbolic_data), std::end(this->symbolic_data),
                                    [ea](const auto& element) { return element.EA == ea; });

    if(found != std::end(this->symbolic_data))
    {
        return &(*found);
    }

    return nullptr;
}

const SymbolMinusSymbol* const DisasmData::getSymbolMinusSymbol(uint64_t ea) const
{
    const auto found =
        std::find_if(std::begin(this->symbol_minus_symbol), std::end(this->symbol_minus_symbol),
                     [ea](const auto& element) { return element.EA == ea; });

    if(found != std::end(this->symbol_minus_symbol))
    {
        return &(*found);
    }

    return nullptr;
}

const String* const DisasmData::getString(uint64_t ea) const
{
    const auto found = std::find_if(std::begin(this->string), std::end(this->string),
                                    [ea](const auto& element) { return element.EA == ea; });

    if(found != std::end(this->string))
    {
        return &(*found);
    }

    return nullptr;
}

const DirectCall* const DisasmData::getDirectCall(uint64_t ea) const
{
    const auto found = std::find_if(std::begin(this->direct_call), std::end(this->direct_call),
                                    [ea](const auto& element) { return element.EA == ea; });

    if(found != std::end(this->direct_call))
    {
        return &(*found);
    }

    return nullptr;
}

const MovedLabel* const DisasmData::getMovedLabel(uint64_t ea, uint64_t index) const
{
    const auto found = std::find_if(
        std::begin(this->moved_label), std::end(this->moved_label),
        [ea, index](const auto& element) { return element.EA == ea && element.N == index; });

    if(found != std::end(this->moved_label))
    {
        return &(*found);
    }

    return nullptr;
}

const MovedDataLabel* const DisasmData::getMovedDataLabel(uint64_t ea) const
{
    const auto found =
        std::find_if(std::begin(this->moved_data_label), std::end(this->moved_data_label),
                     [ea](const auto& element) { return element.EA == ea; });

    if(found != std::end(this->moved_data_label))
    {
        return &(*found);
    }

    return nullptr;
}

const SymbolicOperand* const DisasmData::getSymbolicOperand(uint64_t ea, uint64_t opNum) const
{
    const auto found =
        std::find_if(std::begin(this->symbolic_operand), std::end(this->symbolic_operand),
                     [ea, opNum](const auto& element) {
                         return (element.EA == ea) && (element.OpNum == opNum);
                     });

    if(found != std::end(this->symbolic_operand))
    {
        return &(*found);
    }

    return nullptr;
}

const gtirb::Relocation* const DisasmData::getRelocation(const std::string& x) const
{
    auto relocations = this->ir.getMainModule()->getRelocations();
    const auto found = std::find_if(std::begin(*relocations), std::end(*relocations),
                                    [x](const auto& element) { return element.name == x; });

    if(found != std::end(*relocations))
    {
        return &(*found);
    }

    return nullptr;
}

gtirb::SymbolSet* DisasmData::getSymbolSet() const
{
    return this->ir.getMainModule()->getSymbolSet();
}

const gtirb::Section* const DisasmData::getSection(const std::string& x) const
{
    const auto found = std::find_if(getSections().begin(), getSections().end(),
                                    [x](const auto& element) { return element.name == x; });

    if(found != getSections().end())
    {
        return &(*found);
    }

    return nullptr;
}

const DecodedInstruction* const DisasmData::getDecodedInstruction(uint64_t ea) const
{
    const auto inst = std::find_if(std::begin(this->instruction), std::end(this->instruction),
                                   [ea](const auto& x) { return x.EA == ea; });

    if(inst != std::end(this->instruction))
    {
        return &(*inst);
    }

    return nullptr;
}

const OpIndirect* const DisasmData::getOpIndirect(uint64_t x) const
{
    const auto found = std::find_if(std::begin(this->op_indirect), std::end(this->op_indirect),
                                    [x](const auto& element) { return element.N == x; });

    if(found != std::end(this->op_indirect))
    {
        return &(*found);
    }

    return nullptr;
}

const OpRegdirect* const DisasmData::getOpRegdirect(uint64_t x) const
{
    const auto found = std::find_if(std::begin(this->op_regdirect), std::end(this->op_regdirect),
                                    [x](const auto& element) { return element.N == x; });

    if(found != std::end(this->op_regdirect))
    {
        return &(*found);
    }

    return nullptr;
}

uint64_t DisasmData::getOpRegdirectCode(std::string x) const
{
    const auto found = std::find_if(std::begin(this->op_regdirect), std::end(this->op_regdirect),
                                    [x](const auto& element) { return element.Register == x; });

    if(found != std::end(this->op_regdirect))
    {
        return found->N;
    }

    return 0;
}

const OpImmediate* const DisasmData::getOpImmediate(uint64_t x) const
{
    const auto found = std::find_if(std::begin(this->op_immediate), std::end(this->op_immediate),
                                    [x](const auto& element) { return element.N == x; });

    if(found != std::end(this->op_immediate))
    {
        return &(*found);
    }

    return nullptr;
}

bool DisasmData::getIsAmbiguousSymbol(const std::string& name) const
{
    const auto found =
        std::find(std::begin(this->ambiguous_symbol), std::end(this->ambiguous_symbol), name);
    return found != std::end(this->ambiguous_symbol);
}

void DisasmData::AdjustPadding(std::vector<gtirb::Block>& blocks)
{
    for(auto i = std::begin(blocks); i != std::end(blocks); ++i)
    {
        auto next = i;
        ++next;
        if(next != std::end(blocks))
        {
            const auto gap = next->getStartingAddress() - i->getEndingAddress();

            // If we have overlap, erase the next element in the list.
            if(i->getEndingAddress() > next->getStartingAddress())
            {
                blocks.erase(next);
            }
            else if(gap > 0)
            {
                // insert a block with no instructions.
                // This should be interpreted as nop's.
                blocks.insert(next,
                              gtirb::Block{i->getEndingAddress(), next->getStartingAddress()});
            }
        }
    }
}

std::string DisasmData::CleanSymbolNameSuffix(std::string x)
{
    return x.substr(0, x.find_first_of('@'));
}

std::string DisasmData::AdaptOpcode(const std::string& x)
{
    const std::map<std::string, std::string> adapt{{"movsd2", "movsd"}, {"imul2", "imul"},
                                                   {"imul3", "imul"},   {"imul1", "imul"},
                                                   {"cmpsd3", "cmpsd"}, {"out_i", "out"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    return x;
}

std::string DisasmData::AdaptRegister(const std::string& x)
{
    const std::map<std::string, std::string> adapt{
        {"R8L", "R8B"},   {"R9L", "R9B"},   {"R10L", "R10B"}, {"R11L", "R11B"}, {"R12L", "R12B"},
        {"R13L", "R13B"}, {"R14L", "R14B"}, {"R15L", "R15B"}, {"R12L", "R12B"}, {"R13L", "R13B"},
        {"ST0", "ST(0)"}, {"ST1", "ST(1)"}, {"ST2", "ST(2)"}, {"ST3", "ST(3)"}, {"ST4", "ST(4)"},
        {"ST5", "ST(5)"}, {"ST6", "ST(6)"}, {"ST7", "ST(7)"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    return x;
}

std::string DisasmData::GetSizeName(uint64_t x)
{
    return DisasmData::GetSizeName(std::to_string(x));
}

std::string DisasmData::GetSizeName(const std::string& x)
{
    const std::map<std::string, std::string> adapt{
        {"128", ""},         {"0", ""},          {"80", "TBYTE PTR"}, {"64", "QWORD PTR"},
        {"32", "DWORD PTR"}, {"16", "WORD PTR"}, {"8", "BYTE PTR"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    assert("Unknown Size");

    return x;
}

std::string DisasmData::GetSizeSuffix(const OpIndirect& x)
{
    return DisasmData::GetSizeSuffix(x.Size);
}

std::string DisasmData::GetSizeSuffix(uint64_t x)
{
    return DisasmData::GetSizeSuffix(std::to_string(x));
}

std::string DisasmData::GetSizeSuffix(const std::string& x)
{
    const std::map<std::string, std::string> adapt{
        {"128", ""}, {"0", ""}, {"80", "t"}, {"64", "q"}, {"32", "d"}, {"16", "w"}, {"8", "b"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    assert("Unknown Size");

    return x;
}

bool DisasmData::GetIsReservedSymbol(const std::string& x)
{
    if(x.length() > 2)
    {
        return ((x[0] == '_') && (x[1] == '_'));
    }

    return false;
}

std::string DisasmData::AvoidRegNameConflicts(const std::string& x)
{
    const std::vector<std::string> adapt{"FS",  "MOD", "DIV", "NOT", "mod",
                                         "div", "not", "and", "or"};

    const auto found = std::find(std::begin(adapt), std::end(adapt), x);
    if(found != std::end(adapt))
    {
        return x + "_renamed";
    }

    return x;
}

// Name, Alignment.
const std::array<std::pair<std::string, int>, 7> DataSectionDescriptors{{
    {".got", 8},         //
    {".got.plt", 8},     //
    {".data.rel.ro", 8}, //
    {".init_array", 8},  //
    {".fini_array", 8},  //
    {".rodata", 16},     //
    {".data", 16}        //
}};

const std::pair<std::string, int>* getDataSectionDescriptor(const std::string& name)
{
    const auto foundDataSection =
        std::find_if(std::begin(DataSectionDescriptors), std::end(DataSectionDescriptors),
                     [name](const auto& dsd) { return dsd.first == name; });
    if(foundDataSection != std::end(DataSectionDescriptors))
        return foundDataSection;
    else
        return nullptr;
}
