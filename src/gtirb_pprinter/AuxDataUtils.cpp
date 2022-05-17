#include "AuxDataUtils.hpp"
#include <iostream>

namespace aux_data {

bool validateAuxData(const gtirb::Module& Mod, std::string TargetFormat) {
  if (!Mod.getAuxData<gtirb::schema::FunctionEntries>()) {
    std::string Msg = "Missing FunctionEntries in module " + Mod.getName();
    std::cerr << Msg << std::endl;
    // return gtirb::createStringError(
    //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
    return false;
  }
  auto Blocks = Mod.getAuxData<gtirb::schema::FunctionBlocks>();
  if (!Blocks) {
    std::string Msg = "Missing FunctionBlocks in module " + Mod.getName();
    std::cerr << Msg << std::endl;
    // return gtirb::createStringError(
    //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
    return false;
  }
  for (auto& [UUID, BlockUUIDS] : *Blocks) {
    (void)UUID; // unused
    if (BlockUUIDS.empty()) {
      std::string Msg = "Function with no blocks in module " + Mod.getName();
      std::cerr << Msg << std::endl;
      // return gtirb::createStringError(
      //     gtirb_pprint::pprinter_error::EmptyFunction,
      //     "Function with no blocks in module " + Mod.getName());
      return false;
    }
  }
  if (TargetFormat == "elf") {
    if (!Mod.getAuxData<gtirb::schema::ElfSymbolInfo>()) {
      std::string Msg = "Missing ElfSymbolInfo in module " + Mod.getName();
      std::cerr << Msg << std::endl;
      // return gtirb::createStringError(
      //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
      return false;
    }
    if (!Mod.getAuxData<gtirb::schema::SectionProperties>()) {
      std::string Msg = "Missing SectionProperties in module " + Mod.getName();
      std::cerr << Msg << std::endl;
      // return gtirb::createStringError(
      //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
      return false;
    }
  }
  return true; // gtirb::Error::success();
}

gtirb::schema::FunctionEntries::Type
getFunctionEntries(const gtirb::Module& Mod) {
  return util::getOrDefault<gtirb::schema::FunctionEntries>(Mod);
}

std::map<gtirb::UUID, std::set<gtirb::UUID>>
getFunctionBlocks(const gtirb::Module& Mod) {
  return util::getOrDefault<gtirb::schema::FunctionBlocks>(Mod);
}

std::optional<std::vector<CFIDirective>>
getCFIDirectives(const gtirb::Offset& Offset, const gtirb::Module& Mod) {
  if (auto Lst = util::getByOffset<gtirb::schema::CfiDirectives>(Offset, Mod)) {
    if (!(*Lst).empty()) {
      std::vector<CFIDirective> Dirs;
      for (const auto& Directive : *Lst) {
        Dirs.emplace_back(Directive);
      }
      return Dirs;
    }
  }
  return std::nullopt;
}

std::optional<std::string> getEncodingType(const gtirb::DataBlock& DataBlock) {
  return util::getByNode<gtirb::schema::Encodings>(
      DataBlock, *(DataBlock.getByteInterval()->getSection()->getModule()));
}
std::optional<uint64_t> getSymbolicExpressionSize(const gtirb::Offset& Offset,
                                                  const gtirb::Module& Mod) {
  return util::getByOffset<gtirb::schema::SymbolicExpressionSizes>(Offset, Mod);
}

gtirb::schema::Alignment::Type getAlignments(const gtirb::Module& Mod) {
  return util::getOrDefault<gtirb::schema::Alignment>(Mod);
}

std::optional<uint64_t> getAlignment(const gtirb::UUID& Uuid,
                                     const gtirb::Module& Mod) {
  return util::getByKey<gtirb::schema::Alignment>(
      Uuid, Mod.getAuxData<gtirb::schema::Alignment>());
}

std::optional<gtirb::UUID> getForwardedSymbol(const gtirb::Symbol* Symbol) {
  if (Symbol && Symbol->getModule())
    return util::getByNode<gtirb::schema::SymbolForwarding>(
        *Symbol, *Symbol->getModule());
  return std::nullopt;
}

std::vector<std::string> getLibraries(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::Libraries>(Module);
}

std::vector<std::string> getLibraryPaths(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::LibraryPaths>(Module);
}

std::vector<std::string> getBinaryType(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::BinaryType>(Module);
}

std::vector<std::string> getArchInfo(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::ArchInfo>(Module);
}

std::map<gtirb::UUID, gtirb::UUID>
getSymbolForwarding(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::SymbolForwarding>(Module);
}

const gtirb::schema::Comments::Type* getComments(const gtirb::Module& Module) {
  return Module.getAuxData<gtirb::schema::Comments>();
}

std::optional<aux_data::ElfSymbolInfo>
getElfSymbolInfo(const gtirb::Symbol& Sym) {
  if (Sym.getModule())
    return util::getByNode<gtirb::schema::ElfSymbolInfo>(Sym,
                                                         *(Sym.getModule()));
  return std::nullopt;
}

void setElfSymbolInfo(gtirb::Symbol& Sym, aux_data::ElfSymbolInfo& Info) {
  auto* Table = Sym.getModule()->getAuxData<gtirb::schema::ElfSymbolInfo>();
  (*Table)[Sym.getUUID()] = Info.asAuxData();
}

std::optional<std::tuple<uint64_t, uint64_t>>
getSectionProperties(const gtirb::Section& Section) {
  if (Section.getModule())
    return util::getByNode<gtirb::schema::SectionProperties>(
        Section, *Section.getModule());
  return std::nullopt;
};

gtirb::schema::ImportEntries::Type getImportEntries(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::ImportEntries>(M);
}

gtirb::schema::ExportEntries::Type getExportEntries(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::ExportEntries>(M);
}

gtirb::schema::PEResources::Type getPEResources(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::PEResources>(M);
};

gtirb::schema::PeImportedSymbols::Type
getPeImportedSymbols(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::PeImportedSymbols>(M);
}

gtirb::schema::PeExportedSymbols::Type
getPeExportedSymbols(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::PeExportedSymbols>(M);
}

gtirb::schema::PeSafeExceptionHandlers::Type
getPeSafeExceptionHandlers(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::PeSafeExceptionHandlers>(M);
}
gtirb::provisional_schema::TypeTable::Type
getTypeTable(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::provisional_schema::TypeTable>(M);
}

gtirb::provisional_schema::PrototypeTable::Type
getPrototypeTable(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::provisional_schema::PrototypeTable>(M);
}

} // namespace aux_data

namespace gtirb_types {
template <class T> T* nodeFromUUID(gtirb::Context& C, gtirb::UUID id) {
  return dyn_cast_or_null<T>(gtirb::Node::getByUUID(C, id));
}

TypePrinter::TypePrinter(const gtirb::Module& M, gtirb::Context& C)
    : Types(aux_data::getTypeTable(M)),
      Prototypes(aux_data::getPrototypeTable(M)), Module(M), Context(C) {
  for (auto& [Uuid, TypeObj] : Types) {
    if (static_cast<Index>(TypeObj.index()) == Index::Struct) {
      makeName(Uuid);
    };
  }

  for (auto& [FnId, Entries] : aux_data::getFunctionEntries(M)) {
    for (auto& EntryBlockUUID : Entries) {
      auto* Block = nodeFromUUID<gtirb::CodeBlock>(C, EntryBlockUUID);
      if (Block) {
        functionEntries[*Block->getAddress()] = FnId;
      }
    }
  }
}

void TypePrinter::makeName(const gtirb::UUID& UUID) {
  std::stringstream ss;
  ss << "s" << StructNames.size();
  StructNames[UUID] = ss.str();
}

std::ostream& TypePrinter::printPrototype(const gtirb::UUID& FnId,
                                          std::ostream& Stream) {
  if (auto TypeIter = Prototypes.find(FnId); TypeIter != Prototypes.end()) {
    return printType(TypeIter->second, Stream);
  }
  return Stream;
}

std::ostream& TypePrinter::printPrototype(const gtirb::Addr& Addr,
                                          std::ostream& Stream) {
  if (auto FnIter = functionEntries.find(Addr);
      FnIter != functionEntries.end()) {
    return printPrototype(FnIter->second, Stream);
  }
  return Stream;
}

std::ostream& TypePrinter::printType(const gtirb::UUID& TypeId,
                                     std::ostream& Stream) {
  auto EntryIter = this->Types.find(TypeId);
  if (EntryIter == Types.end()) {
    // Warn
    return Stream;
  }
  auto& Entry = EntryIter->second;
  switch ((Index)Entry.index()) {
  case Index::Unknown:
    return printUnknown(getVariant<Index::Unknown>(Entry), Stream);
  case Index::Bool:
    return printBool(Stream);
  case Index::Int:
    return printInt(getVariant<Index::Int>(Entry), Stream);
  case Index::Char:
    return printChar(getVariant<Index::Char>(Entry), Stream);
  case Index::Float:
    return printFloat(getVariant<Index::Float>(Entry), Stream);
  case Index::Function:
    return printFunction(getVariant<Index::Function>(Entry), Stream);
  case Index::Pointer:
    return printPointer(getVariant<Index::Pointer>(Entry), Stream);
  case Index::Array:
    return printArray(getVariant<Index::Array>(Entry), Stream);
  case Index::Struct:
    return printStruct(TypeId, Stream);
  case Index::Void:
    return printVoid(Stream);
  case Index::Alias:
    return printAlias(getVariant<Index::Alias>(Entry), Stream);
  default:
    assert(0 && "Unknown variant in type table entry");
    exit(1);
  }
};

std::ostream& TypePrinter::printUnknown(const GtType_t<Index::Unknown>& Width,
                                        std::ostream& Stream) {
  Stream << "unknown" << Width;
  return Stream;
};

std::ostream& TypePrinter::printBool(std::ostream& Stream) {
  Stream << "bool";
  return Stream;
}

std::ostream& TypePrinter::printInt(const GtType_t<Index::Int>& Obj,
                                    std::ostream& Stream) {
  auto& [Signed, Width] = Obj;
  if (!Signed) {
    Stream << "u";
  }
  Stream << "int" << Width;
  return Stream;
}

std::ostream& TypePrinter::printChar(const GtType_t<Index::Char>& Width,
                                     std::ostream& Stream) {
  Stream << "char" << Width;
  return Stream;
}

std::ostream& TypePrinter::printFloat(const GtType_t<Index::Float>& Width,
                                      std::ostream& Stream) {
  Stream << "float" << Width;
  return Stream;
}

std::ostream& TypePrinter::printVoid(std::ostream& Stream) {
  Stream << "void";
  return Stream;
}

std::ostream& TypePrinter::printArray(const GtType_t<Index::Array>& ArrayType,
                                      std::ostream& Stream) {
  auto& [TypeId, Length] = ArrayType;
  printType(TypeId, Stream) << "[" << Length << "]";
  return Stream;
}

std::optional<gtirb::UUID> TypePrinter::getStructId(const gtirb::UUID& TypeId) {
  auto Iter = Types.find(TypeId);
  auto Type = Iter->second;
  gtirb::UUID Candidate;
  switch ((Index)Type.index()) {
  case Index::Struct:
    return TypeId;
  case Index::Alias:
    return getVariant<Index::Alias>(Type);
    break;
  case Index::Pointer:
    return getVariant<Index::Pointer>(Type);
    break;
  case Index::Array:
    return std::get<0>(getVariant<Index::Array>(Type));
    break;
  default:
    return {};
  }
  auto CandidateType = Types.find(Candidate)->second;
  if (static_cast<Index>(CandidateType.index()) == Index::Struct) {
    return Candidate;
  } else {
    return {};
  }
}

std::ostream&
TypePrinter::printFunction(const GtType_t<Index::Function>& FunType,
                           std::ostream& Stream) {
  auto& [RetType, ParamTypes] = FunType;
  Stream << "(";
  for (auto Iter = ParamTypes.begin(); Iter != ParamTypes.end(); ++Iter) {
    auto& UUID = *Iter;
    printType(UUID, Stream);
    auto Iter2 = Iter;
    ++Iter2;
    if (Iter2 != ParamTypes.end()) {
      Stream << ",";
    }
  }
  Stream << ")->";
  printType(RetType, Stream);
  return Stream;
}

std::ostream& TypePrinter::printPointer(const GtType_t<Index::Pointer>& PtrType,
                                        std::ostream& Stream) {
  printType(PtrType, Stream) << " *";
  return Stream;
}

std::ostream& TypePrinter::printAlias(const GtType_t<Index::Alias>& AliasType,
                                      std::ostream& Stream) {
  return printType(AliasType, Stream);
}

std::ostream& TypePrinter::printStruct(const gtirb::UUID& Id,
                                       std::ostream& Stream) {
  if (auto Name = StructNames.find(Id); Name != StructNames.end()) {
    Stream << "struct " << Name->second;
  } else {
    Stream << "unknown_struct";
  }
  return Stream;
}

std::ostream&
TypePrinter::layoutStruct(const GtType_t<Index::Struct>& StructType,
                          std::ostream& Stream, gtirb::UUID Id) {
  static std::vector<gtirb::UUID> StructIds;
  auto& [Size, Fields] = StructType;
  std::stringstream ss;
  ss << "s" << StructNames.size();
  Stream << "struct" << Size << " {";
  for (auto FieldIter = Fields.begin(); FieldIter != Fields.end();
       ++FieldIter) {
    printType(std::get<gtirb::UUID>(*FieldIter), Stream);
    auto Iter2 = FieldIter + 1;
    if (Iter2 != Fields.end())
      Stream << ", ";
  }
  Stream << "} " << StructNames[Id];
  return Stream;
}

} // namespace gtirb_types
