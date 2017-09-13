#pragma once

#include "CFG.pb.h"
#include <iostream>
#include <ostream>
#include <functional>

class CFGPrettyPrinter
{
public:
    CFGPrettyPrinter (const Module& module);

    void print (std::ostream& os = std::cout);

private:
    void printModule (const Module& module, std::ostream& os);
    void printFunction (const Function& func, std::ostream& os);
    void printExternalFunction (const ExternalFunction& func, std::ostream& os);
    void printData (const Data& data, std::ostream& os);
    void printEntrySymbol (const EntrySymbol& entry, std::ostream& os);
    void printExternalData (const ExternalData& data, std::ostream& os);
    void printOffsetTable (const OffsetTable& off, std::ostream& os);
    void printBlock (const Block& block, std::ostream& os);
    void printDataSymbol (const DataSymbol& sym, std::ostream& os);
    void printEntrySymbolExtra (const EntrySymbolExtra& esex, std::ostream& os);
    void printJumpTbl (const JumpTbl& jt, std::ostream& os);
    void printJumpIndexTbl (const JumpIndexTbl& jit, std::ostream& os);
    void printInstruction (const Instruction& inst, std::ostream& os);

    const std::string indent (void) const;
    const std::string formatCallingConvention (ExternalFunction::CallingConvention cc) const;
    const std::string formatHexDump (const std::string& bytes) const;
    void wrapPrint (const std::string& name, std::ostream& os, std::function<void(void)> doPrint);

    const Module& m_module;
    const std::string m_singleIndent;
    unsigned int m_indentLvl;
};
