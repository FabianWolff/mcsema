#include "CFGPrettyPrinter.hpp"
#include <sstream>

CFGPrettyPrinter::CFGPrettyPrinter (const Module& module)
    : m_module (module), m_indentLvl (0), m_singleIndent ("   ")
{
}

void CFGPrettyPrinter::print (std::ostream& os)
{
    printModule (m_module, os);
}

void CFGPrettyPrinter::printModule (const Module& module, std::ostream& os)
{
    for (auto intFunc : module.internal_funcs ())
        wrapPrint ("internal_funcs", os, [&] () { printFunction (intFunc, os); });

    for (auto extFunc : module.external_funcs ())
        wrapPrint ("external_funcs", os, [&] () { printExternalFunction (extFunc, os); });

    for (auto intData : module.internal_data ())
        wrapPrint ("internal_data", os, [&] () { printData (intData, os); });

    os << indent () << "module_name: \"" << module.module_name () << "\"" << std::endl;

    for (auto entry : module.entries ())
        wrapPrint ("entries", os, [&] () { printEntrySymbol (entry, os); });

    for (auto extData : module.external_data ())
        wrapPrint ("external_data", os, [&] () { printExternalData (extData, os); });

    for (auto offTbl : module.offset_tables ())
        wrapPrint ("offset_tables", os, [&] () { printOffsetTable (offTbl, os); });
}

void CFGPrettyPrinter::printFunction (const Function& func, std::ostream& os)
{
    for (auto block : func.blocks ())
        wrapPrint ("blocks", os, [&] () { printBlock (block, os); });

    os << indent () << "entry_address: 0x" << std::hex << func.entry_address () << std::dec << std::endl;

    if (func.has_symbol_name ())
        os << indent () << "symbol_name: \"" << func.symbol_name () << "\"" << std::endl;
}

void CFGPrettyPrinter::printExternalFunction (const ExternalFunction& func, std::ostream& os)
{
    os << indent () << "symbol_name: \"" << func.symbol_name () << "\"" << std::endl;
    os << indent () << "calling_convention: " << formatCallingConvention (func.calling_convention ()) << std::endl;
    os << indent () << "has_return: " << ((func.has_return ()) ? "true" : "false") << std::endl;
    os << indent () << "no_return: " << ((func.no_return ()) ? "true" : "false") << std::endl;
    os << indent () << "argument_count: " << std::dec << func.argument_count () << std::endl;
    os << indent () << "is_weak: " << ((func.is_weak ()) ? "true" : "false") << std::endl;

    if (func.has_signature ())
        os << indent () << "signature: \"" << func.signature () << "\"" << std::endl;
}

void CFGPrettyPrinter::printData (const Data& data, std::ostream& os)
{
    os << indent () << "base_address: 0x" << std::hex << data.base_address () << std::dec << std::endl;

    os << indent () << "data: ";
    for (auto c : data.data ())
        os << (((c >= 0x21) && (c <= 0x7E)) ? c : '.');
    os << " [ " << formatHexDump (data.data ()) << " ]" << std::endl;

    for (auto dataSym : data.symbols ())
        wrapPrint ("symbols", os, [&] () { printDataSymbol (dataSym, os); });

    os << indent () << "read_only: " << ((data.read_only ()) ? "true" : "false") << std::endl;
}

void CFGPrettyPrinter::printEntrySymbol (const EntrySymbol& entry, std::ostream& os)
{
    os << indent () << "entry_name: \"" << entry.entry_name () << "\"" << std::endl;
    os << indent () << "entry_address: 0x" << std::hex << entry.entry_address () << std::dec << std::endl;

    if (entry.has_entry_extra ())
        wrapPrint ("entry_extra", os, [&] () { printEntrySymbolExtra (entry.entry_extra (), os); });
}

void CFGPrettyPrinter::printExternalData (const ExternalData& data, std::ostream& os)
{
    os << indent () << "symbol_name: \"" << data.symbol_name () << "\"" << std::endl;
    os << indent () << "data_size: " << std::dec << data.data_size () << std::endl;
    os << indent () << "is_weak: " << ((data.is_weak ()) ? "true" : "false") << std::endl;
}

void CFGPrettyPrinter::printOffsetTable (const OffsetTable& off, std::ostream& os)
{
    os << indent () << "start_addr: 0x" << std::hex << off.start_addr () << std::dec << std::endl;

    for (auto to : off.table_offsets ())
        os << indent () << "table_offset: " << std::dec << to << std::endl;

    for (auto dest : off.destinations ())
        os << indent () << "destinations: " << std::dec << dest << std::endl;
}

void CFGPrettyPrinter::printBlock (const Block& block, std::ostream& os)
{
    for (auto inst : block.insts ())
        wrapPrint ("insts", os, [&] () { printInstruction (inst, os); });

    os << indent () << "base_address: 0x" << std::hex << block.base_address () << std::dec << std::endl;

    for (auto next : block.block_follows ())
        os << indent () << "block_follows: 0x" << std::hex << next << std::dec << std::endl;
}

void CFGPrettyPrinter::printJumpTbl (const JumpTbl& jt, std::ostream& os)
{
    for (auto entry : jt.table_entries ())
        os << indent () << "table_entries: " << std::dec << entry << std::endl;

    os << indent () << "zero_offset: " << std::dec << jt.zero_offset () << std::endl;

    if (jt.has_offset_from_data ())
        os << indent () << "offset_from_data: " << std::dec << jt.offset_from_data () << std::endl;
}

void CFGPrettyPrinter::printJumpIndexTbl (const JumpIndexTbl& jit, std::ostream& os)
{
    os << indent () << "table_entries: " << formatHexDump (jit.table_entries ()) << std::endl;
    os << indent () << "zero_offset: " << std::dec << jit.zero_offset () << std::endl;
}

void CFGPrettyPrinter::printEntrySymbolExtra (const EntrySymbolExtra& esex, std::ostream& os)
{
    os << indent () << "entry_argc: " << std::dec << esex.entry_argc () << std::endl;
    os << indent () << "entry_cconv: " << formatCallingConvention (esex.entry_cconv ()) << std::endl;
    os << indent () << "does_return: " << ((esex.does_return ()) ? "true" : "false") << std::endl;
}

void CFGPrettyPrinter::printDataSymbol (const DataSymbol& sym, std::ostream& os)
{
    os << indent () << "base_address: 0x" << std::hex << sym.base_address () << std::dec << std::endl;
    os << indent () << "symbol_name: \"" << sym.symbol_name () << "\"" << std::endl;
    os << indent () << "symbol_size: " << std::dec << sym.symbol_size () << std::endl;
}

void CFGPrettyPrinter::printInstruction (const Instruction& inst, std::ostream& os)
{
    os << indent () << "inst_bytes: " << formatHexDump (inst.inst_bytes ()) << std::endl;
    os << indent () << "inst_addr: 0x" << std::hex << inst.inst_addr () << std::dec << std::endl;
    if (inst.has_true_target ())
        os << indent () << "true_target: 0x" << std::hex << inst.true_target () << std::dec << std::endl;
    if (inst.has_false_target ())
        os << indent () << "false_target: 0x" << std::hex << inst.false_target () << std::dec << std::endl;
    os << indent () << "inst_len: " << std::dec << inst.inst_len () << std::endl;

    auto formatRefType = [] (Instruction::RefType rt) {
        return (rt == Instruction::CodeRef) ? "CodeRef" : "DataRef";
    };

    if (inst.has_imm_reference ())
        os << indent () << "imm_reference: 0x" << std::hex << inst.imm_reference () << std::dec << std::endl;
    if (inst.has_imm_reloc_offset ())
        os << indent () << "imm_reloc_offset: 0x" << std::hex << inst.imm_reloc_offset () << std::dec << std::endl;
    if (inst.has_imm_ref_type ())
        os << indent () << "imm_ref_type: " << formatRefType (inst.imm_ref_type ()) << std::endl;

    if (inst.has_mem_reference ())
        os << indent () << "mem_reference: 0x" << std::hex << inst.mem_reference () << std::dec << std::endl;
    if (inst.has_mem_reloc_offset ())
        os << indent () << "mem_reloc_offset: 0x" << std::hex << inst.mem_reloc_offset () << std::dec << std::endl;
    if (inst.has_mem_ref_type ())
        os << indent () << "mem_ref_type: " << formatRefType (inst.mem_ref_type ()) << std::endl;

    if (inst.has_ext_call_name ())
        os << indent () << "ext_call_name: \"" << inst.ext_call_name () << "\"" << std::endl;
    if (inst.has_jump_table ())
        wrapPrint ("jump_table", os, [&] () { printJumpTbl (inst.jump_table (), os); });
    if (inst.has_jump_index_table ())
        wrapPrint ("jump_index_table", os, [&] () { printJumpIndexTbl (inst.jump_index_table (), os); });
    if (inst.has_ext_data_name ())
        os << indent () << "ext_data_name: \"" << inst.ext_data_name () << "\"" << std::endl;
    if (inst.has_system_call_number ())
        os << indent () << "system_call_number: " << std::dec << inst.system_call_number () << std::endl;
    if (inst.has_local_noreturn ())
        os << indent () << "local_noreturn: " << ((inst.local_noreturn ()) ? "true" : "false") << std::endl;
    if (inst.has_offset_table_addr ())
        os << indent () << "offset_table_addr: 0x" << std::hex << inst.offset_table_addr () << std::dec << std::endl;
}

const std::string CFGPrettyPrinter::indent (void) const
{
    std::string result;

    for (int i = 0; i < m_indentLvl; ++i)
        result += m_singleIndent;

    return result;
}

const std::string CFGPrettyPrinter::formatCallingConvention (ExternalFunction::CallingConvention cc) const
{
    return (cc == ExternalFunction::CallerCleanup) ? "CallerCleanup"
        : ((cc == ExternalFunction::CalleeCleanup) ? "CalleeCleanup"
           : ((cc == ExternalFunction::FastCall) ? "FastCall"
              : "McsemaCall"));
}

const std::string CFGPrettyPrinter::formatHexDump (const std::string& bytes) const
{
    std::stringstream result;
    bool first = true;

    for (auto c : bytes)
    {
        if (!first)
            result << " ";
        else
            first = false;

        result << std::hex << ((((int) c) & 0xF0) >> 4) << (((int) c) & 0xF) << std::dec;
    }

    return result.str ();
}

void CFGPrettyPrinter::wrapPrint (const std::string& name, std::ostream& os, std::function<void(void)> doPrint)
{
    os << indent () << name << " {" << std::endl;

    m_indentLvl += 1;
    doPrint ();
    m_indentLvl -= 1;

    os << indent () << "}" << std::endl;
}
