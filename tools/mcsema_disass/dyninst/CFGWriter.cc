#include "CFGWriter.hpp"
#include <Dereference.h>
#include <Function.h>
#include <Instruction.h>
#include <InstructionAST.h>
#include <InstructionCategories.h>
#include <sstream>

using namespace Dyninst;

CFGWriter::CFGWriter (Module& m, const std::string& moduleName,
                      SymtabAPI::Symtab& symtab,
                      ParseAPI::CodeObject& codeObj,
                      const ExternalFunctionManager& extFuncMgr)
    : m_module (m), m_moduleName (moduleName), m_symtab (symtab),
      m_codeObj (codeObj), m_extFuncMgr (extFuncMgr), m_funcMap (),
      m_skipFuncs (), m_sectionMgr (), m_relocations ()
{
    // Populate m_funcMap

    std::vector<SymtabAPI::Function *> functions;
    m_symtab.getAllFunctions (functions);

    for (auto func : functions)
        m_funcMap [func->getOffset ()] = *(func->mangled_names_begin ());

    // Populate m_skipFuncs with some functions known to cause problems

    m_skipFuncs = { "register_tm_clones", "deregister_tm_clones", "__libc_csu_init",
                    "frame_dummy", "_init", "_start", "__do_global_dtors_aux",
                    "__libc_csu_fini", "_fini", "__libc_start_main" };

    // Populate m_sectionMgr with the data from symtab

    std::vector<SymtabAPI::Region *> regions;
    symtab.getAllRegions (regions);

    for (auto reg : regions)
        m_sectionMgr.addRegion (reg);

    // Fill in m_relocations

    for (auto reg : regions)
    {
        if (reg->getRegionName () == ".text")
            m_relocations = reg->getRelocations ();
    }
}

void CFGWriter::skipFunction (const std::string& name)
{
    m_skipFuncs.insert (name);
}

void CFGWriter::write ()
{
    writeInternalFunctions ();
    writeExternalFunctions ();
    writeInternalData ();
    writeEntries ();
    m_module.set_module_name (m_moduleName);
}

bool CFGWriter::shouldSkipFunction (const std::string& name) const
{
    return m_skipFuncs.find (name) != m_skipFuncs.end ();
}

void CFGWriter::writeInternalFunctions ()
{
    for (ParseAPI::Function *func : m_codeObj.funcs ())
    {
        if (shouldSkipFunction (func->name ()))
            continue;
        else if (isExternal (func->entry ()->start ()))
            continue;

        // Add an entry in the protocol buffer

        auto cfgInternalFunc = m_module.add_internal_funcs ();

        // Set the entry address

        ParseAPI::Block *entryBlock = func->entry ();
        cfgInternalFunc->set_entry_address (entryBlock->start ());

        // Write blocks

        for (ParseAPI::Block *block : func->blocks ())
            writeBlock (block, func, cfgInternalFunc);

        if (m_funcMap.find (func->addr ()) != m_funcMap.end ())
            cfgInternalFunc->set_symbol_name (m_funcMap [func->addr ()]);
    }
}

void CFGWriter::writeBlock (ParseAPI::Block *block, ParseAPI::Function *func,
                            Function *cfgInternalFunc)
{
    // Add a new block to the protocol buffer and set its base address

    Block *cfgBlock = cfgInternalFunc->add_blocks ();
    cfgBlock->set_base_address (block->start ());

    // Set outgoing edges

    for (auto edge : block->targets ())
    {
        // Is this block part of the current function?

        bool found = false;

        for (auto bl : func->blocks ())
        {
            if (bl->start () == edge->trg ()->start ())
            {
                found = true;
                break;
            }
        }

        if ((!found) || (edge->trg ()->start () == -1))
            continue;

        // Handle recursive calls

        found = false;

        if (edge->trg ()->start () == func->entry ()->start ())
        {
            for (auto callEdge : func->callEdges ())
            {
                if ((callEdge->src ()->start () == block->start ())
                    && (callEdge->trg ()->start () == func->entry ()->start ()))
                {
                    // Looks like a recursive call, so no block_follows edge here
                    found = true;
                    break;
                }
            }
        }

        if (!found)
            cfgBlock->add_block_follows (edge->trg ()->start ());
    }

    // Write instructions

    std::map<Offset, InstructionAPI::Instruction::Ptr> instructions;
    block->getInsns (instructions);

    // This variable "simulates" the instruction pointer
    Address ip = block->start ();

    for (auto p : instructions)
    {
        InstructionAPI::Instruction *instruction = p.second.get ();

        writeInstruction (instruction, ip, cfgBlock);
        ip += instruction->size ();
    }
}

void CFGWriter::writeInstruction (InstructionAPI::Instruction *instruction,
                                  Address addr, Block *cfgBlock)
{
    // Add a new instruction to the protocol buffer

    Instruction *cfgInstruction = cfgBlock->add_insts ();

    // Set the raw instruction bytes

    std::string instBytes;

    for (int offset = 0; offset < instruction->size (); ++offset)
        instBytes += instruction->rawByte (offset);

    cfgInstruction->set_inst_bytes (instBytes);

    // Set the instruction address and length

    cfgInstruction->set_inst_addr (addr);
    cfgInstruction->set_inst_len (instruction->size ());

    // Handle the instruction's operands

    std::vector<InstructionAPI::Operand> operands;
    instruction->getOperands (operands);

    if (instruction->getCategory () == InstructionAPI::c_CallInsn)
        handleCallInstruction (instruction, addr, cfgInstruction);
    else
        handleNonCallInstruction (instruction, addr, cfgInstruction);
}

void CFGWriter::handleCallInstruction (InstructionAPI::Instruction *instruction,
                                       Address addr, Instruction *cfgInstruction)
{
    Address target;

    std::vector<InstructionAPI::Operand> operands;
    instruction->getOperands (operands);

    if (tryEval (operands [0].getValue ().get (), addr + 5, target))
    {
        target -= 5;

        if (isExternal (target))
        {
            cfgInstruction->set_ext_call_name (getExternalName (target));
            return;
        }
    }

    if (m_relocations.size () > 0)
    {
        auto entry = *(m_relocations.begin ());
        bool found = false;

        for (auto ent : m_relocations)
        {
            if (ent.rel_addr () == (addr + 6))
            {
                entry = ent;
                found = true;
                break;
            }
        }

        if (!((!found) || (found && (entry.getDynSym ()->getRegion () == NULL))))
        {
            Offset off = entry.getDynSym ()->getOffset ();
            cfgInstruction->set_mem_reference (off);
            cfgInstruction->set_mem_ref_type (Instruction::CodeRef);
            return;
        }
    }

    if (tryEval (operands [0].getValue ().get (), addr + 5, target))
    {
        target -= 5;
        cfgInstruction->set_mem_reference (target);
        cfgInstruction->set_mem_ref_type (Instruction::CodeRef);
        return;
    }

    std::cerr << "error: unable to resolve call instruction at 0x"
              << std::hex << addr << std::dec << std::endl;
    throw std::runtime_error { "unresolved call instruction" };
}

void CFGWriter::handleNonCallInstruction (Dyninst::InstructionAPI::Instruction *instruction,
                                          Address addr, Instruction *cfgInstruction)
{
    std::vector<InstructionAPI::Operand> operands;
    instruction->getOperands (operands);
    addr += instruction->size ();

    for (auto op : operands)
    {
        auto expr = op.getValue ();

        if (auto imm = dynamic_cast<InstructionAPI::Immediate *> (expr.get ()))
        {
            Address a = imm->eval ().convert<Address> ();
            if (m_sectionMgr.isData (a))
            {
                auto allSymsAtOffset = m_symtab.findSymbolByOffset (a);
                bool isRef = false;
                if (allSymsAtOffset.size () > 0)
                {
                    for (auto symbol : allSymsAtOffset)
                    {
                        if (symbol->getType () == SymtabAPI::Symbol::ST_OBJECT)
                            isRef = true;
                    }
                }

                if (a > 0x1000)
                    isRef = true;

                if (isRef)
                {
                    cfgInstruction->set_imm_reference (a);
                    cfgInstruction->set_imm_ref_type (Instruction::DataRef);

                    if (m_relocations.size () > 0)
                    {
                        auto entry = *(m_relocations.begin ());
                        for (auto ent : m_relocations)
                        {
                            if (ent.rel_addr () == (addr-instruction->size ())+1)
                            {
                                entry = ent;
                                break;
                            }
                        }

                        Offset off = entry.getDynSym ()->getOffset ();
                        cfgInstruction->set_imm_reference (off + entry.addend ());
                    }
                }
            }
        }
        else if (auto deref = dynamic_cast<InstructionAPI::Dereference *> (expr.get ()))
        {
            std::vector<InstructionAPI::InstructionAST::Ptr> children;
            deref->getChildren (children);
            auto expr = dynamic_cast<InstructionAPI::Expression *> (children [0].get ());
            if (!expr) throw std::runtime_error { "expected expression" };

            Address a;
            if (tryEval (expr, addr, a))
            {
                cfgInstruction->set_mem_reference (a);
                cfgInstruction->set_mem_ref_type (Instruction::DataRef);
            }
        }
    }
}

void CFGWriter::writeExternalFunctions ()
{
    for (const auto& func : m_extFuncMgr.getAllUsed ())
    {
        auto cfgExtFunc = m_module.add_external_funcs ();

        cfgExtFunc->set_symbol_name (func.symbolName ());
        cfgExtFunc->set_calling_convention (func.cfgCallingConvention ());
        cfgExtFunc->set_has_return (func.hasReturn ());
        cfgExtFunc->set_no_return (func.noReturn ());
        cfgExtFunc->set_argument_count (func.argumentCount ());
        cfgExtFunc->set_is_weak (func.isWeak ());
    }
}

void CFGWriter::writeInternalData ()
{
    auto dataRegions = m_sectionMgr.getDataRegions ();

    for (auto region : dataRegions)
    {
        // Sanity check

        if (region->getMemSize () <= 0)
            continue;

        auto cfgInternalData = m_module.add_internal_data ();

        // Print raw data

        std::string data;
        int i = 0;

        for (; i < region->getDiskSize (); ++i)
            data += ((const char *) region->getPtrToRawData ()) [i];

        for (; i < region->getMemSize (); ++i)
            data += '\0';

        // Print metadata

        cfgInternalData->set_base_address (region->getMemOffset ());
        cfgInternalData->set_data (data);
        cfgInternalData->set_read_only (region->getRegionPermissions () == SymtabAPI::Region::RP_R);

        if (region->getRegionName () == ".got.plt")
        {
            const auto& relocations = region->getRelocations ();

            for (auto reloc : relocations)
            {
                for (auto f : m_codeObj.funcs ())
                {
                    if (f->entry ()->start () == reloc.getDynSym ()->getOffset ())
                    {
                        auto cfgSymbol = cfgInternalData->add_symbols ();
                        cfgSymbol->set_base_address (reloc.rel_addr ());

                        std::ostringstream symbolName;
                        symbolName << "sub_" << std::hex << reloc.getDynSym ()->getOffset () << std::dec;
                        cfgSymbol->set_symbol_name (symbolName.str ());

                        cfgSymbol->set_symbol_size (8);
                        break;
                    }
                }
            }
        }
    }
}

void CFGWriter::writeEntries ()
{
    for (auto p : m_funcMap)
    {
        auto cfgEntry = m_module.add_entries ();

        cfgEntry->set_entry_address (p.first);
        cfgEntry->set_entry_name (p.second);
    }
}

bool CFGWriter::isExternal (Address addr) const
{
    if (m_codeObj.cs ()->linkage ().find (addr) != m_codeObj.cs ()->linkage ().end ())
    {
        return m_extFuncMgr.isExternal (m_codeObj.cs ()->linkage () [addr]);
    }
}

const std::string& CFGWriter::getExternalName (Address addr) const
{
    return m_codeObj.cs ()->linkage ().at (addr);
}

bool CFGWriter::tryEval (InstructionAPI::Expression *expr,
                         const Address ip, Address& result) const
{
    if (expr->eval ().format () != "[empty]")
    {
        result = expr->eval ().convert<Address> ();
        return true;
    }

    if (auto bin = dynamic_cast<InstructionAPI::BinaryFunction *> (expr))
    {
        std::vector<InstructionAPI::InstructionAST::Ptr> args;
        bin->getChildren (args);

        Address left, right;

        if (tryEval (dynamic_cast<InstructionAPI::Expression *> (args [0].get ()), ip, left)
            && tryEval (dynamic_cast<InstructionAPI::Expression *> (args [1].get ()), ip, right))
        {
            if (bin->isAdd ())
            {
                result = left + right;
                return true;
            }
            else if (bin->isMultiply ())
            {
                result = left * right;
                return true;
            }

            return false;
        }
    }
    else if (auto reg = dynamic_cast<InstructionAPI::RegisterAST *> (expr))
    {
        if (reg->format () == "RIP")
        {
            result = ip;
            return true;
        }
    }

    return false;
}
