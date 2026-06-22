/* Scylla — the model-snapshot EXTRACTION, shared by both producers (DD-041 consolidation).
 *
 * The single source of truth for "a Ghidra Program -> the normalized Scylla snapshot JSON":
 *   - dump_model.java (a Ghidra SCRIPT) calls it on the cold / offline path (analyzeHeadless).
 *   - ScyllaWarmWorker.java (a STANDALONE program) calls it on the warm in-process path.
 * Both are in the default package, so they reference it directly with no import.
 *
 * It uses ONLY ghidra.program.model.* / ghidra.program.model.block.* / ghidra.util.task.TaskMonitor
 * — the public model API that a GhidraScript may import, NOT the ghidra.app.util.importer /
 * analysis classes the OSGi script compiler cannot see. That is exactly why this can be shared:
 * the import+analyze step (which the OSGi compiler chokes on) stays in each producer; only the
 * encoding lives here, and the encoding touches none of the forbidden classes.
 */
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public final class ScyllaModel {

    private ScyllaModel() {}

    /** Build the normalized snapshot JSON for {@code program}. {@code monitor} drives the basic-block
     *  model iteration ({@code TaskMonitor.DUMMY} is fine off the GUI). */
    public static String toJson(Program program, TaskMonitor monitor) throws Exception {
        FunctionManager fm = program.getFunctionManager();
        Listing listing = program.getListing();
        BasicBlockModel bbm = new BasicBlockModel(program);

        List<String> funcJson = new ArrayList<>();
        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }

            List<String> mnems = new ArrayList<>();
            TreeSet<String> callees = new TreeSet<>();
            // Arch-INDEPENDENT features (DD-041): the same function compiled for x86-64 vs aarch64
            // shares neither mnemonics nor addresses, but it references the SAME string literals and
            // calls the SAME imported symbols by NAME — the cross-architecture re-anchoring signal.
            TreeSet<String> imports = new TreeSet<>();
            TreeSet<String> stringRefs = new TreeSet<>();
            // Callee NAMES that are PACKAGE-QUALIFIED (contain a '.', e.g. Go's fmt.Fprintf /
            // main.fib / runtime.convT64). These are the Go cross-architecture lever (DD-043): Go
            // keeps fully-qualified function names in .gopclntab even when STRIPPED, and the set is
            // identical across ISAs. The dotted filter is the point — it captures Go's names (which
            // survive stripping) and naturally EXCLUDES C's bare local names (gcd, fib), which do NOT
            // survive stripping, so the unstripped-C corpus can't "cheat" via names a real target
            // lacks. C library calls already ride `imports`; bare C names contribute nothing here.
            TreeSet<String> calleeNames = new TreeSet<>();
            InstructionIterator iit = listing.getInstructions(f.getBody(), true);
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                mnems.add(ins.getMnemonicString());
                for (Reference ref : ins.getReferencesFrom()) {
                    if (ref.getReferenceType().isCall()) {
                        Function tgt = fm.getFunctionAt(ref.getToAddress());
                        if (tgt != null) {
                            if (tgt.isExternal() || tgt.isThunk()) {
                                // an imported/library call, keyed by NAME (identical across ISAs)
                                imports.add(tgt.getName());
                            } else {
                                callees.add(tgt.getEntryPoint().toString());
                            }
                            // Go package-qualified name: contains '.', but NOT a compiler artifact —
                            // exclude leading '_' (C/i386 PIC thunks like __x86.get_pc_thunk.bx, Go's
                            // arch-tagged _rt0_* entry stubs) and C++ '::' scopes (operator.delete).
                            // What's left is Go's importpath.Func form, which survives pclntab stripping.
                            String nm = tgt.getName();
                            if (nm.indexOf('.') >= 0 && !nm.startsWith("_")
                                    && !nm.startsWith("FUN_") && !nm.contains("::")) {
                                calleeNames.add(nm);
                            }
                        }
                    } else if (ref.getReferenceType().isData()) {
                        Data d = listing.getDataAt(ref.getToAddress());
                        if (d != null && d.hasStringValue()) {
                            Object v = d.getValue();
                            if (v != null) {
                                stringRefs.add(v.toString());
                            }
                        }
                    }
                }
            }

            int bb = 0;
            CodeBlockIterator cbi = bbm.getCodeBlocksContaining(f.getBody(), monitor);
            while (cbi.hasNext()) {
                cbi.next();
                bb++;
            }

            StringBuilder fj = new StringBuilder();
            fj.append("    {");
            fj.append("\"entry\": ").append(jstr(f.getEntryPoint().toString())).append(", ");
            fj.append("\"name\": ").append(jstr(f.getName())).append(", ");
            fj.append("\"size\": ").append(f.getBody().getNumAddresses()).append(", ");
            fj.append("\"bb_count\": ").append(bb).append(", ");
            fj.append("\"mnemonic_count\": ").append(mnems.size()).append(", ");
            fj.append("\"callees\": ").append(jarr(new ArrayList<>(callees))).append(", ");
            fj.append("\"imports\": ").append(jarr(new ArrayList<>(imports))).append(", ");
            fj.append("\"string_refs\": ").append(jarr(new ArrayList<>(stringRefs))).append(", ");
            fj.append("\"callee_names\": ").append(jarr(new ArrayList<>(calleeNames))).append(", ");
            fj.append("\"mnemonics\": ").append(jarr(mnems));
            fj.append("}");
            funcJson.add(fj.toString());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"program\": ").append(jstr(program.getName())).append(",\n");
        sb.append("  \"language\": ").append(jstr(program.getLanguageID().toString())).append(",\n");
        sb.append("  \"function_count\": ").append(funcJson.size()).append(",\n");
        sb.append("  \"functions\": [\n");
        sb.append(String.join(",\n", funcJson));
        sb.append("\n  ]\n}\n");
        return sb.toString();
    }

    static String jstr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c == '\n') {
                b.append("\\n");
            } else if (c == '\t') {
                b.append("\\t");
            } else if (c < 0x20) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.append("\"").toString();
    }

    static String jarr(List<String> xs) {
        List<String> q = new ArrayList<>();
        for (String x : xs) {
            q.add(jstr(x));
        }
        return "[" + String.join(", ", q) + "]";
    }
}
