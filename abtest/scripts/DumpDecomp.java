/* Scylla A/B harness — raw DECOMPILATION baseline dumper (Java GhidraScript).
 *
 * Runs OUTSIDE Scylla, in the engine dist's headless analyzer:
 *   analyzeHeadless <proj> abtest -import <bin> -scriptPath abtest/scripts \
 *       -postScript DumpDecomp.java <out.txt> [name-filter] -deleteProject
 *
 * Emits, per function (sorted by entry address so the file is deterministic across runs):
 *   the prototype, the calling convention, the DECOMPILED C, and the disassembly with raw P-code.
 * Scylla's model carries no decompiled C yet (the engine-service `Decompile` RPC is unimplemented),
 * so this is the OUTSIDE-ONLY leg the A/B records today: the committed baseline the `decompile`
 * verb will be A/B-tested against when it lands. The optional [name-filter] keeps runtime-heavy
 * binaries (Go, Rust: thousands of runtime/std functions) to the user code we have ground truth
 * for — e.g. `main.` for Go, `rustmath` for Rust; C/C++ dump everything.
 *
 * Adapted from CryptoJones/ghidra-difftest scripts/DumpAllLayers.java (the GayHydra-vs-upstream
 * characterization harness), trimmed to the per-function layers.
 * @category Scylla
 */
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;

public class DumpDecomp extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "/tmp/decomp.txt";
        String filter = (args.length > 1) ? args[1] : "";

        Listing listing = currentProgram.getListing();
        List<Function> funcs = new ArrayList<>();
        for (Function f : listing.getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            // Filter on the FULLY QUALIFIED name: GayHydra demangles Rust into namespaces, so
            // rustmath::gcd's bare name is just `gcd` — the namespace is where the filter must look.
            if (!filter.isEmpty() && !f.getName(true).contains(filter)) {
                continue;
            }
            funcs.add(f);
        }
        funcs.sort(Comparator.comparing(Function::getEntryPoint));

        DecompInterface decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.toggleSyntaxTree(false);
        int dumped = 0;
        try (PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(outPath)))) {
            w.println("## LANGUAGE " + currentProgram.getLanguageID() + " / "
                    + currentProgram.getCompilerSpec().getCompilerSpecID());
            w.println("## IMAGEBASE " + currentProgram.getImageBase());
            w.println("## FUNCTIONS " + funcs.size() + (filter.isEmpty() ? "" : " (filter: " + filter + ")"));
            if (!decomp.openProgram(currentProgram)) {
                w.println("## DECOMPILER FAILED TO OPEN: " + decomp.getLastMessage());
            }
            for (Function f : funcs) {
                w.println();
                w.println("==== FUNCTION " + f.getEntryPoint() + " " + f.getName(true) + " ====");
                w.println("PROTO " + f.getPrototypeString(true, false));
                w.println("CCONV " + f.getCallingConventionName());
                w.println("---- DECOMP ----");
                DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    w.print(res.getDecompiledFunction().getC());
                } else {
                    w.println("<decompile-failed: " + (res == null ? "null" : res.getErrorMessage()) + ">");
                }
                w.println("---- ASM+PCODE ----");
                InstructionIterator it = listing.getInstructions(f.getBody(), true);
                while (it.hasNext()) {
                    Instruction ins = it.next();
                    w.println(ins.getAddress() + ": " + ins.toString());
                    for (PcodeOp op : ins.getPcode()) {
                        w.println("    " + op.toString());
                    }
                }
                dumped++;
            }
        } finally {
            decomp.dispose();
        }
        println("Scylla abtest: wrote " + dumped + " functions to " + outPath);
    }
}
