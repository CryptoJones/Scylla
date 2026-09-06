/* Scylla — the on-demand DECOMPILATION extraction, shared by both producers (DD-041 pattern).
 *
 * The single source of truth for "a Ghidra Program -> the decompile JSON" behind the engine-service
 * `Decompile` RPC (the `decompile` verb, DD-017):
 *   - dump_decomp.java (a Ghidra SCRIPT) calls it on the cold path (analyzeHeadless post-script).
 *   - ScyllaWarmWorker.java (a STANDALONE program) calls it on the warm in-process path.
 * Both are in the default package, so they reference it directly with no import.
 *
 * It uses ghidra.app.decompiler.* (DecompInterface — the Java side of the proven Java<->C++
 * decompiler IPC, left exactly as-is per DD-012) plus the public ghidra.program.model.* API; both
 * are visible to the OSGi script compiler (the abtest DumpDecomp.java script proved it), which is
 * why this can be shared. The import+analyze step stays in each producer, as with ScyllaModel.
 *
 * Determinism contract: the decompiler is configured EXACTLY as the A/B baseline dumper
 * (abtest/scripts/DumpDecomp.java) configures it — default DecompileOptions, syntax tree off, a
 * 60 s per-function budget, `getDecompiledFunction().getC()` verbatim — so the `decompile` verb's
 * output is byte-comparable to the committed raw-engine decompilation baseline.
 */
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class ScyllaDecomp {

    private ScyllaDecomp() {}

    /** Per-function decompiler budget, seconds — the same 60 s the A/B baseline dumper uses. */
    static final int PER_FUNCTION_TIMEOUT_SEC = 60;

    /**
     * Decompile the selected functions of {@code program} and return the JSON document
     * {@code {"language": ..., "functions": [{entry, name, prototype, cconv, c, error}, ...]}},
     * functions in entry-address order.
     *
     * <p>Selection: every non-external, non-thunk function; narrowed to the entry offsets in
     * {@code entries} when that is non-empty; narrowed again to functions whose QUALIFIED name
     * ({@code getName(true)} — GayHydra demangles Rust into namespaces, so {@code rustmath::gcd}'s
     * bare name is just {@code gcd}) contains {@code nameFilter} when that is non-empty. A requested
     * entry with no function is reported as a record whose {@code error} says so, never silently
     * dropped — the caller asked for it by address and deserves an answer per address.
     */
    public static String toJson(Program program, TaskMonitor monitor, long[] entries,
            String nameFilter) throws Exception {
        Set<Long> wanted = new HashSet<>();
        if (entries != null) {
            for (long e : entries) {
                wanted.add(e);
            }
        }
        String filter = nameFilter == null ? "" : nameFilter;

        List<Function> funcs = new ArrayList<>();
        Set<Long> found = new HashSet<>();
        for (Function f : program.getListing().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            long off = f.getEntryPoint().getOffset();
            if (!wanted.isEmpty() && !wanted.contains(off)) {
                continue;
            }
            if (!filter.isEmpty() && !f.getName(true).contains(filter)) {
                continue;
            }
            funcs.add(f);
            found.add(off);
        }
        funcs.sort(Comparator.comparing(Function::getEntryPoint));

        List<String> out = new ArrayList<>();
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.setOptions(new DecompileOptions());
            decomp.toggleSyntaxTree(false);
            boolean open = decomp.openProgram(program);
            String openErr = open ? null : "decompiler failed to open: " + decomp.getLastMessage();
            for (Function f : funcs) {
                String c = "";
                String err = openErr;
                if (open) {
                    DecompileResults res = decomp.decompileFunction(f, PER_FUNCTION_TIMEOUT_SEC, monitor);
                    if (res != null && res.decompileCompleted()
                            && res.getDecompiledFunction() != null) {
                        c = res.getDecompiledFunction().getC();
                    } else {
                        err = res == null ? "null" : String.valueOf(res.getErrorMessage());
                    }
                }
                out.add(record(f.getEntryPoint().toString(), f.getName(true),
                        f.getPrototypeString(true, false), f.getCallingConventionName(), c, err));
            }
        } finally {
            decomp.dispose();
        }
        // Requested-but-absent entries: answered by address, in order, after the real ones.
        List<Long> missing = new ArrayList<>();
        for (long e : wanted) {
            if (!found.contains(e)) {
                missing.add(e);
            }
        }
        missing.sort(null);
        for (long e : missing) {
            out.add(record(Long.toHexString(e), "", "", "", "", "no function at entry 0x"
                    + Long.toHexString(e)));
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"language\": ").append(ScyllaModel.jstr(program.getLanguageID().toString()))
                .append(",\n");
        sb.append("  \"function_count\": ").append(out.size()).append(",\n");
        sb.append("  \"functions\": [\n");
        sb.append(String.join(",\n", out));
        sb.append("\n  ]\n}\n");
        return sb.toString();
    }

    private static String record(String entry, String name, String proto, String cconv, String c,
            String err) {
        StringBuilder fj = new StringBuilder();
        fj.append("    {");
        fj.append("\"entry\": ").append(ScyllaModel.jstr(entry)).append(", ");
        fj.append("\"name\": ").append(ScyllaModel.jstr(name)).append(", ");
        fj.append("\"prototype\": ").append(ScyllaModel.jstr(proto == null ? "" : proto)).append(", ");
        fj.append("\"cconv\": ").append(ScyllaModel.jstr(cconv == null ? "" : cconv)).append(", ");
        fj.append("\"c\": ").append(ScyllaModel.jstr(c == null ? "" : c)).append(", ");
        fj.append("\"error\": ").append(ScyllaModel.jstr(err == null ? "" : err));
        fj.append("}");
        return fj.toString();
    }

    /** Parse the comma-separated entry list the producers receive on their command line / protocol
     *  line ({@code "401156,401200"}, hex, optional {@code 0x}); empty → every function. */
    public static long[] parseEntries(String csv) {
        if (csv == null || csv.trim().isEmpty()) {
            return new long[0];
        }
        String[] parts = csv.trim().split(",");
        long[] out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String t = parts[i].trim();
            if (t.startsWith("0x") || t.startsWith("0X")) {
                t = t.substring(2);
            }
            out[i] = Long.parseUnsignedLong(t, 16);
        }
        return out;
    }
}
