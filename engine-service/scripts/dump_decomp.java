/* Scylla — on-demand decompilation dumper (Java GhidraScript), the COLD path of the engine-service
 * `Decompile` RPC. Runs in the engine dist's headless analyzer:
 *   analyzeHeadless ... -postScript dump_decomp.java <out.json> [entries-csv] [name-filter]
 *
 * <entries-csv> is a comma-separated list of hex entry addresses; <name-filter> keeps only
 * functions whose qualified name contains it. Either may be the sentinel "-" (or absent) for
 * "none" — the headless launcher's argv is not a safe place for an empty string.
 *
 * The extraction itself lives in ScyllaDecomp (same scriptPath dir), SHARED with the warm
 * in-process worker so the cold and warm producers can never drift. This script only supplies
 * `currentProgram` + the monitor and writes the file — a thin headless adapter, like dump_model.
 * @category Scylla
 */
import java.io.FileWriter;

import ghidra.app.script.GhidraScript;

public class dump_decomp extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "/tmp/decomp.json";
        String entriesArg = (args.length > 1 && !"-".equals(args[1])) ? args[1] : "";
        String filter = (args.length > 2 && !"-".equals(args[2])) ? args[2] : "";
        long[] entries = ScyllaDecomp.parseEntries(entriesArg);

        String json = ScyllaDecomp.toJson(currentProgram, monitor, entries, filter);
        try (FileWriter w = new FileWriter(outPath)) {
            w.write(json);
        }
        println("Scylla: wrote decompilation to " + outPath);
    }
}
