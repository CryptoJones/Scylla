/* Scylla prototype — model-snapshot dumper (Java GhidraScript).
 * Runs in GayHydra/Ghidra headless with no PyGhidra needed:
 *   analyzeHeadless ... -postScript dump_model.java <out.json>
 * Emits a normalized JSON snapshot (functions, call edges, BB counts, mnemonic
 * fingerprints, arch-independent string/import sets) — the v1/v2 inputs the
 * re-anchoring matcher works against.
 *
 * The extraction itself lives in ScyllaModel (same scriptPath dir), SHARED with the warm
 * in-process worker (DD-041) so the cold and warm producers can never drift. This script only
 * supplies `currentProgram` + the monitor and writes the file — it is a thin headless adapter.
 * @category Scylla
 */
import java.io.FileWriter;

import ghidra.app.script.GhidraScript;

public class dump_model extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "/tmp/snapshot.json";

        String json = ScyllaModel.toJson(currentProgram, monitor);
        try (FileWriter w = new FileWriter(outPath)) {
            w.write(json);
        }
        println("Scylla: wrote snapshot to " + outPath);
    }
}
