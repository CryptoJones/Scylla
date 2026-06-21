/* Scylla prototype — model-snapshot dumper (Java GhidraScript).
 * Runs in GayHydra/Ghidra headless with no PyGhidra needed:
 *   analyzeHeadless ... -postScript dump_model.java <out.json>
 * Emits a normalized JSON snapshot (functions, call edges, BB counts, mnemonic
 * fingerprints) — the v1/v2 inputs the re-anchoring spike matches against.
 * @category Scylla
 */
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

public class dump_model extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "/tmp/snapshot.json";

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);

        List<String> funcJson = new ArrayList<>();
        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }

            List<String> mnems = new ArrayList<>();
            TreeSet<String> callees = new TreeSet<>();
            InstructionIterator iit = listing.getInstructions(f.getBody(), true);
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                mnems.add(ins.getMnemonicString());
                for (Reference ref : ins.getReferencesFrom()) {
                    if (ref.getReferenceType().isCall()) {
                        Function tgt = fm.getFunctionAt(ref.getToAddress());
                        if (tgt != null) {
                            callees.add(tgt.getEntryPoint().toString());
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
            fj.append("\"mnemonics\": ").append(jarr(mnems));
            fj.append("}");
            funcJson.add(fj.toString());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"program\": ").append(jstr(currentProgram.getName())).append(",\n");
        sb.append("  \"language\": ").append(jstr(currentProgram.getLanguageID().toString())).append(",\n");
        sb.append("  \"function_count\": ").append(funcJson.size()).append(",\n");
        sb.append("  \"functions\": [\n");
        sb.append(String.join(",\n", funcJson));
        sb.append("\n  ]\n}\n");

        FileWriter w = new FileWriter(outPath);
        w.write(sb.toString());
        w.close();
        println("Scylla: wrote snapshot with " + funcJson.size() + " functions to " + outPath);
    }

    private static String jstr(String s) {
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

    private static String jarr(List<String> xs) {
        List<String> q = new ArrayList<>();
        for (String x : xs) {
            q.add(jstr(x));
        }
        return "[" + String.join(", ", q) + "]";
    }
}
