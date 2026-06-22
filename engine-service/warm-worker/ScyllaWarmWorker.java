// Scylla WARM ENGINE worker (DD-040). A STANDALONE Java program — NOT a Ghidra script, so it can
// use the full ghidra.app.util.importer / ghidra.app.plugin.core.analysis API (the OSGi script
// compiler can't). The engine-service compiles this at run time against the mounted GayHydra dist
// and runs it as ONE resident subprocess: Ghidra's application + SLEIGH + decompiler init once,
// then a serve loop imports + analyzes + dumps each requested binary IN THE WARM JVM, so only the
// first call pays the cold init (~6s host) and the rest are ~2s.
//
// Protocol (line-oriented): the driver writes "<binPath>\t<outPath>" lines on stdin; the worker
// writes a normalized model JSON to <outPath> and prints "SCYLLA-OK\t<outPath>" (or
// "SCYLLA-ERR\t<msg>") on stdout. "SCYLLA-READY" is printed once the engine is warm. EOF or a
// "QUIT" line stops it. One binary at a time — Ghidra analysis is not thread-safe per program.
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
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
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;

public final class ScyllaWarmWorker {

    public static void main(String[] args) throws Exception {
        ghidra.framework.Application.initializeApplication(
                new ghidra.GhidraApplicationLayout(),
                new ghidra.framework.HeadlessGhidraApplicationConfiguration());
        emit("SCYLLA-READY"); // the engine is warm; the first request is now ~2s, not ~6s

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || "QUIT".equals(line)) {
                break;
            }
            String[] p = line.split("\t", 2);
            if (p.length != 2) {
                emit("SCYLLA-ERR\tbad request");
                continue;
            }
            try {
                materialize(p[0], p[1]);
                emit("SCYLLA-OK\t" + p[1]);
            } catch (Throwable t) {
                emit("SCYLLA-ERR\t" + t);
            }
        }
    }

    /** Import + analyze `binPath` in the warm JVM and write the model JSON to `outPath`. */
    private static void materialize(String binPath, String outPath) throws Exception {
        LoadResults<Program> lr = ProgramLoader.builder()
                .source(new File(binPath))
                .project(null) // transient — never persisted
                .log(new MessageLog())
                .monitor(TaskMonitor.DUMMY)
                .load();
        try {
            Program program = lr.getPrimaryDomainObject();
            int tx = program.startTransaction("scylla-analyze");
            try {
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                mgr.initializeOptions();
                mgr.reAnalyzeAll(null);
                mgr.startAnalysis(TaskMonitor.DUMMY); // blocks until analysis completes
                GhidraProgramUtilities.markProgramAnalyzed(program);
            } finally {
                program.endTransaction(tx, true);
            }
            dump(program, outPath);
        } finally {
            lr.close(); // release the transient program — keep the JVM warm, not leaking
        }
    }

    /** Write the normalized model JSON for `program` to `outPath` (same shape as dump_model.java). */
    private static void dump(Program program, String outPath) throws Exception {
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
            // Arch-INDEPENDENT features (DD-041): same as dump_model.java — referenced string literals
            // and imported call NAMES survive a cross-ISA recompile where mnemonics/addresses don't.
            TreeSet<String> imports = new TreeSet<>();
            TreeSet<String> stringRefs = new TreeSet<>();
            InstructionIterator iit = listing.getInstructions(f.getBody(), true);
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                mnems.add(ins.getMnemonicString());
                for (var ref : ins.getReferencesFrom()) {
                    if (ref.getReferenceType().isCall()) {
                        Function tgt = fm.getFunctionAt(ref.getToAddress());
                        if (tgt != null) {
                            if (tgt.isExternal() || tgt.isThunk()) {
                                imports.add(tgt.getName());
                            } else {
                                callees.add(tgt.getEntryPoint().toString());
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
            CodeBlockIterator cbi = bbm.getCodeBlocksContaining(f.getBody(), TaskMonitor.DUMMY);
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

        try (FileWriter w = new FileWriter(outPath)) {
            w.write(sb.toString());
        }
    }

    private static void emit(String s) {
        System.out.println(s);
        System.out.flush();
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
