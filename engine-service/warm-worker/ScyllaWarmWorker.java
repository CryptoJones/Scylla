// Scylla WARM ENGINE worker (DD-040). A STANDALONE Java program — NOT a Ghidra script, so it can
// use the full ghidra.app.util.importer / ghidra.app.plugin.core.analysis API (the OSGi script
// compiler can't). The engine-service compiles this at run time against the mounted engine dist (GHIDRA_DIST)
// and runs it as ONE resident subprocess: Ghidra's application + SLEIGH + decompiler init once,
// then a serve loop imports + analyzes + dumps each requested binary IN THE WARM JVM, so only the
// first call pays the cold init (~6s host) and the rest are ~2s.
//
// The EXTRACTIONS (program -> snapshot JSON, program -> decompile JSON) live in ScyllaModel and
// ScyllaDecomp, SHARED with the cold-path Ghidra scripts dump_model.java / dump_decomp.java (DD-041)
// so the two producers can never drift — the engine-service compiles both alongside this worker.
// Only the import+analyze step (the part the OSGi script compiler can't do) lives here.
//
// Protocol (line-oriented, tab-separated). The driver writes one request per line on stdin:
//   "<binPath>\t<outPath>"                               materialize: the model snapshot JSON
//   "DECOMP\t<binPath>\t<outPath>\t<entries-csv>\t<filter>" decompile: the decompile JSON
//     (entries-csv = hex entry addresses, "" = all; filter = qualified-name substring, "" = none)
// The worker writes the JSON to <outPath> and prints "SCYLLA-OK\t<outPath>" (or
// "SCYLLA-ERR\t<msg>") on stdout. "SCYLLA-READY" is printed once the engine is warm. EOF or a
// "QUIT" line stops it. One binary at a time — Ghidra analysis is not thread-safe per program.
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
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
            // Strip only a stray CR — NOT trim(): a DECOMP request with an empty entries list and
            // an empty filter ends in two empty tab fields, and trim() would eat them (seen live:
            // every C-binary decompile came back "bad request" and fell back to cold).
            line = line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
            if (line.isBlank() || "QUIT".equals(line.strip())) {
                break;
            }
            // -1: keep trailing empty fields (an empty entries list / filter is a legal request).
            String[] p = line.split("\t", -1);
            try {
                if (p.length == 2) {
                    materialize(p[0], p[1]);
                    emit("SCYLLA-OK\t" + p[1]);
                } else if (p.length == 5 && "DECOMP".equals(p[0])) {
                    decompile(p[1], p[2], ScyllaDecomp.parseEntries(p[3]), p[4]);
                    emit("SCYLLA-OK\t" + p[2]);
                } else {
                    emit("SCYLLA-ERR\tbad request");
                }
            } catch (Throwable t) {
                emit("SCYLLA-ERR\t" + t);
            }
        }
    }

    /** What to do with a freshly imported + analyzed program (its lifetime is the call). */
    private interface ProgramAction {
        void run(Program program) throws Exception;
    }

    /** Import + analyze `binPath` in the warm JVM, hand the analyzed program to `action`, then
     *  release it — the JVM stays warm, nothing leaks, nothing persists (transient project). */
    private static void withProgram(String binPath, ProgramAction action) throws Exception {
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
            action.run(program);
        } finally {
            lr.close(); // release the transient program — keep the JVM warm, not leaking
        }
    }

    /** Import + analyze `binPath` and write the model JSON (via the shared ScyllaModel extraction)
     *  to `outPath`. */
    private static void materialize(String binPath, String outPath) throws Exception {
        withProgram(binPath, program -> {
            // DD-044: compute each function's BSim feature vector (decompiler/BSim API — fine here in
            // the standalone worker, which the OSGi-shared ScyllaModel cannot use) and hand it to the
            // shared serializer. ScyllaBsim is compiled alongside this worker + ScyllaModel.
            java.util.Map<String, int[][]> bsim = ScyllaBsim.vectors(program);
            write(outPath, ScyllaModel.toJson(program, TaskMonitor.DUMMY, bsim));
        });
    }

    /** Import + analyze `binPath` and write the decompile JSON (via the shared ScyllaDecomp
     *  extraction) for the selected functions to `outPath`. */
    private static void decompile(String binPath, String outPath, long[] entries, String filter)
            throws Exception {
        withProgram(binPath, program ->
                write(outPath, ScyllaDecomp.toJson(program, TaskMonitor.DUMMY, entries, filter)));
    }

    private static void write(String outPath, String json) throws Exception {
        try (FileWriter w = new FileWriter(outPath)) {
            w.write(json);
        }
    }

    private static void emit(String s) {
        System.out.println(s);
        System.out.flush();
    }
}
