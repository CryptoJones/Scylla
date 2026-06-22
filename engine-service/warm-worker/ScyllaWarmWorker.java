// Scylla WARM ENGINE worker (DD-040). A STANDALONE Java program — NOT a Ghidra script, so it can
// use the full ghidra.app.util.importer / ghidra.app.plugin.core.analysis API (the OSGi script
// compiler can't). The engine-service compiles this at run time against the mounted GayHydra dist
// and runs it as ONE resident subprocess: Ghidra's application + SLEIGH + decompiler init once,
// then a serve loop imports + analyzes + dumps each requested binary IN THE WARM JVM, so only the
// first call pays the cold init (~6s host) and the rest are ~2s.
//
// The EXTRACTION (program -> snapshot JSON) lives in ScyllaModel, SHARED with the cold-path Ghidra
// script dump_model.java (DD-041) so the two producers can never drift — the engine-service compiles
// ScyllaModel alongside this worker. Only the import+analyze step (the part the OSGi script compiler
// can't do) lives here.
//
// Protocol (line-oriented): the driver writes "<binPath>\t<outPath>" lines on stdin; the worker
// writes the model JSON to <outPath> and prints "SCYLLA-OK\t<outPath>" (or "SCYLLA-ERR\t<msg>") on
// stdout. "SCYLLA-READY" is printed once the engine is warm. EOF or a "QUIT" line stops it. One
// binary at a time — Ghidra analysis is not thread-safe per program.
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

    /** Import + analyze `binPath` in the warm JVM and write the model JSON (via the shared
     *  ScyllaModel extraction) to `outPath`. */
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
            String json = ScyllaModel.toJson(program, TaskMonitor.DUMMY);
            try (FileWriter w = new FileWriter(outPath)) {
                w.write(json);
            }
        } finally {
            lr.close(); // release the transient program — keep the JVM warm, not leaking
        }
    }

    private static void emit(String s) {
        System.out.println(s);
        System.out.flush();
    }
}
