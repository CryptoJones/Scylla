// Standalone warm-worker de-risk: a plain Java program (NOT a Ghidra script — so no OSGi limit on
// ghidra.app.util.importer / ghidra.app.plugin.core.analysis). Init Ghidra once, then import +
// analyze the same binary TWICE in-process to show (a) it works at all and (b) the 2nd pass is warm.
import java.io.File;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;

public final class Worker {
    public static void main(String[] args) throws Exception {
        ghidra.framework.Application.initializeApplication(
                new ghidra.GhidraApplicationLayout(),
                new ghidra.framework.HeadlessGhidraApplicationConfiguration());
        System.out.println("[worker] app initialized; analyzing " + args[0] + " twice:");
        for (int pass = 1; pass <= 2; pass++) {
            long t0 = System.nanoTime();
            LoadResults<Program> lr = ProgramLoader.builder()
                    .source(new File(args[0])).project(null)
                    .log(new MessageLog()).monitor(TaskMonitor.DUMMY).load();
            try {
                Program p = lr.getPrimaryDomainObject();
                int tx = p.startTransaction("scylla");
                try {
                    AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
                    mgr.initializeOptions();
                    mgr.reAnalyzeAll(null);
                    mgr.startAnalysis(TaskMonitor.DUMMY);
                    GhidraProgramUtilities.markProgramAnalyzed(p);
                } finally {
                    p.endTransaction(tx, true);
                }
                int n = 0;
                FunctionIterator it = p.getFunctionManager().getFunctions(true);
                while (it.hasNext()) { it.next(); n++; }
                System.out.println("[worker] pass " + pass + ": " + n + " functions in "
                        + ((System.nanoTime() - t0) / 1_000_000L) + " ms"
                        + (pass == 2 ? "  <-- WARM" : "  (cold-ish: app already up)"));
            } finally {
                lr.close();
            }
        }
    }
}
