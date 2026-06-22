// Scylla — Ghidra Version Tracking de-risk spike (DD-042 candidate).
//
// Question: can a STANDALONE program drive Ghidra's Version Tracking (VT) API headlessly to match
// functions between two programs, and does it crack the cases the Scylla four-pass matcher can't —
// the symmetric arithmetic leaves (cross-opt) and cross-architecture? VT is the heavy lever; this
// proves whether it's worth a multi-PR integration BEFORE betting the build (the warm-engine pattern).
//
// It imports + analyzes a source and a destination binary in-process (like the warm worker), creates
// a VTSession, runs the STRUCTURAL correlators (exact instructions/mnemonics, then the combined
// function+data reference correlator that propagates from those seeds), and prints each function
// match as src-name -> dst-name (so we can read off correct vs wrong vs missing against the
// committed ground-truth symbols). We deliberately AVOID the SymbolName correlator — it would
// trivially match by name on our unstripped corpus and tell us nothing about stripped-binary reality.
//
// Usage: ScyllaVtSpike <sourceBinary> <destBinary>
import java.io.File;
import java.util.Collection;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.feature.vt.api.correlator.program.CombinedFunctionAndDataReferenceProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.ExactMatchMnemonicsProgramCorrelatorFactory;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class ScyllaVtSpike {

    private static final Object CONSUMER = new Object();

    public static void main(String[] args) throws Exception {
        ghidra.framework.Application.initializeApplication(
                new ghidra.GhidraApplicationLayout(),
                new ghidra.framework.HeadlessGhidraApplicationConfiguration());

        LoadResults<Program> srcLr = analyze(args[0]);
        LoadResults<Program> dstLr = analyze(args[1]);
        Program src = srcLr.getPrimaryDomainObject();
        Program dst = dstLr.getPrimaryDomainObject();
        System.out.println("[vt] source=" + args[0] + "  dest=" + args[1]);

        VTSessionDB session = new VTSessionDB("scylla-vt", src, dst, CONSUMER);
        try {
            // The EXACT correlators first — and ACCEPT their matches, because the reference
            // correlator only propagates from ACCEPTED associations (the GUI workflow, automated).
            VTAbstractProgramCorrelatorFactory[] exact = {
                    new ExactMatchInstructionsProgramCorrelatorFactory(),
                    new ExactMatchMnemonicsProgramCorrelatorFactory(),
            };
            for (VTAbstractProgramCorrelatorFactory f : exact) {
                VTMatchSet ms = correlate(session, f, src, dst);
                report(f.getName(), ms, src, dst);
                acceptAll(session, ms);
            }
            // Now the reference correlator, SEEDED by the accepted exact matches — VT's propagation,
            // the steelman of "but VT spreads matches through the reference graph".
            VTMatchSet ref = correlate(session,
                    new CombinedFunctionAndDataReferenceProgramCorrelatorFactory(), src, dst);
            report("Combined Function and Data Reference (seeded)", ref, src, dst);
        } finally {
            srcLr.close();
            dstLr.close();
        }
    }

    private static VTMatchSet correlate(VTSessionDB session,
            VTAbstractProgramCorrelatorFactory f, Program src, Program dst) throws Exception {
        VTProgramCorrelator c = f.createCorrelator(src, src.getMemory(), dst, dst.getMemory(), null);
        int tx = session.startTransaction("correlate " + f.getName());
        try {
            return c.correlate(session, TaskMonitor.DUMMY);
        } finally {
            session.endTransaction(tx, true);
        }
    }

    /** Accept every match in {@code ms} so the reference correlator will propagate from it. */
    private static void acceptAll(VTSessionDB session, VTMatchSet ms) {
        int tx = session.startTransaction("accept");
        try {
            for (VTMatch m : ms.getMatches()) {
                try {
                    m.getAssociation().setAccepted();
                } catch (Exception ignored) {
                    // a competing association may block this one — fine, skip it
                }
            }
        } finally {
            session.endTransaction(tx, true);
        }
    }

    private static void report(String correlator, VTMatchSet ms, Program src, Program dst) {
        Collection<VTMatch> matches = ms.getMatches();
        int func = 0, correct = 0, wrong = 0;
        StringBuilder detail = new StringBuilder();
        for (VTMatch m : matches) {
            VTAssociation a = m.getAssociation();
            Function sf = src.getFunctionManager().getFunctionAt(a.getSourceAddress());
            Function df = dst.getFunctionManager().getFunctionAt(a.getDestinationAddress());
            if (sf == null || df == null) {
                continue; // data match, not a function — ignore for this spike
            }
            func++;
            boolean ok = sf.getName().equals(df.getName());
            if (ok) {
                correct++;
            } else {
                wrong++;
            }
            // only print the interesting (user) functions, not the CRT/runtime noise
            String n = sf.getName();
            if (n.equals("main") || n.equals("gcd") || n.equals("fib") || n.equals("factorial")
                    || n.equals("sum_to") || n.equals("lcm") || n.startsWith("my_")
                    || n.equals("count_vowels")) {
                detail.append("      ").append(n).append(" -> ").append(df.getName())
                        .append(ok ? "" : "   <-- WRONG").append('\n');
            }
        }
        System.out.println("[vt] " + correlator + ": " + func + " function matches ("
                + correct + " name-correct, " + wrong + " name-mismatch)");
        if (detail.length() > 0) {
            System.out.print(detail);
        }
    }

    private static LoadResults<Program> analyze(String binPath) throws Exception {
        LoadResults<Program> lr = ProgramLoader.builder()
                .source(new File(binPath)).project(null)
                .log(new MessageLog()).monitor(TaskMonitor.DUMMY).load();
        Program p = lr.getPrimaryDomainObject();
        int tx = p.startTransaction("analyze");
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(TaskMonitor.DUMMY);
            ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(p);
        } finally {
            p.endTransaction(tx, true);
        }
        return lr;
    }
}
