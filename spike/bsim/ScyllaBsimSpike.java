// Scylla — BSim de-risk spike (DD-044 candidate).
//
// Question: BSim is the last un-de-risked cross-arch lever for the functions the Scylla four-pass
// matcher CANNOT re-anchor — the symmetric arithmetic *leaves* (gcd/factorial/sum_to). They have no
// string_refs, no imports, no callee_names, mnemonic cosine ~0 across ISAs, and (being leaves)
// nothing for call-graph propagation to lever from. BSim's premise is LSH over the DECOMPILER's
// p-code feature vectors, which are meant to abstract the ISA — so gcd.x86-64 and gcd.aarch64 should
// land near each other. This proves whether that holds BEFORE betting a multi-PR integration (the
// warm-engine / VT-spike pattern).
//
// It analyzes a source and a destination binary in-process (like the VT spike + warm worker), builds
// each user function's BSim LSH vector via the decompiler signature path (exactly as Ghidra's own
// CompareBSimSignaturesScript does — WeightedLSHCosineVectorFactory + the 64-bit cross-arch weights
// from GenSignatures.getWeightsFile(srcLang, dstLang)), then prints the full cross-arch
// similarity/significance MATRIX and reads off, for each source function, whether its best match is
// its true twin. The honesty test is sharp here: factorial (`r *= i`) and sum_to (`s += i`) differ
// by one p-code opcode (INT_MULT vs INT_ADD), so WRONG=0 demands BSim keep them apart while still
// matching each to its own cross-arch self. We compare by SYMBOL NAME on the unstripped corpus as
// ground truth (never use names as a matching signal — same discipline as the VT spike).
//
// Usage: ScyllaBsimSpike <sourceBinary> <destBinary>
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import generic.jar.ResourceFile;
import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.VectorCompare;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public final class ScyllaBsimSpike {

    private static final Object CONSUMER = new Object();

    // The user functions in mathlib.c — ground truth by symbol on the unstripped corpus.
    // gcd is distinctive (modulo while-loop); fib is recursive; factorial and sum_to are the
    // near-identical symmetric pair (one p-code opcode apart). main is the anchored caller.
    private static final String[] FUNCS = {"main", "gcd", "fib", "factorial", "sum_to"};

    // BSim's default match floor (Ghidra's CompareExecutablesScript uses sim>=0.7). The thresholded
    // verdict below gates on this AND reciprocal-best-match (Scylla pass-3) — never raw argmax —
    // which is what a WRONG=0 integration must do. The matrix is printed UNTHRESHOLDED so the raw
    // cross-arch signal (incl. the sub-threshold gcd self-similarity) stays visible.
    private static final double SIM_THRESHOLD = 0.7;

    /** A candidate match: the dest/source function name and its cosine similarity. */
    private record Match(String name, double sim) {}

    public static void main(String[] args) throws Exception {
        ghidra.framework.Application.initializeApplication(
                new ghidra.GhidraApplicationLayout(),
                new ghidra.framework.HeadlessGhidraApplicationConfiguration());

        LoadResults<Program> srcLr = analyze(args[0]);
        LoadResults<Program> dstLr = analyze(args[1]);
        Program src = srcLr.getPrimaryDomainObject();
        Program dst = dstLr.getPrimaryDomainObject();
        System.out.println("[bsim] source=" + args[0] + " (" + src.getLanguageID() + ")");
        System.out.println("[bsim] dest=  " + args[1] + " (" + dst.getLanguageID() + ")");

        try {
            // ONE factory + the cross-arch (src,dst) weights — getWeightsFile takes both langs
            // precisely so a 64-bit-vs-64-bit pair resolves to the shared lshweights_64 template.
            LSHVectorFactory factory = buildFactory(src.getLanguageID(), dst.getLanguageID());
            System.out.println("[bsim] weights = lshweights for (" + src.getLanguageID() + ", "
                    + dst.getLanguageID() + ")");

            Map<String, LSHVector> srcVecs = vectors(src, factory);
            Map<String, LSHVector> dstVecs = vectors(dst, factory);

            printMatrix(srcVecs, dstVecs, factory);
            verdict(srcVecs, dstVecs, factory);
        } finally {
            srcLr.close();
            dstLr.close();
        }
    }

    /** Build the BSim LSH vector for each target user function (decompiler signature path). */
    private static Map<String, LSHVector> vectors(Program program, LSHVectorFactory factory) {
        Map<String, LSHVector> out = new LinkedHashMap<>();
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleSyntaxTree(false);
            decompiler.setSignatureSettings(factory.getSettings());
            if (!decompiler.openProgram(program)) {
                System.out.println("[bsim] WARN cannot open decompiler for " + program.getName()
                        + ": " + decompiler.getLastMessage());
                return out;
            }
            for (String name : FUNCS) {
                Function f = firstFunctionNamed(program, name);
                if (f == null) {
                    System.out.println("[bsim] WARN " + program.getName() + " has no function '"
                            + name + "'");
                    continue;
                }
                SignatureResult sig = decompiler.generateSignatures(f, false, 10, TaskMonitor.DUMMY);
                if (sig == null || sig.features == null) {
                    System.out.println("[bsim] WARN no signature for " + name);
                    continue;
                }
                out.put(name, factory.buildVector(sig.features));
            }
        } finally {
            decompiler.closeProgram();
            decompiler.dispose();
        }
        return out;
    }

    private static Function firstFunctionNamed(Program program, String name) {
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    private static double similarity(LSHVector a, LSHVector b) {
        return a.compare(b, new VectorCompare());
    }

    /** Print the full src x dst cosine-similarity matrix; the diagonal is the true cross-arch twin. */
    private static void printMatrix(Map<String, LSHVector> srcVecs, Map<String, LSHVector> dstVecs,
            LSHVectorFactory factory) {
        List<String> cols = new ArrayList<>(dstVecs.keySet());
        System.out.println();
        System.out.println("[bsim] cross-arch similarity matrix (rows=source, cols=dest):");
        StringBuilder header = new StringBuilder(String.format("%-12s", "src\\dst"));
        for (String c : cols) {
            header.append(String.format("%10s", c));
        }
        System.out.println("[bsim] " + header);
        for (Map.Entry<String, LSHVector> r : srcVecs.entrySet()) {
            StringBuilder row = new StringBuilder(String.format("%-12s", r.getKey()));
            for (String c : cols) {
                double sim = similarity(r.getValue(), dstVecs.get(c));
                String cell = String.format("%10.3f", sim);
                if (c.equals(r.getKey())) {
                    cell = String.format("%9.3f*", sim); // mark the true twin
                }
                row.append(cell);
            }
            System.out.println("[bsim] " + row);
        }
        System.out.println("[bsim] (* = true cross-arch twin; significance reported in the verdict)");
    }

    /** Best (highest-similarity) match for {@code vec} among {@code candidates}, or null if empty. */
    private static Match bestMatch(LSHVector vec, Map<String, LSHVector> candidates) {
        String name = null;
        double sim = -1.0;
        for (Map.Entry<String, LSHVector> c : candidates.entrySet()) {
            double s = similarity(vec, c.getValue());
            if (s > sim) {
                sim = s;
                name = c.getKey();
            }
        }
        return name == null ? null : new Match(name, sim);
    }

    /**
     * For each source function report its best dest match TWO ways: naive argmax (what a careless
     * integration does) and the WRONG=0-preserving gate (sim>=threshold AND reciprocal-best). gcd's
     * cross-arch self-similarity is sub-threshold, so the gate flags it (fail-closed) instead of
     * emitting the spurious gcd->factorial argmax pick.
     */
    private static void verdict(Map<String, LSHVector> srcVecs, Map<String, LSHVector> dstVecs,
            LSHVectorFactory factory) {
        System.out.println();
        System.out.println("[bsim] verdict — best dest match per source function:");
        int naiveCorrect = 0, naiveWrong = 0;
        int gateMatched = 0, gateWrong = 0, gateFlagged = 0;
        for (Map.Entry<String, LSHVector> r : srcVecs.entrySet()) {
            String srcName = r.getKey();
            Match best = bestMatch(r.getValue(), dstVecs);
            if (best == null) {
                gateFlagged++;
                continue;
            }
            double signif = signifOf(r.getValue(), dstVecs.get(best.name()), factory);
            boolean nameOk = best.name().equals(srcName);
            // reciprocal-best (Scylla pass-3): is srcName also the best SOURCE match for that dest?
            Match back = bestMatch(dstVecs.get(best.name()), srcVecs);
            boolean reciprocal = back != null && back.name().equals(srcName);
            if (nameOk) {
                naiveCorrect++;
            } else {
                naiveWrong++;
            }
            String outcome;
            if (best.sim() < SIM_THRESHOLD || !reciprocal) {
                gateFlagged++;
                outcome = "FLAGGED (fail-closed)";
            } else if (nameOk) {
                gateMatched++;
                outcome = "matched";
            } else {
                gateWrong++;
                outcome = "WRONG";
            }
            System.out.printf(
                    "[bsim]   %-10s -> best=%-10s sim=%.3f signif=%.2f recip=%-5s | %s%n",
                    srcName, best.name(), best.sim(), signif, reciprocal, outcome);
        }
        // The sharp symmetric-leaf test, called out explicitly (one p-code opcode apart).
        if (srcVecs.containsKey("factorial") && dstVecs.containsKey("sum_to")
                && dstVecs.containsKey("factorial")) {
            double fSelf = similarity(srcVecs.get("factorial"), dstVecs.get("factorial"));
            double fCross = similarity(srcVecs.get("factorial"), dstVecs.get("sum_to"));
            System.out.printf(
                    "[bsim]   SYMMETRIC-LEAF TEST: factorial->factorial=%.3f  factorial->sum_to=%.3f"
                            + "  (margin=%.3f, must be > 0)%n",
                    fSelf, fCross, fSelf - fCross);
        }
        System.out.println("[bsim] NAIVE argmax (no gate): " + naiveCorrect + " correct, "
                + naiveWrong + " WRONG");
        System.out.printf(
                "[bsim] GATED (sim>=%.2f + reciprocal-best): %d matched, %d WRONG, %d flagged"
                        + "  (WRONG must be 0)%n",
                SIM_THRESHOLD, gateMatched, gateWrong, gateFlagged);
    }

    private static double signifOf(LSHVector a, LSHVector b, LSHVectorFactory factory) {
        VectorCompare vc = new VectorCompare();
        a.compare(b, vc); // populates vc with the comparison detail
        return factory.calculateSignificance(vc);
    }

    private static LSHVectorFactory buildFactory(LanguageID srcId, LanguageID dstId)
            throws IOException {
        WeightedLSHCosineVectorFactory factory = new WeightedLSHCosineVectorFactory();
        ResourceFile weightsFile = GenSignatures.getWeightsFile(srcId, dstId);
        try (InputStream input = weightsFile.getInputStream()) {
            XmlPullParser parser = new NonThreadedXmlPullParserImpl(input, "Vector weights parser",
                    SpecXmlUtils.getXmlHandler(), false);
            factory.readWeights(parser);
        } catch (Exception e) {
            throw new IOException("failed to read BSim weights " + weightsFile, e);
        }
        return factory;
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
