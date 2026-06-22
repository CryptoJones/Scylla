// Scylla — BSim feature-vector EXTRACTOR (DD-044). A STANDALONE helper (default package), NOT a
// Ghidra script and deliberately NOT part of the OSGi-shared ScyllaModel: it uses
// ghidra.app.decompiler.* + ghidra.features.bsim.* + generic.lsh.vector.*, which the OSGi script
// compiler cannot see. So — exactly like the import+analyze step — the BSim COMPUTATION lives with
// the warm worker (compiled against the full mounted dist), while ScyllaModel only SERIALIZES the
// vector it is handed. The cold dump_model.java path calls the 2-arg ScyllaModel.toJson and so emits
// no BSim vector (degrades cleanly; the cross-arch BSim re-anchoring pass simply doesn't fire there).
//
// It walks the decompiler signature path Ghidra's own CompareBSimSignaturesScript uses
// (WeightedLSHCosineVectorFactory + the weights for the program's language + DecompInterface
// .generateSignatures -> buildVector), then returns each function's LSH vector as (feature_hash,
// f32-coeff-bits) pairs keyed by entry-point string. A weighted cosine over these reproduces
// Ghidra's LSHVector.compare exactly, because the producer bakes BSim's feature weights into the
// coefficients — which is what the Rust matcher's Pass 4 (DD-044, slice 1) relies on.
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import generic.jar.ResourceFile;
import generic.lsh.vector.HashEntry;
import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public final class ScyllaBsim {

    private ScyllaBsim() {}

    /** Per-function BSim LSH vector as (hash, f32-coeff-bits) pairs, keyed by entry-point string.
     *  Best-effort: any function whose signature can't be generated is simply omitted (→ that
     *  function carries no BSim signal, the matcher pass just won't fire for it). Never throws past
     *  the decompiler open failure, which yields an empty map (clean degrade). */
    public static Map<String, int[][]> vectors(Program program) throws Exception {
        Map<String, int[][]> out = new HashMap<>();

        // The same factory + weights setup as CompareBSimSignaturesScript: pick the weights file for
        // the program's language, parse it into a WeightedLSHCosineVectorFactory.
        LanguageID id = program.getLanguageID();
        LSHVectorFactory factory = new WeightedLSHCosineVectorFactory();
        ResourceFile weightsFile = GenSignatures.getWeightsFile(id, id);
        try (InputStream input = weightsFile.getInputStream()) {
            XmlPullParser parser = new NonThreadedXmlPullParserImpl(
                    input, "Vector weights parser", SpecXmlUtils.getXmlHandler(), false);
            factory.readWeights(parser);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleSyntaxTree(false);
            decompiler.setSignatureSettings(factory.getSettings());
            if (!decompiler.openProgram(program)) {
                return out; // no decompiler -> no BSim signal; degrade to empty
            }
            FunctionIterator fit = program.getFunctionManager().getFunctions(true);
            while (fit.hasNext()) {
                Function f = fit.next();
                if (f.isExternal() || f.isThunk()) {
                    continue; // same filter as ScyllaModel — external/thunk aren't user code
                }
                SignatureResult sig = decompiler.generateSignatures(f, false, 10, TaskMonitor.DUMMY);
                if (sig == null || sig.features == null) {
                    continue;
                }
                LSHVector vec = factory.buildVector(sig.features);
                HashEntry[] entries = vec.getEntries();
                int[][] pairs = new int[entries.length][2];
                for (int i = 0; i < entries.length; i++) {
                    pairs[i][0] = entries[i].getHash();
                    // f32 bits of the coefficient — kept integral so the model stays exact/Eq.
                    pairs[i][1] = Float.floatToIntBits((float) entries[i].getCoeff());
                }
                out.put(f.getEntryPoint().toString(), pairs);
            }
        } finally {
            decompiler.closeProgram();
            decompiler.dispose();
        }
        return out;
    }
}
