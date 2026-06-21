package dev.scylla.engine;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.nio.file.Files;
import java.nio.file.Path;
import scylla.engine.v1.DecompileReply;
import scylla.engine.v1.DecompileRequest;
import scylla.engine.v1.EngineGrpc;
import scylla.engine.v1.FunctionChunk;
import scylla.engine.v1.InfoReply;
import scylla.engine.v1.InfoRequest;
import scylla.engine.v1.MaterializeRequest;

/**
 * Scylla engine-as-service (DD-040) — STANDALONE JVM gRPC server fronting GayHydra.
 *
 * <p>{@code Materialize} runs GayHydra's {@code analyzeHeadless} as a subprocess with the
 * shared dump-model post-script, then streams the result. GayHydra runs under its own
 * launcher (a clean separate process) and grpc-netty-shaded lives in this JVM — they never
 * share a classloader. Cold-start per request for now; a warm co-resident engine is a backlog
 * performance optimization, behind this same RPC. ALWAYS GayHydra, never stock Ghidra.
 */
public final class EngineServer {

    /** The post-script directory: {@code SCYLLA_SCRIPT_DIR} if set, else the {@code scripts/}
     *  dir shipped beside this service in the install — so dump_model.java travels WITH the
     *  service instead of being read out of the prototype tree at run time. */
    static String resolveScriptDir() {
        String env = System.getenv("SCYLLA_SCRIPT_DIR");
        return (env != null && !env.isEmpty()) ? env : shippedScriptDir();
    }

    /** The {@code scripts/} dir the install lays down beside the app jar
     *  ({@code <install>/lib/<jar>} → {@code <install>/scripts}), or {@code ""} if it cannot be
     *  resolved (e.g. running from a classes dir in dev — set SCYLLA_SCRIPT_DIR there). */
    static String shippedScriptDir() {
        try {
            java.net.URI loc =
                    EngineServer.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            Path scripts = Path.of(loc).getParent().getParent().resolve("scripts");
            if (Files.isDirectory(scripts)) {
                return scripts.toString();
            }
        } catch (Exception ignored) {
            // fall through to "" — main() validates and errors clearly
        }
        return "";
    }

    /** Last {@code n} chars of {@code s}, trimmed — the useful end of a subprocess log. */
    static String tail(String s, int n) {
        s = s.strip();
        return s.length() <= n ? s : "…" + s.substring(s.length() - n);
    }

    static final class EngineImpl extends EngineGrpc.EngineImplBase {
        private final String dist;
        private final String scriptDir;

        EngineImpl(String dist, String scriptDir) {
            this.dist = dist;
            this.scriptDir = scriptDir;
        }

        @Override
        public void info(InfoRequest req, StreamObserver<InfoReply> resp) {
            resp.onNext(InfoReply.newBuilder().setEngine("GayHydra").setVersion("0.1-subprocess").build());
            resp.onCompleted();
        }

        @Override
        public void materialize(MaterializeRequest req, StreamObserver<FunctionChunk> resp) {
            Path bin = null, out = null, proj = null;
            try {
                bin = Files.createTempFile("scylla-bin", ".bin");
                out = Files.createTempFile("scylla-snap", ".json");
                proj = Files.createTempDirectory("scylla-proj");
                Files.write(bin, req.getBinary().toByteArray());

                ProcessBuilder pb = new ProcessBuilder(
                        Path.of(dist, "support", "analyzeHeadless").toString(), proj.toString(),
                        "scylla_engine",
                        "-import", bin.toString(),
                        "-scriptPath", scriptDir,
                        "-postScript", "dump_model.java", out.toString(),
                        "-deleteProject");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                // Drain so the engine never blocks on a full pipe — but KEEP it: when a hostile
                // or malformed binary kills the analyzer, a bare exit code is useless. Surface the
                // tail over the wire so the failure says *why* (DD-021: errors carry meaning).
                byte[] log = p.getInputStream().readAllBytes();
                int code = p.waitFor();
                if (code != 0 || !Files.exists(out) || Files.size(out) == 0) {
                    String tail = tail(new String(log, java.nio.charset.StandardCharsets.UTF_8), 1200);
                    resp.onError(Status.INTERNAL
                            .withDescription("GayHydra headless failed (exit " + code + "): " + tail)
                            .asRuntimeException());
                    return;
                }

                JsonObject root = JsonParser.parseString(Files.readString(out)).getAsJsonObject();
                for (JsonElement fe : root.getAsJsonArray("functions")) {
                    JsonObject f = fe.getAsJsonObject();
                    FunctionChunk.Builder b = FunctionChunk.newBuilder()
                            .setEntry(Long.parseUnsignedLong(f.get("entry").getAsString(), 16))
                            .setName(f.get("name").getAsString())
                            .setSize(f.get("size").getAsLong())
                            .setBbCount(f.get("bb_count").getAsInt());
                    if (f.has("callees")) {
                        for (JsonElement c : f.getAsJsonArray("callees")) {
                            b.addCallees(Long.parseUnsignedLong(c.getAsString(), 16));
                        }
                    }
                    resp.onNext(b.build());
                }
                resp.onCompleted();
            } catch (Exception e) {
                resp.onError(Status.INTERNAL.withDescription(String.valueOf(e.getMessage()))
                        .asRuntimeException());
            } finally {
                try { if (bin != null) Files.deleteIfExists(bin); } catch (Exception ignored) {}
                try { if (out != null) Files.deleteIfExists(out); } catch (Exception ignored) {}
            }
        }

        @Override
        public void decompile(DecompileRequest req, StreamObserver<DecompileReply> resp) {
            resp.onNext(DecompileReply.newBuilder()
                    .setC("/* decompilation: on-demand GayHydra call, pending */").build());
            resp.onCompleted();
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 50051;

        // GHIDRA_DIST is REQUIRED — the GayHydra dist is an external ~890MB mount, never baked
        // into the image, and a hardcoded laptop path is a footgun that works on exactly one box.
        // Validate the whole config at START (fail-fast) rather than dying per-request with a
        // cryptic headless exit code.
        String dist = System.getenv("GHIDRA_DIST");
        if (dist == null || dist.isEmpty()) {
            System.err.println("FATAL: GHIDRA_DIST is not set — point it at the GayHydra dist "
                    + "(the directory containing support/analyzeHeadless). ALWAYS GayHydra.");
            System.exit(2);
            return;
        }
        if (!Files.isExecutable(Path.of(dist, "support", "analyzeHeadless"))) {
            System.err.println("FATAL: no executable support/analyzeHeadless under GHIDRA_DIST="
                    + dist + " — wrong path, or not a GayHydra dist.");
            System.exit(2);
            return;
        }
        String scriptDir = resolveScriptDir();
        if (scriptDir.isEmpty() || !Files.isRegularFile(Path.of(scriptDir, "dump_model.java"))) {
            System.err.println("FATAL: dump_model.java not found (scriptDir='" + scriptDir
                    + "'). It ships in the install's scripts/ dir; set SCYLLA_SCRIPT_DIR to override.");
            System.exit(2);
            return;
        }

        Server server =
                ServerBuilder.forPort(port).addService(new EngineImpl(dist, scriptDir)).build().start();
        System.out.println("scylla-engine-service (GayHydra subprocess) on " + port
                + " | dist=" + dist + " | scripts=" + scriptDir);
        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown));
        server.awaitTermination();
    }
}
