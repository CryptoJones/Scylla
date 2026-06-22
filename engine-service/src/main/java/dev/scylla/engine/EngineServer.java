package dev.scylla.engine;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.Status;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.epoll.EpollServerDomainSocketChannel;
import io.grpc.netty.shaded.io.netty.channel.unix.DomainSocketAddress;
import io.grpc.stub.StreamObserver;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import scylla.engine.v1.DecompileReply;
import scylla.engine.v1.DecompileRequest;
import scylla.engine.v1.EngineGrpc;
import scylla.engine.v1.FunctionChunk;
import scylla.engine.v1.InfoReply;
import scylla.engine.v1.InfoRequest;
import scylla.engine.v1.MaterializeEvent;
import scylla.engine.v1.MaterializeRequest;
import scylla.engine.v1.ProgramInfo;

/**
 * Scylla engine-as-service (DD-040) — STANDALONE JVM gRPC server fronting GayHydra.
 *
 * <p>{@code Materialize} has two paths behind the SAME RPC (DD-040). COLD (default): run GayHydra's
 * {@code analyzeHeadless} as a subprocess with the shared dump-model post-script, then stream the
 * result — GayHydra runs under its own launcher (a clean separate process), grpc-netty-shaded lives
 * in this JVM, they never share a classloader, and every call pays fresh JVM+Ghidra init (~6s host).
 * WARM (opt-in, {@code SCYLLA_ENGINE_WARM}): one resident GayHydra JVM ({@link WarmEngine}) inits the
 * application + SLEIGH + decompiler ONCE and imports+analyzes each binary in-process (~2s), with the
 * cold subprocess as the fallback if a warm call fails. Both paths emit the same snapshot JSON, so
 * {@link EngineImpl#streamSnapshot} is shared. ALWAYS GayHydra, never stock Ghidra.
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

    /** Per-invocation wall-clock budget for {@code analyzeHeadless} (GAP-2 / DD-034), seconds.
     *  {@code SCYLLA_ENGINE_TIMEOUT_SEC} overrides; default 300 (a normal binary is ~25s). */
    static int timeoutSeconds() {
        String v = System.getenv("SCYLLA_ENGINE_TIMEOUT_SEC");
        try {
            return (v == null || v.isEmpty()) ? 300 : Math.max(1, Integer.parseInt(v.trim()));
        } catch (NumberFormatException e) {
            return 300;
        }
    }

    /** A set-and-on env flag: present and not one of {@code 0/false/no/off/""} (case-insensitive). */
    static boolean isTruthy(String v) {
        if (v == null) {
            return false;
        }
        String s = v.trim().toLowerCase();
        return !(s.isEmpty() || s.equals("0") || s.equals("false") || s.equals("no") || s.equals("off"));
    }

    /** Last {@code n} chars of {@code s}, trimmed — the useful end of a subprocess log. */
    static String tail(String s, int n) {
        s = s.strip();
        return s.length() <= n ? s : "…" + s.substring(s.length() - n);
    }

    /** The warm-worker source ({@code ScyllaWarmWorker.java}): {@code SCYLLA_WARM_WORKER_SRC} if
     *  set, else the {@code warm-worker/} dir shipped beside this service in the install — the
     *  worker travels WITH the service and is compiled against the dist at startup. {@code ""} if
     *  it cannot be resolved. */
    static String resolveWarmWorkerSrc() {
        String env = System.getenv("SCYLLA_WARM_WORKER_SRC");
        if (env != null && !env.isEmpty()) {
            return env;
        }
        try {
            java.net.URI loc =
                    EngineServer.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            Path src = Path.of(loc).getParent().getParent()
                    .resolve("warm-worker").resolve("ScyllaWarmWorker.java");
            if (Files.isRegularFile(src)) {
                return src.toString();
            }
        } catch (Exception ignored) {
            // fall through to "" — main() validates and errors clearly
        }
        return "";
    }

    /**
     * The WARM ENGINE (DD-040): one resident GayHydra JVM that inits Ghidra's application + SLEIGH +
     * decompiler ONCE, then imports + analyzes each binary in-process. Only the first call pays the
     * ~6s cold init; the rest are ~2s. The worker ({@code ScyllaWarmWorker}) is a STANDALONE program,
     * NOT a Ghidra script — the OSGi script compiler can't see {@code ProgramLoader} /
     * {@code AutoAnalysisManager} — compiled at startup against the mounted dist and run with the
     * dist on its classpath, exactly like the de-risk spike. Requests are SERIALIZED: Ghidra analysis
     * is not thread-safe per program, so one warm engine serves one binary at a time, behind the same
     * RPC. A wedged/failed call kills the worker (no hang); the caller falls back to the cold path.
     */
    static final class WarmEngine implements AutoCloseable {
        private final Process proc;
        private final BufferedWriter toWorker;
        private final BlockingQueue<String> markers = new LinkedBlockingQueue<>();

        WarmEngine(String dist, String workerSrc) throws Exception {
            String distCp = distClasspath(dist);
            Path classesDir = Files.createTempDirectory("scylla-warm-classes");

            // Compile the worker against the dist (javac ships in the JDK image). One-time, ~1s.
            Process jc = new ProcessBuilder("javac", "-proc:none", "-cp", distCp,
                    "-d", classesDir.toString(), workerSrc)
                    .redirectErrorStream(true).start();
            byte[] jcLog = jc.getInputStream().readAllBytes();
            if (!jc.waitFor(120, TimeUnit.SECONDS) || jc.exitValue() != 0) {
                jc.destroyForcibly();
                throw new IOException("warm worker compile failed: "
                        + tail(new String(jcLog, java.nio.charset.StandardCharsets.UTF_8), 1200));
            }

            // Spawn the resident worker: dist on the classpath, ghidra.install.dir set (like the spike).
            ProcessBuilder pb = new ProcessBuilder("java",
                    "-cp", classesDir + java.io.File.pathSeparator + distCp,
                    "-Dghidra.install.dir=" + dist,
                    "ScyllaWarmWorker");
            pb.redirectError(ProcessBuilder.Redirect.DISCARD); // Ghidra log4j/init noise → /dev/null
            this.proc = pb.start();
            this.toWorker = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream()));

            Thread reader = new Thread(() -> {
                try (BufferedReader br =
                        new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                    String l;
                    while ((l = br.readLine()) != null) {
                        if (l.startsWith("SCYLLA-")) {
                            markers.offer(l);
                        }
                    }
                } catch (Exception ignored) {
                    // pipe closed on worker exit — markers.poll timeouts surface it
                }
            }, "scylla-warm-reader");
            reader.setDaemon(true);
            reader.start();

            // Block until the engine is warm (the one-time cold init). Generous — container cold
            // init is ~25s; this is paid ONCE at startup, not per request.
            String ready = markers.poll(180, TimeUnit.SECONDS);
            if (!"SCYLLA-READY".equals(ready)) {
                close();
                throw new IOException("warm worker did not become ready (got: " + ready + ")");
            }
        }

        boolean isAlive() {
            return proc.isAlive();
        }

        /** Import + analyze {@code binary} in the warm JVM; returns the snapshot JSON path (caller
         *  deletes it). Serialized. On timeout the worker is killed (it serves serially, so a wedged
         *  call would poison the engine) — the caller then falls back to the cold subprocess. */
        synchronized Path materialize(byte[] binary, int timeoutSec) throws Exception {
            if (!proc.isAlive()) {
                throw new IOException("warm worker is not alive");
            }
            Path bin = Files.createTempFile("scylla-warm-bin", ".bin");
            Path out = Files.createTempFile("scylla-warm-snap", ".json");
            try {
                Files.write(bin, binary);
                toWorker.write(bin.toAbsolutePath() + "\t" + out.toAbsolutePath() + "\n");
                toWorker.flush();
                String marker = markers.poll(timeoutSec, TimeUnit.SECONDS);
                if (marker == null) {
                    close(); // wedged on a hostile/pathological binary (GAP-2) — tear the worker down
                    Files.deleteIfExists(out);
                    throw new IOException("warm analyze exceeded " + timeoutSec + "s — worker killed");
                }
                if (marker.startsWith("SCYLLA-ERR")) {
                    Files.deleteIfExists(out);
                    int t = marker.indexOf('\t');
                    throw new IOException("warm analyze: "
                            + (t >= 0 ? marker.substring(t + 1) : marker));
                }
                return out;
            } finally {
                try { Files.deleteIfExists(bin); } catch (Exception ignored) {}
            }
        }

        @Override
        public void close() {
            try {
                if (proc.isAlive()) {
                    toWorker.write("QUIT\n");
                    toWorker.flush();
                }
            } catch (Exception ignored) {
                // best-effort graceful quit; force-kill below regardless
            }
            if (proc.isAlive()) {
                proc.destroyForcibly();
            }
        }

        /** Every jar under the dist — the worker needs the full Ghidra classpath, like the spike. */
        private static String distClasspath(String dist) throws Exception {
            StringBuilder cp = new StringBuilder();
            try (java.util.stream.Stream<Path> paths = Files.walk(Path.of(dist))) {
                for (Path p : (Iterable<Path>) paths
                        .filter(x -> x.toString().endsWith(".jar"))::iterator) {
                    cp.append(p).append(java.io.File.pathSeparator);
                }
            }
            return cp.toString();
        }
    }

    static final class EngineImpl extends EngineGrpc.EngineImplBase {
        private final String dist;
        private final String scriptDir;
        private final WarmEngine warm; // non-null = warm in-process mode; null = cold subprocess

        EngineImpl(String dist, String scriptDir, WarmEngine warm) {
            this.dist = dist;
            this.scriptDir = scriptDir;
            this.warm = warm;
        }

        @Override
        public void info(InfoRequest req, StreamObserver<InfoReply> resp) {
            String mode = warm != null ? "0.1-warm" : "0.1-subprocess";
            resp.onNext(InfoReply.newBuilder().setEngine("GayHydra").setVersion(mode).build());
            resp.onCompleted();
        }

        @Override
        public void materialize(MaterializeRequest req, StreamObserver<MaterializeEvent> resp) {
            // WARM (DD-040): the resident worker imports+analyzes in its hot Ghidra JVM (~2s vs the
            // ~6s cold subprocess). Same snapshot JSON contract, so the streaming is identical. The
            // PRODUCE step (warm.materialize) is what can fail on a bad binary or a dead worker; if
            // it does we fall through to the cold subprocess — the subprocess is the fallback behind
            // the same RPC (DD-040), so one pathological binary never takes warm-mode down. Stream
            // errors AFTER production started are terminal (the client is already mid-stream).
            if (warm != null && warm.isAlive()) {
                Path warmOut = null;
                try {
                    warmOut = warm.materialize(req.getBinary().toByteArray(), timeoutSeconds());
                } catch (Exception e) {
                    System.err.println("warm engine failed (" + e.getMessage()
                            + "); falling back to cold subprocess");
                }
                if (warmOut != null) {
                    try {
                        streamSnapshot(warmOut, resp);
                    } catch (Exception e) {
                        resp.onError(Status.INTERNAL.withDescription(String.valueOf(e.getMessage()))
                                .asRuntimeException());
                    } finally {
                        try { Files.deleteIfExists(warmOut); } catch (Exception ignored) {}
                    }
                    return;
                }
            }
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
                // Drain stdout OFF-THREAD: keep it (a bare exit code is useless when a hostile
                // binary kills the analyzer — surface the tail, DD-021), but a blocking read here
                // would itself hang forever on a hung analyzer. Off-thread + a bounded waitFor lets
                // us enforce a WALL-CLOCK deadline (GAP-2 / DD-034): a binary engineered to hang
                // analyzeHeadless must not tie up the engine slot forever.
                java.util.concurrent.atomic.AtomicReference<byte[]> logRef =
                        new java.util.concurrent.atomic.AtomicReference<>(new byte[0]);
                Thread drain = new Thread(() -> {
                    try {
                        logRef.set(p.getInputStream().readAllBytes());
                    } catch (Exception ignored) {
                        // a killed process closes the pipe; nothing to read
                    }
                }, "scylla-drain");
                drain.setDaemon(true);
                drain.start();

                if (!p.waitFor(timeoutSeconds(), java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    resp.onError(Status.DEADLINE_EXCEEDED
                            .withDescription("GayHydra headless exceeded the " + timeoutSeconds()
                                    + "s wall-clock limit — killed (a hostile or pathological binary).")
                            .asRuntimeException());
                    return;
                }
                drain.join(2000); // the process exited; let the drain finish reading the tail
                byte[] log = logRef.get();
                int code = p.exitValue();
                if (code != 0 || !Files.exists(out) || Files.size(out) == 0) {
                    String tail = tail(new String(log, java.nio.charset.StandardCharsets.UTF_8), 1200);
                    resp.onError(Status.INTERNAL
                            .withDescription("GayHydra headless failed (exit " + code + "): " + tail)
                            .asRuntimeException());
                    return;
                }

                streamSnapshot(out, resp);
            } catch (Exception e) {
                resp.onError(Status.INTERNAL.withDescription(String.valueOf(e.getMessage()))
                        .asRuntimeException());
            } finally {
                try { if (bin != null) Files.deleteIfExists(bin); } catch (Exception ignored) {}
                try { if (out != null) Files.deleteIfExists(out); } catch (Exception ignored) {}
            }
        }

        /**
         * Stream a snapshot JSON file (warm or cold — same contract) over the Materialize RPC: a
         * ProgramInfo header once, then one FunctionChunk per function. Both producers (the warm
         * in-process worker and the cold analyzeHeadless script) write the SAME shape, so the wire
         * side is identical regardless of how the snapshot was made.
         */
        private void streamSnapshot(Path out, StreamObserver<MaterializeEvent> resp) throws Exception {
            JsonObject root = JsonParser.parseString(Files.readString(out)).getAsJsonObject();

            // Program header first (once): the SLEIGH language id (the analyzer emits it; over
            // gRPC it used to be dropped, leaving Program.language empty). The NAME is left
            // empty on purpose — this service receives bytes and imports them under a temp
            // file, so the only name it knows is meaningless noise; the client names the
            // program (its real filename), via materialize()'s fallback.
            ProgramInfo info = ProgramInfo.newBuilder()
                    .setName("")
                    .setLanguage(root.has("language") ? root.get("language").getAsString() : "")
                    .build();
            resp.onNext(MaterializeEvent.newBuilder().setInfo(info).build());

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
                // The mnemonics the analyzer already emits — streamed raw so the CORE folds
                // them into Function.fingerprint with the same hash the snapshot path uses
                // (DD-038). The engine does not hash; one hash, one place.
                if (f.has("mnemonics")) {
                    for (JsonElement m : f.getAsJsonArray("mnemonics")) {
                        b.addMnemonics(m.getAsString());
                    }
                }
                // Arch-independent features (DD-041): the string literals + import names the analyzer
                // extracted, carried raw — the CROSS-ARCHITECTURE re-anchoring signal.
                if (f.has("string_refs")) {
                    for (JsonElement s : f.getAsJsonArray("string_refs")) {
                        b.addStringRefs(s.getAsString());
                    }
                }
                if (f.has("imports")) {
                    for (JsonElement s : f.getAsJsonArray("imports")) {
                        b.addImports(s.getAsString());
                    }
                }
                resp.onNext(MaterializeEvent.newBuilder().setFunction(b.build()).build());
            }
            resp.onCompleted();
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

        // WARM ENGINE (DD-040), opt-in via SCYLLA_ENGINE_WARM: stand up one resident GayHydra JVM at
        // startup (pays the cold init ONCE) so Materialize is ~2s instead of ~6s. Best-effort — if the
        // worker can't be built/warmed we log and run cold (the subprocess path is always present as
        // the fallback). Default OFF: cold-only is the proven, dependency-light path.
        WarmEngine warm = null;
        if (isTruthy(System.getenv("SCYLLA_ENGINE_WARM"))) {
            String workerSrc = resolveWarmWorkerSrc();
            if (workerSrc.isEmpty()) {
                System.err.println("WARN: SCYLLA_ENGINE_WARM set but ScyllaWarmWorker.java not found "
                        + "(set SCYLLA_WARM_WORKER_SRC). Running COLD.");
            } else {
                long t0 = System.nanoTime();
                try {
                    warm = new WarmEngine(dist, workerSrc);
                    System.out.println("warm engine ready in "
                            + ((System.nanoTime() - t0) / 1_000_000L) + " ms (in-process GayHydra)");
                } catch (Exception e) {
                    System.err.println("WARN: warm engine failed to start (" + e.getMessage()
                            + "); running COLD.");
                    warm = null;
                }
            }
        }
        final WarmEngine warmEngine = warm;
        if (warmEngine != null) {
            Runtime.getRuntime().addShutdownHook(new Thread(warmEngine::close));
        }
        String mode = warmEngine != null ? "warm+subprocess-fallback" : "subprocess";

        String uds = System.getenv("SCYLLA_ENGINE_UDS");
        Server server;
        if (uds != null && !uds.isEmpty()) {
            // No-egress sandbox (DD-034 GAP-1): listen on a Unix-domain socket so the container can
            // run with `--network none` — a hostile binary has literally no network to phone home
            // over. UDS needs the epoll NATIVE transport (the NIO transport can't do domain sockets).
            java.io.File sock = new java.io.File(uds);
            sock.delete(); // clear a stale socket from a previous run
            server = NettyServerBuilder.forAddress(new DomainSocketAddress(sock))
                    .channelType(EpollServerDomainSocketChannel.class)
                    .bossEventLoopGroup(new EpollEventLoopGroup(1))
                    .workerEventLoopGroup(new EpollEventLoopGroup())
                    .addService(new EngineImpl(dist, scriptDir, warmEngine))
                    .build().start();
            // Netty creates the socket under the process umask; widen it so the host client (a
            // different uid) can connect across the bind-mounted, host-private socket dir.
            try {
                java.nio.file.Files.setPosixFilePermissions(sock.toPath(),
                        java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx"));
            } catch (Exception ignored) {
                // best-effort; if the host runs the client as the same uid it isn't needed
            }
            System.out.println("scylla-engine-service (GayHydra " + mode + ") on unix:" + uds
                    + " | dist=" + dist + " | scripts=" + scriptDir);
        } else {
            server = ServerBuilder.forPort(port)
                    .addService(new EngineImpl(dist, scriptDir, warmEngine)).build().start();
            System.out.println("scylla-engine-service (GayHydra " + mode + ") on " + port
                    + " | dist=" + dist + " | scripts=" + scriptDir);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown));
        server.awaitTermination();
    }
}
