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
import scylla.engine.v1.BsimFeature;
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
 * WARM (opt-in, {@code SCYLLA_ENGINE_WARM}): a POOL of resident GayHydra JVMs ({@link WarmEngine},
 * {@code SCYLLA_ENGINE_WARM_POOL} workers, default 1) inits the application + SLEIGH + decompiler
 * ONCE and imports+analyzes each binary in-process (~2s), up to pool-size CONCURRENTLY, with the cold
 * subprocess as the fallback if a warm call fails. Both paths emit the same snapshot JSON, so
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

    /** Warm-engine pool size — the number of resident GayHydra workers for CONCURRENT materialize
     *  ({@code SCYLLA_ENGINE_WARM_POOL}, default 1). Each worker is a full Ghidra JVM, so this is
     *  RAM-bound; capped at 16 to keep a typo from forking a hundred JVMs. */
    static int warmPoolSize() {
        String v = System.getenv("SCYLLA_ENGINE_WARM_POOL");
        try {
            return (v == null || v.isEmpty()) ? 1 : Math.min(16, Math.max(1, Integer.parseInt(v.trim())));
        } catch (NumberFormatException e) {
            return 1;
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

    /** Recursively delete a directory tree, best-effort (ignores individual failures). Java's
     *  {@code deleteIfExists} won't remove a non-empty dir, so the cold path's temp project would
     *  otherwise leak on every request until the sandbox runs out of inodes/disk. */
    private static void deleteRecursively(Path root) {
        try (var walk = Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                    // best-effort
                }
            });
        } catch (Exception ignored) {
            // the dir may already be gone
        }
    }

    /** Max inbound gRPC message. A whole binary (a 200 MB firmware — see job.rs) rides in
     *  {@code MaterializeRequest.binary}, so the 4 MiB grpc-java default would reject the very inputs
     *  the service is designed for. Matches the artifact loader's traversal ceiling. */
    static final int MAX_INBOUND_MESSAGE = 512 * 1024 * 1024;

    /** Cap concurrent COLD {@code analyzeHeadless} subprocesses — each is a full Ghidra JVM, so an
     *  unbounded burst would exhaust host CPU/RAM. Sized by {@code SCYLLA_ENGINE_COLD_CONCURRENCY}
     *  (default 2). The warm pool is already bounded by its worker queue; this guards the fallback. */
    private static int coldConcurrency() {
        try {
            return Math.max(1, Integer.parseInt(System.getenv("SCYLLA_ENGINE_COLD_CONCURRENCY")));
        } catch (Exception e) {
            return 2;
        }
    }

    private static final java.util.concurrent.Semaphore COLD_SLOTS =
            new java.util.concurrent.Semaphore(coldConcurrency());

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
     * One resident GayHydra JVM ({@code ScyllaWarmWorker}): inits Ghidra's application + SLEIGH +
     * decompiler ONCE, then imports + analyzes each binary in-process (~2s after the ~6s cold init).
     * The worker is a STANDALONE program — NOT a Ghidra script (the OSGi script compiler can't see
     * {@code ProgramLoader} / {@code AutoAnalysisManager}) — run with the dist on its classpath, like
     * the de-risk spike. A single worker serves ONE binary at a time (Ghidra analysis is not
     * thread-safe per program); the {@link WarmEngine} pool runs several workers for concurrency.
     */
    static final class WarmWorker implements AutoCloseable {
        private final Process proc;
        private final BufferedWriter toWorker;
        private final BlockingQueue<String> markers = new LinkedBlockingQueue<>();

        /** Spawn + warm one worker. {@code classpath} = the compiled worker classes + the full dist;
         *  blocks until the worker prints {@code SCYLLA-READY} (the one-time cold init). */
        WarmWorker(int id, String classpath, String dist) throws Exception {
            ProcessBuilder pb = new ProcessBuilder("java",
                    "-cp", classpath,
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
            }, "scylla-warm-reader-" + id);
            reader.setDaemon(true);
            reader.start();

            // Block until warm (the one-time cold init). Generous — container cold init is ~25s.
            String ready = markers.poll(180, TimeUnit.SECONDS);
            if (!"SCYLLA-READY".equals(ready)) {
                close();
                throw new IOException("warm worker did not become ready (got: " + ready + ")");
            }
        }

        boolean isAlive() {
            return proc.isAlive();
        }

        /** Import + analyze {@code binary}; returns the snapshot JSON path (caller deletes it). The
         *  caller holds this worker exclusively (checked out of the pool), so no synchronization is
         *  needed. On timeout the worker is KILLED (a wedged serial worker would poison itself) — the
         *  pool then drops it and the caller falls back to the cold subprocess. */
        Path materialize(byte[] binary, int timeoutSec) throws Exception {
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
                // Kill the whole tree in case the worker forked helpers, not just the direct child.
                proc.descendants().forEach(ProcessHandle::destroyForcibly);
                proc.destroyForcibly();
            }
        }
    }

    /**
     * The WARM ENGINE (DD-040): a POOL of {@link WarmWorker}s behind the same Materialize RPC. The
     * worker + the shared {@code ScyllaModel} extraction are compiled ONCE at startup against the
     * mounted dist; then {@code SCYLLA_ENGINE_WARM_POOL} workers (default 1) are spawned and warmed.
     * {@code materialize} checks a free worker out of a blocking queue, uses it, and returns it — so
     * up to {@code poolSize} binaries analyze CONCURRENTLY (separate workers, separate programs: safe,
     * since the thread-safety hazard is only WITHIN one program's analysis). A worker that wedges and
     * is killed is dropped from the pool, not returned; if the pool drains, the RPC falls back to the
     * cold subprocess. Each worker is a full Ghidra JVM — size the pool to the sandbox's memory.
     */
    static final class WarmEngine implements AutoCloseable {
        private final java.util.List<WarmWorker> workers = new java.util.ArrayList<>();
        private final BlockingQueue<WarmWorker> available = new LinkedBlockingQueue<>();

        WarmEngine(String dist, String workerSrc, String modelSrc, int poolSize) throws Exception {
            String distCp = distClasspath(dist);
            Path classesDir = Files.createTempDirectory("scylla-warm-classes");

            // Compile the worker, the shared ScyllaModel extraction (DD-041 — same source the cold
            // dump_model.java script uses), AND the BSim extractor (DD-044, a sibling of the worker:
            // it uses the decompiler/BSim API the OSGi cold path can't, so it lives here and is
            // compiled against the dist). ONCE; javac ships in the JDK image. ~1s, shared by the pool.
            String bsimSrc = Path.of(workerSrc).resolveSibling("ScyllaBsim.java").toString();
            Process jc = new ProcessBuilder("javac", "-proc:none", "-cp", distCp,
                    "-d", classesDir.toString(), workerSrc, modelSrc, bsimSrc)
                    .redirectErrorStream(true).start();
            byte[] jcLog = jc.getInputStream().readAllBytes();
            if (!jc.waitFor(120, TimeUnit.SECONDS) || jc.exitValue() != 0) {
                jc.destroyForcibly();
                throw new IOException("warm worker compile failed: "
                        + tail(new String(jcLog, java.nio.charset.StandardCharsets.UTF_8), 1200));
            }
            String cp = classesDir + java.io.File.pathSeparator + distCp;

            try {
                for (int i = 0; i < Math.max(1, poolSize); i++) {
                    WarmWorker w = new WarmWorker(i, cp, dist); // blocks for SCYLLA-READY
                    workers.add(w);
                    available.offer(w);
                }
            } catch (Exception e) {
                close(); // a partial pool is no pool — tear down any that did come up
                throw e;
            }
        }

        /** Any worker still alive? When false, the pool has drained and the caller goes cold. */
        boolean isAlive() {
            return workers.stream().anyMatch(WarmWorker::isAlive);
        }

        /** Check out a free worker (waiting up to {@code timeoutSec} for one), analyze, return it to
         *  the pool iff it survived. A killed/dead worker is dropped — the pool shrinks rather than
         *  handing back a corpse. */
        Path materialize(byte[] binary, int timeoutSec) throws Exception {
            WarmWorker w = available.poll(timeoutSec, TimeUnit.SECONDS);
            if (w == null) {
                throw new IOException("no warm worker free within " + timeoutSec + "s");
            }
            try {
                Path out = w.materialize(binary, timeoutSec);
                available.offer(w); // healthy → back in the pool
                return out;
            } catch (Exception e) {
                if (w.isAlive()) {
                    available.offer(w); // a benign analyze error (bad binary) — the worker is fine
                }
                // else: it was killed (timeout) — drop it; isAlive() reflects the smaller pool
                throw e;
            }
        }

        @Override
        public void close() {
            workers.forEach(WarmWorker::close);
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
            boolean slot = false;
            try {
                // Bound concurrent cold Ghidra JVMs (each is heavy) so a burst can't exhaust the host.
                COLD_SLOTS.acquire();
                slot = true;
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
                    // analyzeHeadless is a launcher that forks the real Ghidra JVM as a grandchild;
                    // destroyForcibly() on the direct child alone orphans that JVM (still analyzing a
                    // hostile binary) past the deadline (GAP-2). Kill the whole tree, descendants first.
                    p.descendants().forEach(ProcessHandle::destroyForcibly);
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
                if (slot) {
                    COLD_SLOTS.release();
                }
                try { if (bin != null) Files.deleteIfExists(bin); } catch (Exception ignored) {}
                try { if (out != null) Files.deleteIfExists(out); } catch (Exception ignored) {}
                // -deleteProject removes the ghidra project INSIDE proj, never the temp dir itself.
                if (proj != null) {
                    deleteRecursively(proj);
                }
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
                // Package-qualified callee names (DD-043) — the Go cross-architecture anchor signal.
                if (f.has("callee_names")) {
                    for (JsonElement s : f.getAsJsonArray("callee_names")) {
                        b.addCalleeNames(s.getAsString());
                    }
                }
                // BSim LSH feature vector (DD-044): [[hash, f32_bits], …] — the cross-arch lever for
                // the symmetric leaves. The CORE compares these by weighted cosine (== Ghidra's
                // LSHVector.compare). Values are UNSIGNED 32-bit in the JSON; packed into the proto's
                // int-bit uint32 (the Rust side reads them back as u32).
                if (f.has("bsim_vector")) {
                    for (JsonElement pe : f.getAsJsonArray("bsim_vector")) {
                        b.addBsimVector(BsimFeature.newBuilder()
                                .setHash((int) pe.getAsJsonArray().get(0).getAsLong())
                                .setWeight((int) pe.getAsJsonArray().get(1).getAsLong())
                                .build());
                    }
                }
                resp.onNext(MaterializeEvent.newBuilder().setFunction(b.build()).build());
            }
            resp.onCompleted();
        }

        @Override
        public void decompile(DecompileRequest req, StreamObserver<DecompileReply> resp) {
            // Not yet implemented — return UNIMPLEMENTED rather than a placeholder string a caller
            // can't distinguish from a real (empty) decompilation.
            resp.onError(Status.UNIMPLEMENTED
                    .withDescription("decompile is not yet implemented (on-demand GayHydra call pending)")
                    .asRuntimeException());
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 50051;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("invalid port: " + args[0]);
                System.exit(2);
            }
        }

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
            // ScyllaModel.java (the shared extraction, DD-041) lives beside dump_model.java in the
            // script dir; the worker is compiled together with it.
            String modelSrc = Path.of(scriptDir, "ScyllaModel.java").toString();
            if (workerSrc.isEmpty() || !Files.isRegularFile(Path.of(modelSrc))) {
                System.err.println("WARN: SCYLLA_ENGINE_WARM set but the warm worker sources weren't "
                        + "found (worker='" + workerSrc + "', model='" + modelSrc
                        + "'; set SCYLLA_WARM_WORKER_SRC). Running COLD.");
            } else {
                long t0 = System.nanoTime();
                int poolSize = warmPoolSize();
                try {
                    warm = new WarmEngine(dist, workerSrc, modelSrc, poolSize);
                    System.out.println("warm engine ready in "
                            + ((System.nanoTime() - t0) / 1_000_000L) + " ms (" + poolSize
                            + " in-process GayHydra worker" + (poolSize == 1 ? "" : "s") + ")");
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
                    .maxInboundMessageSize(MAX_INBOUND_MESSAGE)
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
                    .maxInboundMessageSize(MAX_INBOUND_MESSAGE)
                    .addService(new EngineImpl(dist, scriptDir, warmEngine)).build().start();
            System.out.println("scylla-engine-service (GayHydra " + mode + ") on " + port
                    + " | dist=" + dist + " | scripts=" + scriptDir);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown));
        server.awaitTermination();
    }
}
