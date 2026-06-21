// Warm-engine de-risk spike (DD-040 follow-up). Question: can ONE JVM host grpc-netty-shaded AND
// initialize Ghidra as an in-process library — or does Ghidra's "notoriously fussy" classloader
// fight grpc, the way DD-040 worried, forcing the per-call subprocess model?
//
// This is NOT the warm engine. It is the smallest experiment that answers GO/NO-GO: load grpc,
// initialize Ghidra in-process (the risky part), and report whether both live + how long init took
// (the cost warming would amortize). Run via run-spike.sh.
public final class Spike {
    public static void main(String[] args) throws Exception {
        System.out.println("[spike] system classloader = " + ClassLoader.getSystemClassLoader().getClass().getName());

        // (1) The grpc side — what the engine-service JVM already runs today.
        Class.forName("io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder");
        System.out.println("[spike] grpc-netty-shaded: loaded OK");

        // (2) THE RISK: Ghidra as an in-process library (the DD-040 classloader question).
        try {
            long t0 = System.nanoTime();
            ghidra.framework.Application.initializeApplication(
                    new ghidra.GhidraApplicationLayout(),
                    new ghidra.framework.HeadlessGhidraApplicationConfiguration());
            long ms = (System.nanoTime() - t0) / 1_000_000L;
            System.out.println("[spike] Ghidra in-process init: OK in " + ms + " ms"
                    + "  <-- the fixed cost warming amortizes");

            // (3) Touch grpc again AFTER Ghidra init — prove both coexist.
            io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder.forPort(0);
            System.out.println("[spike] RESULT: GO — grpc-netty + in-process Ghidra coexist in ONE JVM (default classloader).");
        } catch (Throwable t) {
            System.out.println("[spike] Ghidra in-process init FAILED: " + t);
            t.printStackTrace(System.out);
            System.out.println("[spike] RESULT: in-process is NOT free under the default classloader — see SPIKE-REPORT.md.");
        }
    }
}
