package dev.scylla.engine;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import scylla.engine.v1.EngineGrpc;
import scylla.engine.v1.DecompileReply;
import scylla.engine.v1.DecompileRequest;
import scylla.engine.v1.FunctionChunk;
import scylla.engine.v1.InfoReply;
import scylla.engine.v1.InfoRequest;
import scylla.engine.v1.MaterializeRequest;

/**
 * Scylla engine-as-service (DD-040) — STANDALONE JVM gRPC server.
 *
 * <p>This is the spike skeleton: it stands up grpc-java in a normal classpath and serves the
 * engine-port contract with stub data. Driving Ghidra headless as a library lands next, after
 * the classloader-coexistence milestone — keeping grpc-java OUT of Ghidra's plugin classloader
 * is the whole point of making this a standalone process, not a GUI plugin.
 */
public final class EngineServer {

    static final class EngineImpl extends EngineGrpc.EngineImplBase {
        @Override
        public void info(InfoRequest req, StreamObserver<InfoReply> resp) {
            resp.onNext(InfoReply.newBuilder().setEngine("GayHydra").setVersion("spike-0").build());
            resp.onCompleted();
        }

        @Override
        public void materialize(MaterializeRequest req, StreamObserver<FunctionChunk> resp) {
            // Stub: two functions. Real analysis (Ghidra headless) replaces this next.
            resp.onNext(FunctionChunk.newBuilder()
                    .setEntry(0x401156L).setName("gcd").setSize(64).setBbCount(4).build());
            resp.onNext(FunctionChunk.newBuilder()
                    .setEntry(0x401249L).setName("main").setSize(180).setBbCount(4)
                    .addCallees(0x401156L).build());
            resp.onCompleted();
        }

        @Override
        public void decompile(DecompileRequest req, StreamObserver<DecompileReply> resp) {
            resp.onNext(DecompileReply.newBuilder()
                    .setC("/* decompilation pending Ghidra wiring */").build());
            resp.onCompleted();
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 50051;
        Server server = ServerBuilder.forPort(port).addService(new EngineImpl()).build().start();
        System.out.println("scylla-engine-service (spike) listening on " + port);
        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown));
        server.awaitTermination();
    }
}
