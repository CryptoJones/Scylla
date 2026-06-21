# Scylla engine-as-service (DD-034) — the adversarial-binary parser, packaged for sandboxing.
# Small image: a JDK + the service. The ~890MB GayHydra dist is a READ-ONLY mount at runtime,
# never baked in. ALWAYS GayHydra.
#
# A JDK, not a JRE: GayHydra's launcher hunts for a real JDK, and Java GhidraScripts
# (dump_model.java) are COMPILED at run time — javac has to be on board.
FROM eclipse-temurin:21-jdk

# Non-root. The JVM derives user.home from the passwd entry, NOT $HOME — so point the home at
# the writable /tmp tmpfs. Otherwise Ghidra's launcher dies writing its JDK-detection save file
# under the read-only rootfs (FileNotFoundException: user home directory does not exist).
RUN useradd -r -u 10001 -d /tmp scylla
COPY build/install/scylla-engine-service /opt/engine-service

ENV HOME=/tmp
USER 10001
EXPOSE 50051
ENTRYPOINT ["/opt/engine-service/bin/scylla-engine-service", "50051"]
