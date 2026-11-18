import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import javax.management.MBeanServer;
import javax.management.ObjectName;

/**
 * Runtime mitigation (no restart) for the Base64 AVX-512 VBMI decode-stub OOB write
 * (CVE-2026-114938). Source from the Xint / Theori runtime patch, with local comments
 * (theori-io/java4shell-runtime-patch-CVE-2026-114938, src/CVE_2026_114938.java) so it
 * can be built and audited in-repo instead of pulled from a `curl | sh` installer.
 *
 * Uses only supported interfaces: compiler directives (== jcmd Compiler.directives_add)
 * + class retransform. It does not write JVM memory directly. Compatibility depends
 * on the target JVM's diagnostic commands, instrumentation, and attach permissions;
 * attach success alone does not prove that mitigation was applied.
 *
 *   jcmd <pid> JVMTI.agent_load /path/CVE-2026-114938.jar            apply (only if the JVM is exposed)
 *   jcmd <pid> JVMTI.agent_load /path/CVE-2026-114938.jar dry-run    load/log; no directives or retransform
 *   jcmd <pid> JVMTI.agent_load /path/CVE-2026-114938.jar force      apply even if checks say "not exposed"
 *
 * How:
 *  1) Directives: Base64$Decoder.decode0 (the only caller of the decodeBlock intrinsic) is excluded from
 *     C2 and must not be inlined anywhere, so no C2 code contains the intrinsic call site. C1 and the
 *     interpreter never use the Base64 intrinsics. Encoding is untouched.
 *     (Note: a directive "DisableIntrinsic" does not work on 17u, and flipping UseBASE64Intrinsics in
 *     memory does not work either: the per-intrinsic decision is cached after the first compilation.)
 *  2) Retransform Base64$Decoder/$Encoder with unchanged bytes -> already compiled code that depends on
 *     them is deoptimized (all compiled code if no redefine-capable agent was present at startup).
 *     JIT warm-up and CPU cost depend on JVM and agent state.
 * Dry-run still loads this agent and creates or replaces logs.
 * In-memory only: keep -XX:-UseBASE64Intrinsics in the startup options for the next restart.
 */
public class CVE_2026_114938 {
    static final String MARK = "java/util/Base64$Decoder.decode0";
    static final String DIRECTIVE =
            "[{ match: \"" + MARK + "\", c2: { Exclude: true } },"
          + " { match: \"*.*\", inline: \"-" + MARK + "\" }]";

    public static void agentmain(String a, Instrumentation inst) { run(a, inst); }
    public static void premain(String a, Instrumentation inst) { run(a, inst); }

    static Path logFile;   // <jar dir>/CVE-2026-114938-<pid>.log, read by apply.sh

    static void log(String s) {
        String line = "[CVE-2026-114938 Runtime Patch] " + s;
        System.err.println(line); System.err.flush();
        try {
            if (logFile != null) Files.writeString(logFile, line + System.lineSeparator(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable ignore) { }
    }

    static synchronized void run(String args, Instrumentation inst) {
        String opt = args == null ? "" : args.trim().toLowerCase(Locale.ROOT);
        boolean dry = opt.contains("dry-run"), force = opt.contains("force");
        try {
            Path jar = Path.of(CVE_2026_114938.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            logFile = jar.resolveSibling("CVE-2026-114938-" + ProcessHandle.current().pid() + ".log");
            Files.deleteIfExists(logFile);
        } catch (Throwable ignore) { logFile = null; }
        try {
            MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
            ObjectName dcmd = new ObjectName("com.sun.management:type=DiagnosticCommand");

            // ---- checks ------------------------------------------------------------------
            Runtime.Version v = Runtime.version();
            boolean verAffected = v.feature() >= 18 || (v.feature() == 17 && v.update() >= 6);
            String arch = System.getProperty("os.arch");
            boolean x86 = arch.equals("amd64") || arch.equals("x86_64");
            String vmInfo = String.valueOf(dcmd(mbs, dcmd, "vmInfo"));
            boolean vbmi = vmInfo.contains("avx512_vbmi") && vmInfo.contains("avx512bw");
            String flag = ManagementFactory.getPlatformMXBean(com.sun.management.HotSpotDiagnosticMXBean.class)
                    .getVMOption("UseBASE64Intrinsics").getValue();
            boolean already = String.valueOf(dcmd(mbs, dcmd, "compilerDirectivesPrint")).contains(MARK);
            boolean exposed = verAffected && x86 && vbmi && "true".equals(flag);

            log("JVM " + v + " " + arch + " | version affected=" + verAffected + " | CPU avx512_vbmi+bw=" + vbmi
                    + " | UseBASE64Intrinsics=" + flag + " | directive already present=" + already);
            log("=> " + (exposed ? "EXPOSED" : "not exposed")
                    + (exposed ? "" : " (" + (!verAffected ? "JDK version " : "") + (!x86 ? "non-x86 " : "")
                       + (!vbmi ? "no AVX-512 VBMI " : "") + (!"true".equals(flag) ? "intrinsic already off" : "") + ")"));

            if (!exposed && !force) { log("nothing to do"); return; }
            if (dry) {
                log("dry-run: would " + (already ? "skip directive (present), " : "add directives " + DIRECTIVE + ", ")
                        + "then retransform Base64$Decoder/$Encoder (deopt). No directives added or classes retransformed; agent loading, staging, and logging may still occur.");
                return;
            }

            // ---- apply -------------------------------------------------------------------
            if (!already) {
                Path f = Files.createTempFile("CVE-2026-114938-directive", ".json");
                try {
                    Files.writeString(f, DIRECTIVE);
                    Object out = mbs.invoke(dcmd, "compilerDirectivesAdd", new Object[] { new String[] { f.toString() } },
                            new String[] { String[].class.getName() });
                    log("directives added: " + String.valueOf(out).trim());
                } finally {
                    Files.deleteIfExists(f);
                }
                if (!String.valueOf(dcmd(mbs, dcmd, "compilerDirectivesPrint")).contains(MARK)) {
                    log("FAILED: directive not visible after add; no deopt performed"); return;
                }
            }
            long t0 = System.nanoTime();
            inst.retransformClasses(Class.forName("java.util.Base64$Decoder"), Class.forName("java.util.Base64$Encoder"));
            log("existing JIT code deoptimized (" + (System.nanoTime() - t0) / 1_000_000 + " ms)");
            log("APPLIED: Base64 decode intrinsic disabled in this JVM (in memory only). "
                    + "Add -XX:-UseBASE64Intrinsics to the startup options so it stays disabled after a restart.");
        } catch (Throwable t) {
            log("FAILED: " + t);
        }
    }

    static Object dcmd(MBeanServer mbs, ObjectName on, String op) throws Exception {
        return mbs.invoke(on, op, new Object[] { new String[0] }, new String[] { String[].class.getName() });
    }
}
