import java.util.Arrays;
import java.util.Base64;
import jdk.internal.misc.Unsafe;

/**
 * Long-running probe used to validate an in-memory mitigation that is attached to an
 * already-running JVM (the Xint runtime patch). Every ~1s it checks whether Base64
 * decode writes past the destination array and, if so, attempts to restore the
 * neighbouring bytes. This uses Unsafe and can corrupt the heap or crash the JVM;
 * use test hosts only. The matrix uses the separate bounded LiveProbe instead.
 * Adapted from the upstream runtime-patch test harness
 * (theori-io/java4shell-runtime-patch-CVE-2026-114938, test/LoopHarness.java).
 *
 * Requires: --add-exports java.base/jdk.internal.misc=ALL-UNNAMED (compile and run).
 * Uses the 128*'A'+'=' tail. Triggering depends on the build and compiled path.
 * Internal Unsafe APIs and object layouts are not portable across JDK versions.
 *
 * Optional arg: max number of probes before exiting (default: run forever).
 */
public class LoopHarness {
    static final Unsafe U = Unsafe.getUnsafe();
    static volatile Object SINK;   // keep victim allocation alive (no EA elimination)
    static final long BASE = U.arrayBaseOffset(byte[].class);
    static final int DST = 98, FROM = 96, LEN = 96;
    static long objSize(int n) { return (BASE + n + 7) & ~7L; }

    static int probe(Base64.Decoder dec, byte[] src) {
        for (int tries = 0; tries < 1000; tries++) {
            byte[] dst = new byte[DST];
            byte[] victim = new byte[256];
            SINK = victim;
            if (U.getInt(dst, objSize(DST) + BASE - 4) != 256) continue;   // need victim right after dst
            byte[] before = new byte[LEN];
            for (int i = 0; i < LEN; i++) before[i] = U.getByte(dst, BASE + FROM + i);
            try { dec.decode(src, dst); } catch (IllegalArgumentException expected) { }
            int oob = 0;
            for (int i = DST - FROM; i < LEN; i++) {
                if (U.getByte(dst, BASE + FROM + i) != before[i]) { oob++; U.putByte(dst, BASE + FROM + i, before[i]); } // heal
            }
            return oob;
        }
        return -1;
    }

    public static void main(String[] a) throws Exception {
        int maxProbes = a.length > 0 ? Integer.parseInt(a[0]) : Integer.MAX_VALUE;
        Base64.Decoder dec = Base64.getDecoder();
        byte[] src = new byte[129]; Arrays.fill(src, (byte) 'A'); src[128] = '=';
        byte[] valid = new byte[256]; Arrays.fill(valid, (byte) 'A'); byte[] out = new byte[192];
        System.out.println("harness " + System.getProperty("java.runtime.version")); System.out.flush();
        for (int n = 1; n <= maxProbes; n++) {
            long end = System.currentTimeMillis() + 1000;
            while (System.currentTimeMillis() < end) for (int i = 0; i < 2000; i++) dec.decode(valid, out);  // keep decode0 hot
            int oob = probe(dec, src);
            System.out.println("probe " + n + ": " + (oob > 0 ? "OOB WRITE " + oob + " bytes (vulnerable stub active)" : oob == 0 ? "no OOB" : "inconclusive"));
            System.out.flush();
        }
    }
}
