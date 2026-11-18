import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;

/**
 * Long-running, public-API-only live probe for validating a mitigation that is
 * hot-attached to an already-running JVM (the Xint runtime patch).
 *
 * Unlike poc/LoopHarness.java (which uses jdk.internal.misc.Unsafe and therefore breaks
 * across JDK internal-API changes — e.g. Unsafe.arrayBaseOffset's signature changed in
 * JDK 25), this harness uses the same oversized-array approach as
 * Java4ShellProbe: it decodes the malformed input into an oversized array and counts how
 * many bytes were written past the decoder's own computed output length. No Unsafe, no
 * --add-exports, Java 8 bytecode. The matrix tests selected JRE/JDK builds from 8 to 27.
 * Observed writes stay inside the array; untested JVMs have no safety guarantee.
 * Use a test host.
 *
 * It prints the same line format the matrix parser expects:
 *   probe N: OOB WRITE 62 bytes (vulnerable stub active)
 *   probe N: no OOB
 * Later "no OOB" lines mean no overwrite was observed in those samples, not proof
 * that attach succeeded or every later decode is safe.
 *
 * Optional arg: max number of probes before exiting (default: run forever).
 */
public final class LiveProbe {
    private static volatile int sink;
    private static final Charset ASCII = Charset.forName("US-ASCII");

    private static int ceilDiv(int a, int b) { return (a + b - 1) / b; }

    private static byte[] malformed(int numA) {
        byte[] m = new byte[numA + 1];
        Arrays.fill(m, (byte) 'A');
        m[numA] = (byte) '=';
        return m;
    }

    /** @return changed bytes beyond the calculated output length, inside the backing array. */
    private static int probeOnce(Base64.Decoder dec, byte[] input, int bufferLen, byte[] target) {
        Arrays.fill(target, (byte) 0x5a);
        try { dec.decode(input, target); } catch (IllegalArgumentException expected) { }
        int changed = 0;
        for (int i = bufferLen; i < target.length; i++) if (target[i] != (byte) 0x5a) changed++;
        return changed;
    }

    public static void main(String[] a) {
        int maxProbes = a.length > 0 ? Integer.parseInt(a[0]) : Integer.MAX_VALUE;
        Base64.Decoder dec = Base64.getDecoder();

        byte[] warmSrc = new byte[256]; Arrays.fill(warmSrc, (byte) 'A');
        byte[] warmOut = new byte[256];
        byte[] m64 = malformed(64), m128 = malformed(128);
        int buf64 = ceilDiv(65, 4) * 3 - 1, buf128 = ceilDiv(129, 4) * 3 - 1;
        byte[] target = new byte[4096];

        System.out.println("harness " + System.getProperty("java.runtime.version"));
        System.out.flush();

        for (int n = 1; n <= maxProbes; n++) {
            long end = System.currentTimeMillis() + 1000;
            while (System.currentTimeMillis() < end)
                for (int i = 0; i < 2000; i++) sink += dec.decode(warmSrc, warmOut); // keep decode0 hot
            int oob = Math.max(probeOnce(dec, m64, buf64, target), probeOnce(dec, m128, buf128, target));
            System.out.println("probe " + n + ": " + (oob > 0
                    ? "OOB WRITE " + oob + " bytes (vulnerable stub active)" : "no OOB"));
            System.out.flush();
        }
    }
}
