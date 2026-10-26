package ir.sirgsm.vpnshare;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public final class RootShell {
    private RootShell() {}

    public static Result run(String script, int timeoutSeconds) {
        Process process = null;
        try {
            process = new ProcessBuilder("su", "-c", script).redirectErrorStream(true).start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new Result(-1, "Root command timed out.");
            }
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null && output.length() < 32_768) output.append(line).append('\n');
            }
            return new Result(process.exitValue(), output.toString().trim());
        } catch (Exception error) {
            if (process != null) process.destroyForcibly();
            return new Result(-1, error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }

    public static boolean available() {
        Result result = run("id -u", 5);
        return result.code == 0 && "0".equals(result.output.trim());
    }

    public record Result(int code, String output) {}
}
