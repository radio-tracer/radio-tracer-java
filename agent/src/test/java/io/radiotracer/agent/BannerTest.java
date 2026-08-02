package io.radiotracer.agent;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

class BannerTest {

    @Test
    void printIncludesProductName() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Banner.print(new PrintStream(buf));
        String text = buf.toString();
        assertTrue(text.contains("RadioTracer"));
        assertTrue(text.contains("Dynamic Reachability"));
    }
}
