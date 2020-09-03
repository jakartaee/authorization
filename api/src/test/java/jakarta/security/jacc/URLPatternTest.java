package jakarta.security.jacc;

public class URLPatternTest {
  private final static int DEPTH_IS_ALWAYS_1 = 1;

  private static void assertDepthForPattern(int expected, int actual, String pattern) {
    assert actual == expected : "For '" + pattern + "' pattern expected depth is " + expected;
  }

  public void testDepthOfDefaultPattern() {
    URLPattern spec = new URLPattern();

    int depth = spec.getPatternDepth();

    assertDepthForPattern(DEPTH_IS_ALWAYS_1, depth, "<default>");
  }

  public void testDepthOfRoot() {
    URLPattern spec = new URLPattern("/");

    int depth = spec.getPatternDepth();

    assertDepthForPattern(DEPTH_IS_ALWAYS_1, depth, "/");
  }

  public void testDepthOfTwoSlashPattern() {
    URLPattern spec = new URLPattern("/unit/test");

    int depth = spec.getPatternDepth();

    assertDepthForPattern(DEPTH_IS_ALWAYS_1, depth, "/unit/test");
  }

  public void testDepthOfThreeSlashPattern() {
    URLPattern spec = new URLPattern("/unit/test/");

    int depth = spec.getPatternDepth();

    assertDepthForPattern(DEPTH_IS_ALWAYS_1, depth, "/unit/test/");
  }

  public void testDepthOfTwoImmediateSlashPattern() {
    URLPattern spec = new URLPattern("/unit//test/");

    int depth = spec.getPatternDepth();

    assertDepthForPattern(DEPTH_IS_ALWAYS_1, depth, "/unit//test/");
  }

  public void testDepthOfTwoImmediateSlashAtBeginingPattern() {
    URLPattern spec = new URLPattern("//unit/test/");

    int depth = spec.getPatternDepth();

    assertDepthForPattern(DEPTH_IS_ALWAYS_1, depth, "//unit/test/");
  }
}
