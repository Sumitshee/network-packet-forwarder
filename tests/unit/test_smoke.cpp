#include <gtest/gtest.h>

// Phase 0 has no production code. This exists to prove the toolchain, the presets, the
// sanitizers and CI are wired together before anything depends on them.
TEST(Smoke, OnePlusOne) {
  EXPECT_EQ(1 + 1, 2);
}
