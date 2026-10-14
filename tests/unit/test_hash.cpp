#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <npf/pipe/hash.hpp>
#include <random>
#include <vector>

namespace {

using npf::pipe::mix32;
using npf::pipe::symmetric_hash_5tuple;

constexpr int kSamples = 20'000;

struct FiveTuple {
  std::uint32_t sip, dip;
  std::uint16_t sp, dp;
  std::uint8_t proto;
};

FiveTuple random_tuple(std::mt19937& rng) {
  std::uniform_int_distribution<std::uint32_t> u32;
  return {u32(rng), u32(rng), static_cast<std::uint16_t>(u32(rng)),
          static_cast<std::uint16_t>(u32(rng)), static_cast<std::uint8_t>(u32(rng))};
}

std::uint32_t hash(const FiveTuple& t) {
  return symmetric_hash_5tuple(t.sip, t.dip, t.sp, t.dp, t.proto);
}

TEST(SymmetricHash, BothDirectionsOfAFlowHashAlike) {
  std::mt19937 rng(1);
  for (int i = 0; i < kSamples; ++i) {
    const FiveTuple t = random_tuple(rng);
    ASSERT_EQ(hash(t), symmetric_hash_5tuple(t.dip, t.sip, t.dp, t.sp, t.proto));
  }
}

// The price of symmetry, pinned down so that it is a known property rather than a surprise: the
// two XORs cannot tell which port went with which address, so swapping only the addresses (or
// only the ports) gives the same hash -- A:a -> B:b and B:a -> A:b always share a worker.
TEST(SymmetricHash, SwappingOnlyTheAddressesCollides) {
  std::mt19937 rng(2);
  for (int i = 0; i < 1000; ++i) {
    const FiveTuple t = random_tuple(rng);
    ASSERT_EQ(hash(t), symmetric_hash_5tuple(t.dip, t.sip, t.sp, t.dp, t.proto));
  }
}

// Anything else that differs is a different flow, and looks like one: the protocol, here.
TEST(SymmetricHash, TheProtocolSeparatesFlows) {
  std::mt19937 rng(5);
  int same = 0;
  for (int i = 0; i < kSamples; ++i) {
    const FiveTuple t = random_tuple(rng);
    same += hash(t) == symmetric_hash_5tuple(t.sip, t.dip, t.sp, t.dp,
                                             static_cast<std::uint8_t>(t.proto ^ 1U))
                ? 1
                : 0;
  }
  EXPECT_LT(same, 5);
}

// The plan's avalanche test: flipping any single input bit flips each output bit with probability
// near one half -- so about 16 of the 32 on average, and no output bit stuck or nearly so.
TEST(Mix32, EveryInputBitFlipsHalfTheOutputBits) {
  std::mt19937 rng(3);
  std::uniform_int_distribution<std::uint32_t> u32;
  for (unsigned bit = 0; bit < 32; ++bit) {
    std::array<int, 32> flips_per_output{};
    long total = 0;
    for (int i = 0; i < kSamples; ++i) {
      const std::uint32_t x = u32(rng);
      const std::uint32_t diff = mix32(x) ^ mix32(x ^ (1U << bit));
      total += std::popcount(diff);
      for (unsigned out = 0; out < 32; ++out) {
        flips_per_output.at(out) += static_cast<int>((diff >> out) & 1U);
      }
    }
    const double mean = static_cast<double>(total) / kSamples;
    EXPECT_NEAR(mean, 16.0, 0.5) << "input bit " << bit;
    for (unsigned out = 0; out < 32; ++out) {
      const double p = static_cast<double>(flips_per_output.at(out)) / kSamples;
      EXPECT_NEAR(p, 0.5, 0.05) << "input bit " << bit << ", output bit " << out;
    }
  }
}

// The same through the whole 5-tuple hash, one field bit at a time.
TEST(SymmetricHash, EveryFieldBitFlipsHalfTheOutputBits) {
  std::mt19937 rng(4);
  const auto flip = [](FiveTuple t, unsigned field_bit) {
    if (field_bit < 32) {
      t.sip ^= 1U << field_bit;
    } else if (field_bit < 64) {
      t.dip ^= 1U << (field_bit - 32);
    } else if (field_bit < 80) {
      t.sp = static_cast<std::uint16_t>(t.sp ^ (1U << (field_bit - 64)));
    } else if (field_bit < 96) {
      t.dp = static_cast<std::uint16_t>(t.dp ^ (1U << (field_bit - 80)));
    } else {
      t.proto = static_cast<std::uint8_t>(t.proto ^ (1U << (field_bit - 96)));
    }
    return t;
  };
  for (unsigned field_bit = 0; field_bit < 104; ++field_bit) {
    long total = 0;
    for (int i = 0; i < kSamples; ++i) {
      const FiveTuple t = random_tuple(rng);
      total += std::popcount(hash(t) ^ hash(flip(t, field_bit)));
    }
    EXPECT_NEAR(static_cast<double>(total) / kSamples, 16.0, 0.5) << "field bit " << field_bit;
  }
}

// What the pipeline does with the hash: keep its low bits as a worker index. Flows that differ
// only a little -- consecutive clients, consecutive source ports, to one server, as a load
// generator makes them -- must still spread evenly over 2, 4, 8 and 16 workers.
TEST(SymmetricHash, SimilarFlowsSpreadEvenlyOverWorkers) {
  constexpr std::uint32_t kServer = 0x0A000202;  // 10.0.2.2
  std::vector<std::uint32_t> hashes;
  for (std::uint32_t client = 0; client < 64; ++client) {
    for (std::uint16_t port = 0; port < 256; ++port) {
      hashes.push_back(symmetric_hash_5tuple(0x0A000100 + client, kServer,
                                             static_cast<std::uint16_t>(10000 + port), 5001, 17));
    }
  }
  for (const std::uint32_t workers : {2U, 4U, 8U, 16U}) {
    std::vector<int> load(workers, 0);
    for (const std::uint32_t h : hashes) {
      ++load.at(h & (workers - 1));
    }
    const double mean = static_cast<double>(hashes.size()) / workers;
    for (std::uint32_t w = 0; w < workers; ++w) {
      EXPECT_NEAR(load.at(w), mean, mean * 0.1) << workers << " workers, worker " << w;
    }
  }
}

}  // namespace
