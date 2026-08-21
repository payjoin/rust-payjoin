#pragma once

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "payjoin.hpp"

// In-memory persisters backing the JSON session persister callback traits,
// mirroring payjoin-ffi/python/test/utils.py.
class InMemoryReceiverPersister : public payjoin::JsonReceiverSessionPersister {
public:
  std::vector<std::string> events;
  bool closed = false;

  void save(const std::string &event) override { events.push_back(event); }
  std::vector<std::string> load() override { return events; }
  void close() override { closed = true; }
};

class InMemorySenderPersister : public payjoin::JsonSenderSessionPersister {
public:
  std::vector<std::string> events;
  bool closed = false;

  void save(const std::string &event) override { events.push_back(event); }
  std::vector<std::string> load() override { return events; }
  void close() override { closed = true; }
};

inline std::vector<uint8_t> from_hex(const std::string &hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(
        static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

// The OHTTP key configuration used across the python and C# unit tests.
inline std::shared_ptr<payjoin::OhttpKeys> test_ohttp_keys() {
  return payjoin::OhttpKeys::decode(from_hex(
      "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb4"
      "83824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d3709570004"
      "00010003"));
}

// Minimal test harness: run a void() callable, report pass/fail, and keep a
// global failure count for the process exit code.
inline int failed_tests = 0;

template <typename F> void run_test(const std::string &name, F &&f) {
  try {
    f();
    std::cout << "PASS " << name << std::endl;
  } catch (const std::exception &e) {
    ++failed_tests;
    std::cout << "FAIL " << name << ": " << e.what() << std::endl;
  } catch (...) {
    ++failed_tests;
    std::cout << "FAIL " << name << ": unknown exception" << std::endl;
  }
}

#define EXPECT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      throw std::runtime_error("expectation failed: " #cond);                  \
    }                                                                          \
  } while (0)
