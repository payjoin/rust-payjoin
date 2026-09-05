// Unit tests for the C++ bindings, ported from
// payjoin-ffi/python/test/test_payjoin_unit_test.py.
//
// The async persistence variants are not ported: the C++ generator skips
// async exports (see scripts/generate_bindings.sh).

#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "payjoin.hpp"
#include "utils.hpp"

namespace {

const char *kReceiverAddress = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
const char *kSenderReceiverAddress = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
const char *kDirectory = "https://example.com";

void test_todo_url_encoded() {
  auto uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://"
             "example.com?ciao";
  EXPECT(payjoin::Url::parse(uri) != nullptr);
}

void test_valid_url() {
  auto uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://"
             "example.com?ciao";
  EXPECT(payjoin::Url::parse(uri) != nullptr);
}

void test_missing_amount() {
  auto uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://"
             "testnet.demo.btcpayserver.org/BTC/pj";
  EXPECT(payjoin::Url::parse(uri) != nullptr);
}

void test_valid_uris() {
  auto https = payjoin::example_url();
  auto onion =
      "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";

  std::vector<std::string> addresses = {
      "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
      "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4",
      "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
  };
  for (const auto &address : addresses) {
    for (const auto &pj : {https, std::string(onion)}) {
      auto uri = address + "?amount=1&pj=" + pj;
      EXPECT(payjoin::Url::parse(uri) != nullptr);
    }
  }
}

void test_receiver_persistence() {
  auto persister = std::make_shared<InMemoryReceiverPersister>();
  payjoin::ReceiverBuilder::init(kReceiverAddress, kDirectory,
                                 test_ohttp_keys())
      ->build()
      ->save(persister);
  auto result = payjoin::replay_receiver_event_log(persister);
  EXPECT(std::holds_alternative<payjoin::ReceiveSession::kInitialized>(
      result->state().get_variant()));
}

void test_sender_persistence() {
  // Create a receiver to just get the pj uri
  auto recv_persister = std::make_shared<InMemoryReceiverPersister>();
  auto receiver = payjoin::ReceiverBuilder::init(kSenderReceiverAddress,
                                                 kDirectory, test_ohttp_keys())
                      ->build()
                      ->save(recv_persister);
  auto uri = receiver->pj_uri();

  auto persister = std::make_shared<InMemorySenderPersister>();
  auto psbt = payjoin::original_psbt();
  auto with_reply_key =
      payjoin::SenderBuilder::init(psbt, uri)->build_recommended(1000)->save(
          persister);
  EXPECT(with_reply_key != nullptr);
}

void test_receiver_cancel() {
  auto persister = std::make_shared<InMemoryReceiverPersister>();
  auto initialized = payjoin::ReceiverBuilder::init(
                         kReceiverAddress, kDirectory, test_ohttp_keys())
                         ->build()
                         ->save(persister);
  auto cancel_transition = initialized->cancel();
  auto fallback = cancel_transition->save(persister);
  EXPECT(fallback == nullptr);
  auto result = payjoin::replay_receiver_event_log(persister);
  EXPECT(std::holds_alternative<payjoin::ReceiveSession::kClosed>(
      result->state().get_variant()));
}

void test_sender_cancel() {
  // Create a receiver to just get the pj uri
  auto recv_persister = std::make_shared<InMemoryReceiverPersister>();
  auto receiver = payjoin::ReceiverBuilder::init(kSenderReceiverAddress,
                                                 kDirectory, test_ohttp_keys())
                      ->build()
                      ->save(recv_persister);
  auto uri = receiver->pj_uri();

  auto persister = std::make_shared<InMemorySenderPersister>();
  auto psbt = payjoin::original_psbt();
  auto with_reply_key =
      payjoin::SenderBuilder::init(psbt, uri)->build_recommended(1000)->save(
          persister);
  auto cancel_transition = with_reply_key->cancel();
  auto pending_fallback = cancel_transition->save(persister);
  EXPECT(pending_fallback != nullptr);
  EXPECT(!pending_fallback->fallback_tx().empty());
  auto result = payjoin::replay_sender_event_log(persister);
  EXPECT(std::holds_alternative<payjoin::SendSession::kSenderPendingFallback>(
      result->state().get_variant()));
  pending_fallback->close()->save(persister);
  result = payjoin::replay_sender_event_log(persister);
  EXPECT(std::holds_alternative<payjoin::SendSession::kClosed>(
      result->state().get_variant()));
}

void test_receiver_builder_rejects_bad_address() {
  bool threw = false;
  try {
    payjoin::ReceiverBuilder::init("not-an-address", kDirectory,
                                   test_ohttp_keys());
  } catch (const std::exception &) {
    threw = true;
  }
  EXPECT(threw);
}

void test_input_pair_rejects_invalid_outpoint() {
  bool threw = false;
  try {
    payjoin::TxIn txin{
        std::make_shared<payjoin::OutPoint>(payjoin::OutPoint{"deadbeef", 0}),
        {},
        0,
        {},
    };
    payjoin::PsbtInput psbtin{std::nullopt, std::nullopt, std::nullopt};
    payjoin::InputPair::init(txin, psbtin, std::nullopt);
  } catch (const std::exception &) {
    threw = true;
  }
  EXPECT(threw);
}

void test_sender_builder_rejects_bad_psbt() {
  auto uri =
      payjoin::Uri::parse("bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?"
                          "pj=https://example.com/pj")
          ->check_pj_supported();
  bool threw = false;
  try {
    payjoin::SenderBuilder::init("not-a-psbt", uri);
  } catch (const std::exception &) {
    threw = true;
  }
  EXPECT(threw);
}

} // namespace

int main() {
  run_test("test_todo_url_encoded", test_todo_url_encoded);
  run_test("test_valid_url", test_valid_url);
  run_test("test_missing_amount", test_missing_amount);
  run_test("test_valid_uris", test_valid_uris);
  run_test("test_receiver_persistence", test_receiver_persistence);
  run_test("test_sender_persistence", test_sender_persistence);
  run_test("test_receiver_cancel", test_receiver_cancel);
  run_test("test_sender_cancel", test_sender_cancel);
  run_test("test_receiver_builder_rejects_bad_address",
           test_receiver_builder_rejects_bad_address);
  run_test("test_input_pair_rejects_invalid_outpoint",
           test_input_pair_rejects_invalid_outpoint);
  run_test("test_sender_builder_rejects_bad_psbt",
           test_sender_builder_rejects_bad_psbt);
  return failed_tests == 0 ? 0 : 1;
}
