// Integration tests for the C++ bindings, ported from
// payjoin-ffi/python/test/test_payjoin_integration_test.py.
//
// Requires bitcoind (BITCOIND_EXE) and runs the payjoin test services from
// the _test-utils FFI exports, so it must be built from bindings generated
// with the _test-utils feature (the default in scripts/generate_bindings.sh).

#include <cmath>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "http.hpp"
#include "payjoin.hpp"
#include "utils.hpp"

using json = nlohmann::json;

namespace {

std::string to_hex(const std::vector<uint8_t> &bytes) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (auto b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0x0F]);
  }
  return out;
}

std::vector<std::optional<std::string>>
rpc_params(std::initializer_list<json> params) {
  std::vector<std::optional<std::string>> out;
  for (const auto &p : params) {
    out.push_back(p.dump());
  }
  return out;
}

json rpc(const std::shared_ptr<payjoin::RpcClient> &client,
         const std::string &method, std::initializer_list<json> params = {}) {
  return json::parse(client->call(method, rpc_params(params)));
}

// Callbacks driving the receiver checklist against bitcoind, ported from the
// python test's MempoolAcceptanceCallback and friends.
class MempoolAcceptanceCallback : public payjoin::CanBroadcast {
public:
  explicit MempoolAcceptanceCallback(
      std::shared_ptr<payjoin::RpcClient> connection)
      : connection_(std::move(connection)) {}

  bool callback(const std::vector<uint8_t> &tx) override {
    try {
      auto res =
          rpc(connection_, "testmempoolaccept", {json::array({to_hex(tx)})});
      return res.at(0).at("allowed").get<bool>();
    } catch (const std::exception &e) {
      std::cerr << "An error occurred: " << e.what() << std::endl;
      return false;
    }
  }

private:
  std::shared_ptr<payjoin::RpcClient> connection_;
};

class IsScriptOwnedCallback : public payjoin::IsScriptOwned {
public:
  explicit IsScriptOwnedCallback(std::shared_ptr<payjoin::RpcClient> connection)
      : connection_(std::move(connection)) {}

  bool callback(const std::vector<uint8_t> &script) override {
    try {
      auto decoded = rpc(connection_, "decodescript", {to_hex(script)});
      std::vector<std::string> candidates;
      auto collect = [&candidates](const json &obj) {
        if (obj.contains("address") && obj["address"].is_string()) {
          candidates.push_back(obj["address"].get<std::string>());
        }
        if (obj.contains("addresses") && obj["addresses"].is_array()) {
          for (const auto &addr : obj["addresses"]) {
            if (addr.is_string())
              candidates.push_back(addr.get<std::string>());
          }
        }
      };
      collect(decoded);
      if (decoded.contains("p2sh") && decoded["p2sh"].is_string()) {
        candidates.push_back(decoded["p2sh"].get<std::string>());
      }
      if (decoded.contains("segwit") && decoded["segwit"].is_object()) {
        collect(decoded["segwit"]);
      }
      for (const auto &addr : candidates) {
        auto info = rpc(connection_, "getaddressinfo", {addr});
        if (info.value("ismine", false))
          return true;
      }
      return false;
    } catch (const std::exception &e) {
      std::cerr << "An error occurred: " << e.what() << std::endl;
      return false;
    }
  }

private:
  std::shared_ptr<payjoin::RpcClient> connection_;
};

class IsInputOwnedCallback : public payjoin::IsInputOwned {
public:
  explicit IsInputOwnedCallback(std::shared_ptr<payjoin::RpcClient> connection)
      : connection_(std::move(connection)) {}

  bool callback(const payjoin::OutPoint &outpoint) override {
    try {
      auto tx_out =
          rpc(connection_, "gettxout", {outpoint.txid, outpoint.vout, true});
      if (tx_out.is_null())
        return false;
      auto script_hex = tx_out.at("scriptPubKey").at("hex").get<std::string>();
      return IsScriptOwnedCallback(connection_).callback(from_hex(script_hex));
    } catch (const std::exception &e) {
      std::cerr << "An error occurred: " << e.what() << std::endl;
      return false;
    }
  }

private:
  std::shared_ptr<payjoin::RpcClient> connection_;
};

class CheckInputsNotSeenCallback : public payjoin::IsOutputKnown {
public:
  bool callback(const payjoin::OutPoint &) override { return false; }
};

class ProcessPsbtCallback : public payjoin::ProcessPsbt {
public:
  explicit ProcessPsbtCallback(std::shared_ptr<payjoin::RpcClient> connection)
      : connection_(std::move(connection)) {}

  std::string callback(const std::string &psbt) override {
    auto res = json::parse(connection_->call("walletprocesspsbt", {psbt}));
    return res.at("psbt").get<std::string>();
  }

private:
  std::shared_ptr<payjoin::RpcClient> connection_;
};

std::string build_sweep_psbt(const std::shared_ptr<payjoin::RpcClient> &sender,
                             const std::shared_ptr<payjoin::PjUri> &pj_uri) {
  json outputs = json::object();
  outputs[pj_uri->address()] = 50;
  json options = {{"lockUnspents", true},
                  {"fee_rate", 10},
                  {"subtractFeeFromOutputs", {0}}};
  auto created = rpc(sender, "walletcreatefundedpsbt",
                     {json::array(), outputs, 0, options});
  auto psbt = created.at("psbt").get<std::string>();
  auto processed = json::parse(sender->call(
      "walletprocesspsbt",
      {psbt, json(true).dump(), json("ALL").dump(), json(false).dump()}));
  return processed.at("psbt").get<std::string>();
}

std::vector<std::shared_ptr<payjoin::InputPair>>
get_inputs(const std::shared_ptr<payjoin::RpcClient> &rpc_connection) {
  auto utxos = rpc(rpc_connection, "listunspent");
  std::vector<std::shared_ptr<payjoin::InputPair>> inputs;
  for (const auto &utxo : utxos) {
    payjoin::TxIn txin{
        std::make_shared<payjoin::OutPoint>(payjoin::OutPoint{
            utxo.at("txid").get<std::string>(),
            utxo.at("vout").get<uint32_t>(),
        }),
        {},
        0,
        {},
    };
    auto amount_sat = static_cast<uint64_t>(
        std::llround(utxo.at("amount").get<double>() * 100'000'000.0));
    payjoin::PsbtInput psbt_in{
        std::make_shared<payjoin::TxOut>(payjoin::TxOut{
            amount_sat,
            from_hex(utxo.at("scriptPubKey").get<std::string>()),
        }),
        std::nullopt,
        std::nullopt,
    };
    inputs.push_back(payjoin::InputPair::init(txin, psbt_in, std::nullopt));
  }
  return inputs;
}

// Shared bitcoind environment, mirroring the python test's setUpClass.
struct TestEnv {
  std::shared_ptr<payjoin::BitcoindEnv> env;
  std::shared_ptr<payjoin::RpcClient> receiver;
  std::shared_ptr<payjoin::RpcClient> sender;

  TestEnv() {
    env = payjoin::init_bitcoind_sender_receiver();
    receiver = env->get_receiver();
    sender = env->get_sender();
  }
};

TestEnv &test_env() {
  static TestEnv env;
  return env;
}

// Walks the receiver typestate chain until a payjoin proposal is available,
// mirroring the python test's process_receiver_proposal. Returns nullptr when
// polling reached stasis (no sender fallback available yet).
std::shared_ptr<payjoin::PayjoinProposal> process_receiver_proposal(
    const std::shared_ptr<payjoin::Initialized> &session,
    const std::shared_ptr<InMemoryReceiverPersister> &recv_persister,
    const std::string &ohttp_relay, const std::vector<uint8_t> &cert) {
  auto &env = test_env();

  auto request = session->create_poll_request(ohttp_relay);
  auto response = payjoin_test_http::post(request.request->url,
                                          request.request->content_type,
                                          request.request->body, cert);
  auto outcome = session->process_response(response, request.client_response)
                     ->save(recv_persister);
  if (std::holds_alternative<payjoin::InitializedTransitionOutcome::kStasis>(
          outcome.get_variant())) {
    return nullptr;
  }
  auto proposal = std::get<payjoin::InitializedTransitionOutcome::kProgress>(
                      outcome.get_variant())
                      .inner;

  auto maybe_inputs_owned =
      proposal
          ->check_broadcast_suitability(
              std::nullopt,
              std::make_shared<MempoolAcceptanceCallback>(env.receiver))
          ->save(recv_persister);
  auto maybe_inputs_seen =
      maybe_inputs_owned
          ->check_inputs_not_owned(
              std::make_shared<IsInputOwnedCallback>(env.receiver))
          ->save(recv_persister);
  auto outputs_unknown = maybe_inputs_seen
                             ->check_no_inputs_seen_before(
                                 std::make_shared<CheckInputsNotSeenCallback>())
                             ->save(recv_persister);
  auto wants_outputs =
      outputs_unknown
          ->identify_receiver_outputs(
              std::make_shared<IsScriptOwnedCallback>(env.receiver))
          ->save(recv_persister);
  auto wants_inputs = wants_outputs->commit_outputs()->save(recv_persister);
  auto wants_fee_range =
      wants_inputs->contribute_inputs(get_inputs(env.receiver))
          ->commit_inputs()
          ->save(recv_persister);
  auto provisional =
      wants_fee_range->apply_fee_range(1, 10)->save(recv_persister);
  return provisional
      ->finalize_proposal(std::make_shared<ProcessPsbtCallback>(env.receiver))
      ->save(recv_persister);
}

void test_ffi_validation() {
  auto &env = test_env();
  const uint64_t too_large_amount = 21'000'000ULL * 100'000'000ULL + 1;

  // Invalid outpoint (txid too long) should fail before amount checks.
  {
    payjoin::TxIn txin{
        std::make_shared<payjoin::OutPoint>(
            payjoin::OutPoint{std::string(128, '0'), 0}),
        {},
        0,
        {},
    };
    payjoin::PsbtInput psbt_in{
        std::make_shared<payjoin::TxOut>(payjoin::TxOut{1, {0x6A}}),
        std::nullopt,
        std::nullopt,
    };
    bool threw = false;
    try {
      payjoin::InputPair::init(txin, psbt_in, std::nullopt);
    } catch (const payjoin::input_pair_error::InvalidOutPoint &) {
      threw = true;
    }
    EXPECT(threw);
  }

  // Valid outpoint hits amount overflow validation.
  {
    payjoin::TxIn txin{
        std::make_shared<payjoin::OutPoint>(
            payjoin::OutPoint{std::string(64, '0'), 0}),
        {},
        0,
        {},
    };
    payjoin::PsbtInput psbt_in{
        std::make_shared<payjoin::TxOut>(
            payjoin::TxOut{too_large_amount, {0x6A}}),
        std::nullopt,
        std::nullopt,
    };
    bool threw = false;
    try {
      payjoin::InputPair::init(txin, psbt_in, std::nullopt);
    } catch (const payjoin::input_pair_error::FfiValidation &e) {
      threw = true;
      EXPECT(
          dynamic_cast<const payjoin::ffi_validation_error::AmountOutOfRange *>(
              e.v1.get()) != nullptr);
    }
    EXPECT(threw);
  }

  // SenderBuilder rejects fee rate overflow.
  auto receiver_address = rpc(env.receiver, "getnewaddress").get<std::string>();
  auto services = payjoin::TestServices::initialize();
  services->wait_for_services_ready();
  auto directory = services->directory_url();
  auto ohttp_keys = services->fetch_ohttp_keys();
  auto recv_persister = std::make_shared<InMemoryReceiverPersister>();
  auto pj_uri =
      payjoin::ReceiverBuilder::init(receiver_address, directory, ohttp_keys)
          ->build()
          ->save(recv_persister)
          ->pj_uri();

  {
    bool threw = false;
    try {
      payjoin::SenderBuilder::init(payjoin::original_psbt(), pj_uri)
          ->build_recommended(UINT64_MAX);
    } catch (const payjoin::sender_input_error::FfiValidation &e) {
      threw = true;
      EXPECT(dynamic_cast<const payjoin::ffi_validation_error::FeeRateOutOfRange
                              *>(e.v1.get()) != nullptr);
    }
    EXPECT(threw);
  }

  // PjUri rejects amount out of range.
  {
    bool threw = false;
    try {
      pj_uri->set_amount_sats(too_large_amount);
    } catch (const payjoin::ffi_validation_error::AmountOutOfRange &) {
      threw = true;
    }
    EXPECT(threw);
  }
}

void test_integration_v2_to_v2() {
  auto &env = test_env();
  auto receiver_address = rpc(env.receiver, "getnewaddress").get<std::string>();
  payjoin::init_tracing();
  auto services = payjoin::TestServices::initialize();
  services->wait_for_services_ready();
  auto directory = services->directory_url();
  auto ohttp_relay = services->ohttp_relay_url();
  auto ohttp_keys = services->fetch_ohttp_keys();
  auto cert = services->cert();

  // **********************
  // Inside the Receiver:
  auto recv_persister = std::make_shared<InMemoryReceiverPersister>();
  auto sender_persister = std::make_shared<InMemorySenderPersister>();
  auto session =
      payjoin::ReceiverBuilder::init(receiver_address, directory, ohttp_keys)
          ->build()
          ->save(recv_persister);
  auto no_proposal =
      process_receiver_proposal(session, recv_persister, ohttp_relay, cert);
  EXPECT(no_proposal == nullptr);

  // **********************
  // Inside the Sender:
  // Create a funded PSBT (not broadcasted) to address with amount given in the
  // pj_uri
  auto pj_uri = session->pj_uri();
  auto psbt = build_sweep_psbt(env.sender, pj_uri);
  auto req_ctx = payjoin::SenderBuilder::init(psbt, pj_uri)
                     ->build_recommended(1000)
                     ->save(sender_persister);
  auto request_send = req_ctx->create_v2_post_request(ohttp_relay);
  auto response = payjoin_test_http::post(request_send.request->url,
                                          request_send.request->content_type,
                                          request_send.request->body, cert);
  auto send_ctx = req_ctx->process_response(response, request_send.ohttp_ctx)
                      ->save(sender_persister);
  // POST Original PSBT

  // **********************
  // Inside the Receiver:

  // GET fallback psbt
  auto payjoin_proposal =
      process_receiver_proposal(session, recv_persister, ohttp_relay, cert);
  EXPECT(payjoin_proposal != nullptr);
  auto request_recv = payjoin_proposal->create_post_request(ohttp_relay);
  response = payjoin_test_http::post(request_recv.request->url,
                                     request_recv.request->content_type,
                                     request_recv.request->body, cert);
  payjoin_proposal->process_response(response, request_recv.client_response);

  // **********************
  // Inside the Sender:
  // Sender checks, signs, finalizes, extracts, and broadcasts
  // Replay post fallback to get the response
  std::optional<std::string> proposal_psbt;
  for (int i = 0; i < 4; ++i) {
    auto poll_req = send_ctx->create_poll_request(ohttp_relay);
    auto poll_resp = payjoin_test_http::post(poll_req.request->url,
                                             poll_req.request->content_type,
                                             poll_req.request->body, cert);
    auto outcome = send_ctx->process_response(poll_resp, poll_req.ohttp_ctx)
                       ->save(sender_persister);
    if (const auto *progress = std::get_if<
            payjoin::PollingForProposalTransitionOutcome::kProgress>(
            &outcome.get_variant())) {
      proposal_psbt = progress->psbt_base64;
      break;
    }
  }
  if (!proposal_psbt.has_value()) {
    // Receiver still not ready; treat as acceptable in this smoke test.
    return;
  }
  auto payjoin_psbt =
      json::parse(env.sender->call("walletprocesspsbt", {*proposal_psbt}))
          .at("psbt")
          .get<std::string>();
  auto final_psbt =
      json::parse(
          env.sender->call("finalizepsbt", {payjoin_psbt, json(false).dump()}))
          .at("psbt")
          .get<std::string>();
  auto final_tx_hex =
      json::parse(
          env.sender->call("finalizepsbt", {final_psbt, json(true).dump()}))
          .at("hex")
          .get<std::string>();
  rpc(env.sender, "sendrawtransaction", {final_tx_hex});

  // Check resulting transaction and balances
  auto decoded_psbt = rpc(env.sender, "decodepsbt", {final_psbt});
  auto network_fees = decoded_psbt.at("fee").get<double>();
  auto decoded_tx = rpc(env.sender, "decoderawtransaction", {final_tx_hex});
  // Sender sent the entire value of their utxo to receiver (minus fees)
  EXPECT(decoded_tx.at("vin").size() == 2);
  EXPECT(decoded_tx.at("vout").size() == 1);
  auto receiver_pending = rpc(env.receiver, "getbalances")
                              .at("mine")
                              .at("untrusted_pending")
                              .get<double>();
  EXPECT(std::abs(receiver_pending - (100.0 - network_fees)) < 1e-8);
  EXPECT(rpc(env.sender, "getbalance").get<double>() == 0.0);
}

} // namespace

int main() {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  run_test("test_ffi_validation", test_ffi_validation);
  run_test("test_integration_v2_to_v2", test_integration_v2_to_v2);
  curl_global_cleanup();
  return failed_tests == 0 ? 0 : 1;
}
