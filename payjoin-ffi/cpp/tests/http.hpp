#pragma once

// Minimal libcurl HTTP POST helper for the integration tests, trusting the
// self-signed certificate served by the local payjoin test services (the role
// python's httpx verify context and C#'s Payjoin.Http.cs play).

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#include <curl/curl.h>

namespace payjoin_test_http {

// DER certificate bytes -> PEM string so libcurl can consume it via
// CURLOPT_CAINFO_BLOB.
inline std::string der_to_pem(const std::vector<uint8_t> &der) {
  static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string b64;
  b64.reserve((der.size() + 2) / 3 * 4);
  for (size_t i = 0; i < der.size(); i += 3) {
    uint32_t chunk = static_cast<uint32_t>(der[i]) << 16;
    if (i + 1 < der.size())
      chunk |= static_cast<uint32_t>(der[i + 1]) << 8;
    if (i + 2 < der.size())
      chunk |= static_cast<uint32_t>(der[i + 2]);
    b64.push_back(table[(chunk >> 18) & 0x3F]);
    b64.push_back(table[(chunk >> 12) & 0x3F]);
    b64.push_back(i + 1 < der.size() ? table[(chunk >> 6) & 0x3F] : '=');
    b64.push_back(i + 2 < der.size() ? table[chunk & 0x3F] : '=');
  }
  std::string pem = "-----BEGIN CERTIFICATE-----\n";
  for (size_t i = 0; i < b64.size(); i += 64) {
    pem += b64.substr(i, 64);
    pem += '\n';
  }
  pem += "-----END CERTIFICATE-----\n";
  return pem;
}

inline size_t write_body(char *ptr, size_t size, size_t nmemb, void *userdata) {
  auto *out = static_cast<std::vector<uint8_t> *>(userdata);
  out->insert(out->end(), ptr, ptr + size * nmemb);
  return size * nmemb;
}

// POST `body` to `url` with the given content type; `cert_der` is the test
// services' root certificate in DER form. Returns the response body and
// throws on transport errors or non-2xx statuses.
inline std::vector<uint8_t> post(const std::string &url,
                                 const std::string &content_type,
                                 const std::vector<uint8_t> &body,
                                 const std::vector<uint8_t> &cert_der) {
  CURL *curl = curl_easy_init();
  if (!curl)
    throw std::runtime_error("curl_easy_init failed");

  std::vector<uint8_t> response;
  std::string pem = der_to_pem(cert_der);
  struct curl_blob ca_blob = {pem.data(), pem.size(), CURL_BLOB_COPY};
  struct curl_slist *headers = nullptr;
  headers =
      curl_slist_append(headers, ("Content-Type: " + content_type).c_str());

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);

  CURLcode res = curl_easy_perform(curl);
  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    throw std::runtime_error(std::string("curl error: ") +
                             curl_easy_strerror(res));
  }
  if (status < 200 || status >= 300) {
    throw std::runtime_error("unexpected HTTP status " +
                             std::to_string(status) + " from " + url);
  }
  return response;
}

} // namespace payjoin_test_http
