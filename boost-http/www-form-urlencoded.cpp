#include "www-form-urlencoded.h"
#include <algorithm>

namespace cocoon {

namespace http {

static td::uint8 decode_hex(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  } else if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  } else {
    return 0;
  }
}

static std::string url_decode(td::Slice in) {
  std::string out;
  out.reserve(in.size());

  while (in.size() > 0) {
    if (in[0] == '+') {
      out.push_back(' ');
      in.remove_prefix(1);
    } else if (in[0] == '%' && in.size() >= 3) {
      out.push_back((char)(decode_hex(in[1]) * 16 + decode_hex(in[2])));
      in.remove_prefix(3);
    } else {
      out.push_back(in[0]);
      in.remove_prefix(1);
    }
  }

  return out;
}

std::vector<std::pair<std::string, std::string>> parse_x_www_form_urlencoded(td::Slice body) {
  std::vector<std::pair<std::string, std::string>> res;

  while (body.size() > 0) {
    auto amp = body.find('&');
    if (amp == body.npos) {
      amp = body.size();
    }

    size_t eq = body.find('=');
    if (eq != body.npos && eq < amp) {
      auto key = url_decode(body.copy().truncate(eq));
      auto value = url_decode(body.copy().truncate(amp).remove_prefix(eq + 1));
      res.emplace_back(std::move(key), std::move(value));
    } else {
      auto key = url_decode(body.copy().truncate(amp));
      res.emplace_back(std::move(key), "");
    }

    body.remove_prefix(std::min<size_t>(amp + 1, body.size()));
  }

  std::sort(res.begin(), res.end());

  return res;
}

}  // namespace http

}  // namespace cocoon
