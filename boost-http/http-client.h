#pragma once

#include "http.h"
#include "td/utils/port/IPAddress.h"

namespace cocoon {

namespace http {

void run_http_request(const td::IPAddress& addr, HttpCallback::RequestType request_type, std::string url,
                      std::vector<std::pair<std::string, std::string>> headers, std::string payload, double timeout,
                      std::unique_ptr<HttpRequestCallback> callback);

}

}  // namespace cocoon
