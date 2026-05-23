#include <vector>
#include "td/utils/Slice.h"

namespace cocoon {

namespace http {

std::vector<std::pair<std::string, std::string>> parse_x_www_form_urlencoded(td::Slice body);

}

}  // namespace cocoon
