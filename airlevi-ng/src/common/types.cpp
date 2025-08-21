#include "common/types.h"
#include <iomanip>
#include <sstream>
#include <cstring>

namespace airlevi {

std::string MacAddress::toString() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

bool MacAddress::operator==(const MacAddress& other) const {
    return memcmp(bytes, other.bytes, 6) == 0;
}

bool MacAddress::operator<(const MacAddress& other) const {
    return memcmp(bytes, other.bytes, 6) < 0;
}

} // namespace airlevi
