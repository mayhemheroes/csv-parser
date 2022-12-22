#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "csv.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString(1000);
    std::string_view sv{str};
    csv::parse_no_header(sv);

    return 0;
}