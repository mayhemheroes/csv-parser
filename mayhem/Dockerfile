FROM --platform=linux/amd64 ubuntu:18.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang-10

COPY . /repo
WORKDIR /repo/build
RUN sed -i 's/-Wall -Werror -Wextra/-Wall -Wextra/' /repo/CMakeLists.txt
RUN cmake ..
RUN make -j8
RUN clang++-10 /repo/mayhem/fuzz_parse_no_header.cpp -fsanitize=fuzzer,address -I /repo/mayhem/ -I /repo/single_include -std=c++17 -o /fuzz

FROM ubuntu:18.04 as package
COPY --from=builder /repo/build/programs/csv_info /
COPY --from=builder /fuzz /fuzz_parse_no_header
