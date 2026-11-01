# Regression tests

Configure a release build, then run CTest:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

`startup_readiness.cc` uses the public decoder API, synthetic PAT/PMT/ECM
sections, and a fake card with test-only keys. It requires no physical reader,
card, or broadcast recording. The same tests run against the B1 and B25 builds.
They cover delayed PMTs/ECMs, repeated tables, byte-sized and packet-sized
input, free-to-air streams, reset, sparse PAT/ECM entries during streaming and at EOF, and the existing
32 MiB missing-table limits. Use `-DBUILD_TESTING=OFF` to omit these targets.

`multi2_kat.cc` contains the existing MULTI2 known-answer tests. The build
workflow compiles and runs it separately for the selected SIMD implementation.
