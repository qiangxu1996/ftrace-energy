# ftrace-energy

Script to measure Android energy consumption using ftrace-based power models.

## Setup

```bash
conda create -n ftrace poetry
conda activate ftrace
git clone https://github.com/qiangxu1996/ftrace-energy.git
cd ftrace-energy
poetry install
cd ftrace_energy
$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android$MIN_SDK_VERSION-clang++ gettime.cpp -o gettime
```

## Usage

Create a `FtraceEnergy` object, and call `prepare()`, `start()`, and `stop_and_calc()` in order.

The `models.json` provided is for Pixel 2.

