# Fuzzing Restarts

This repository is part of our paper *[Novelty Not Found: Adaptive Fuzzer Restarts to Improve Input Space Coverage](https://mschloegel.me/paper/schiller2023fuzzerrestarts.pdf)*. Here you can find the codebase for our scheduler `Sileo`, as well as the submodules for Fuzzbench and a patched version of AFL++. We tested Sileo with AFL++ 4.04c and 4.06c. The reports for our experiments can be found in [fuzzbench_reports](fuzzbench_reports)

**Note: If you want to reproduce the results from our paper, please have a look at our [Sileo-Fuzzbench](https://github.com/CISPA-SysSec/fuzzing-restarts-fuzzbench) repository.**

## Setup

1. Clone this repository:

    ```bash
   git clone https://github.com/CISPA-SysSec/fuzzing-restarts.git
    ```

2. Install requirements:

   ```bash
   pip install -r sileo/requirements.txt
   ```

3. Clone [AFL++](https://github.com/AFLplusplus/AFLplusplus):

   ```bash
   git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus && git checkout tags/4.04c
   ```

4. Install AFL++ dependencies (for more information about the installation see [AFL++ Install](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md)):

   ```bash
   sudo apt-get update
   sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev

   sudo apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 || sudo apt-get install -y lld llvm llvm-dev clang
   
   sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
   ```

5. Set llvm-config

   ```bash
   export LLVM_CONFIG=/bin/llvm-config-14
   ```

6. Build AFL++:

   ```bash
   cd AFLplusplus && make source-only && make install
   ```

7. Build your target

8. Find your ALF++ binaries:

    ```bash
    which afl-fuzz
    ```

9.  Start fuzzing using Sileo (use the path obtained from `which` for `afl_bin`). The following uses the corpus retention strategy `corpus_del` which refers to *Corpus Pruning* in our paper and objdump as example target:

   ```bash
   python3 fuzzing-restarts/sileo/sileo_main.py --mode corpus_del --purge --runtime 24 --log INFO --afl_bin path_to_afl_bin/afl-fuzz --afl_seed seeds_dir --afl_out out_dir --afl_target path_to_target/objdump --afl_target_args -s -g -G @@
   ```
