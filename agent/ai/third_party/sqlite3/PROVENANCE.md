# SQLite 3.37.2 amalgamation (vendored for T2b)

- Upstream: https://www.sqlite.org/ (public domain)
- Source package: Ubuntu jammy-updates `sqlite3` 3.37.2-2ubuntu0.8
  - mirror: http://mirrors.tuna.tsinghua.edu.cn/ubuntu/pool/main/s/sqlite3/
  - orig tarball: sqlite3_3.37.2.orig.tar.xz
    sha256 3157723da779963f7887f29de12289a4890f0c18eb17b570aa2c8d2c96d31d6f
- Generated with the official toolchain (not hand-written):
    ./configure --disable-shared --enable-static
    make sqlite3.c sqlite3.h
- Verified on L1 (gcc 11.4.0):
    gcc -O2 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=1 -c sqlite3.c
    static test: sqlite=3.37.2 value=42, exit 0, 0 warnings
- Why 3.37.2: matches the system libsqlite3.so.0 that Python 3.10 uses on L1,
  so sqlite-backend differential tests compare like with like.
- Build flags for the product: -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=1
  (no dlopen dependency; link -lpthread -lm).
