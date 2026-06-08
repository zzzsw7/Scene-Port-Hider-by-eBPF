#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_DIR="${DEPS_DIR:-$ROOT/deps}"
PREFIX="${PREFIX:-$DEPS_DIR/android-arm64}"
ANDROID_API="${ANDROID_API:-26}"
ANDROID_NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-}}"
JOBS="${JOBS:-$(nproc)}"

if [[ -z "$ANDROID_NDK" ]]; then
    echo "Set ANDROID_NDK or ANDROID_NDK_HOME to your Android NDK path." >&2
    exit 1
fi

HOST_TAG="linux-x86_64"
TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG"
export AR="$TOOLCHAIN/bin/llvm-ar"
export AS="$TOOLCHAIN/bin/llvm-as"
export CC="$TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang"
export CXX="$TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang++"
export LD="$TOOLCHAIN/bin/ld.lld"
export RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
export STRIP="$TOOLCHAIN/bin/llvm-strip"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"
export UAPI_COMPAT_CFLAGS="-D__user= -D__force= -D__iomem= -D__must_check= -DSHT_GNU_verdef=0x6ffffffd -DSHT_GNU_verneed=0x6ffffffe -DSHT_GNU_versym=0x6fffffff"
export CFLAGS="${CFLAGS:-} -fPIC $UAPI_COMPAT_CFLAGS"
export CPPFLAGS="${CPPFLAGS:-} -I$PREFIX/include"
export LDFLAGS="${LDFLAGS:-}"

mkdir -p "$DEPS_DIR/src" "$PREFIX"
cd "$DEPS_DIR/src"

mkdir -p "$PREFIX/include"
if [[ ! -f "$PREFIX/include/libintl.h" ]]; then
    cat > "$PREFIX/include/libintl.h" <<'EOF_STUB'
#ifndef HIDEPORT_STUB_LIBINTL_H
#define HIDEPORT_STUB_LIBINTL_H

#define gettext(String) (String)
#define dgettext(Domain, String) (String)
#define dcgettext(Domain, String, Category) (String)
#define ngettext(String1, String2, N) ((N) == 1 ? (String1) : (String2))
#define dngettext(Domain, String1, String2, N) ((N) == 1 ? (String1) : (String2))
#define dcngettext(Domain, String1, String2, N, Category) ((N) == 1 ? (String1) : (String2))
#define textdomain(Domain) (Domain)
#define bindtextdomain(Domain, Directory) (Directory)
#define bind_textdomain_codeset(Domain, Codeset) (Codeset)

#endif
EOF_STUB
fi

tar_extract() {
    tar --no-same-owner --no-same-permissions -m -xf "$1"
}

tar_topdir() {
    local list_file
    local first

    list_file="$(mktemp)"
    tar tf "$1" > "$list_file"
    IFS= read -r first < "$list_file"
    rm -f "$list_file"
    first="${first%%/*}"

    if [[ -z "$first" ]]; then
        echo "Failed to detect top-level directory in $1" >&2
        return 1
    fi

    printf '%s\n' "$first"
}

fetch() {
    local name="$1"
    local url="$2"
    local archive="$3"
    if [[ ! -f "$archive" ]]; then
        local tmp_archive="${archive}.tmp"
        rm -f "$tmp_archive"
        echo "Fetching $name from $url"
        if ! curl -fL --retry 3 "$url" -o "$tmp_archive"; then
            rm -f "$tmp_archive"
            return 1
        fi
        mv "$tmp_archive" "$archive"
    fi
}

fetch_tar_gz_any() {
    local name="$1"
    local archive="$2"
    shift 2

    if [[ -f "$archive" ]] && tar tzf "$archive" >/dev/null 2>&1; then
        return 0
    fi
    rm -f "$archive"

    local url
    for url in "$@"; do
        if fetch "$name" "$url" "$archive" && tar tzf "$archive" >/dev/null 2>&1; then
            return 0
        fi
        rm -f "$archive"
    done

    echo "Failed to download $name." >&2
    return 1
}

if [[ ! -f "$PREFIX/lib/libz.a" ]]; then
    echo "==> Building zlib"
    fetch_tar_gz_any zlib zlib-1.3.1.tar.gz \
        "https://zlib.net/fossils/zlib-1.3.1.tar.gz" \
        "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"
    zlib_dir="$(tar_topdir zlib-1.3.1.tar.gz)"
    rm -rf "$zlib_dir"
    tar_extract zlib-1.3.1.tar.gz
    (
        cd "$zlib_dir"
        CHOST=aarch64-linux-android ./configure --static --prefix="$PREFIX"
        make -j"$JOBS"
        make install
    )
fi

if [[ ! -f "$PREFIX/lib/libelf.a" ]]; then
    echo "==> Building elfutils libelf"
    fetch elfutils "https://sourceware.org/elfutils/ftp/0.191/elfutils-0.191.tar.bz2" elfutils-0.191.tar.bz2
    rm -rf elfutils-0.191
    tar_extract elfutils-0.191.tar.bz2
    (
        cd elfutils-0.191
        ac_cv_search_argp_parse='none required' \
        ac_cv_func_argp_parse=yes \
        ac_cv_search__obstack_free='none required' \
        ac_cv_func__obstack_free=yes \
        CPPFLAGS="$CPPFLAGS" \
        ./configure \
            --host=aarch64-linux-android \
            --prefix="$PREFIX" \
            --disable-debuginfod \
            --disable-libdebuginfod \
            --disable-debuginfod-urls \
            --disable-nls \
            --disable-shared \
            --enable-static \
            --without-bzlib \
            --without-lzma \
            --without-zstd
        make -j"$JOBS" -C libelf CPPFLAGS="$CPPFLAGS" libelf.a
        install -d "$PREFIX/lib" "$PREFIX/include"
        install -m 0644 libelf/libelf.a "$PREFIX/lib/libelf.a"
        install -m 0644 libelf/libelf.h libelf/gelf.h libelf/nlist.h "$PREFIX/include/"
        install -d "$PREFIX/lib/pkgconfig"
        cat > "$PREFIX/lib/pkgconfig/libelf.pc" <<EOF_PC
prefix=$PREFIX
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libelf
Description: ELF object file access library
Version: 0.191
Libs: -L\${libdir} -lelf
Cflags: -I\${includedir}
EOF_PC
    )
fi

if [[ -f "$PREFIX/lib/libelf.a" && ! -f "$PREFIX/lib/pkgconfig/libelf.pc" ]]; then
    install -d "$PREFIX/lib/pkgconfig"
    cat > "$PREFIX/lib/pkgconfig/libelf.pc" <<EOF_PC
prefix=$PREFIX
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libelf
Description: ELF object file access library
Version: 0.191
Libs: -L\${libdir} -lelf
Cflags: -I\${includedir}
EOF_PC
fi

if [[ ! -f "$PREFIX/lib/libbpf.a" ]]; then
    echo "==> Building libbpf"
    if [[ ! -d libbpf ]]; then
        git clone --depth 1 https://github.com/libbpf/libbpf.git
    fi
    (
        cd libbpf/src
        make -j"$JOBS" \
            CC="$CC" \
            AR="$AR" \
            RANLIB="$RANLIB" \
            BUILD_STATIC_ONLY=1 \
            OBJDIR=build \
            PREFIX="$PREFIX" \
            INCLUDEDIR="$PREFIX/include" \
            LIBDIR="$PREFIX/lib" \
            UAPIDIR="$PREFIX/include" \
            CFLAGS="-I$PREFIX/include -fPIC $UAPI_COMPAT_CFLAGS" \
            LDFLAGS="-L$PREFIX/lib"
        make install \
            BUILD_STATIC_ONLY=1 \
            OBJDIR=build \
            PREFIX="$PREFIX" \
            INCLUDEDIR="$PREFIX/include" \
            LIBDIR="$PREFIX/lib" \
            UAPIDIR="$PREFIX/include"
    )
fi

cat <<EOF
Dependencies are ready:
  PREFIX=$PREFIX
  LIBBPF_INCLUDE_DIR=$PREFIX/include
  LIBBPF_LIBRARY=$PREFIX/lib/libbpf.a
  LIBELF_LIBRARY=$PREFIX/lib/libelf.a
  ZLIB_LIBRARY=$PREFIX/lib/libz.a

To build hideport:
  export ANDROID_NDK="$ANDROID_NDK"
  export LIBBPF_SRC="$PREFIX"
  export LIBBPF_HEADERS="$PREFIX/include"
  export LIBBPF_LIBDIR="$PREFIX/lib"
  export BPFTOOL="${BPFTOOL:-bpftool}"
  ./build.sh
EOF
