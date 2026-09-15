#!/usr/bin/env python3
"""Host-C execution of production BPF helpers, NOT a kernel/verifier test.

Only CO-RE views/clang intrinsics and SEC annotations are adapted for host C.
Every helper/function body is compiled from the current flow.bpf.c unchanged.
BPF helper calls use in-process memory/map/ring-buffer shims in fixture.c.
Iterator field availability and relocated enum values model upstream Linux
v5.10, v5.14, v5.15, v6.1, v6.4 and v6.8 include/linux/uio.h (not BTF relocation proof).
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--case", default="all", choices=["all", "scatter", "identity", "destination"])
parser.add_argument("--source", type=Path)
args = parser.parse_args()
here = Path(__file__).resolve().parent
source = (args.source or here.parents[1] / "bpf/flow.bpf.c").read_text()
# CO-RE local structs are field-name views, not literal target layouts. Supply
# all fixture fields so a missing production field cannot prevent a RED run.
source = re.sub(r"struct iov_iter \{.*?\} __attribute__\(\(preserve_access_index\)\);", """struct iov_iter {
    unsigned char iter_type;
    unsigned int type;
    unsigned long iov_offset, count, nr_segs;
    union { const struct iovec *iov; const struct iovec *__iov; void *ubuf; };
};""", source, count=1, flags=re.S)
source = re.sub(r"struct msghdr \{.*?\} __attribute__\(\(preserve_access_index\)\);", """struct msghdr {
    void *msg_name;
    int msg_namelen;
    struct iov_iter msg_iter;
};""", source, count=1, flags=re.S)
source = source.replace('#define SEC(name) __attribute__((section(name), used))', '#define SEC(name)')
source = source.replace('__attribute__((preserve_access_index))', '')
prefix = """static int host_field_exists(const char *);
static int host_enum(const char *, int);
#define __builtin_preserve_access_index(source) (source)
#define __builtin_preserve_field_info(field, kind) host_field_exists(#field)
#define __builtin_preserve_enum_value(expr, kind) host_enum(#expr, kind)
"""
with tempfile.TemporaryDirectory(prefix="bpf-safety-") as temp:
    path = Path(temp) / "host.c"
    path.write_text(prefix + source + '\n' + (here / 'fixture.c').read_text())
    exe = Path(temp) / "host"
    subprocess.run([os.environ.get('CLANG', 'clang'), '-std=gnu11', '-O1', '-g',
                    '-Wall', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', str(path), '-o', str(exe)], check=True)
    subprocess.run([str(exe), args.case], check=True)
