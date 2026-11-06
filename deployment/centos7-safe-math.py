"""Use GCC 4.8's compile-time type selection in place of C11 _Generic.

Wireshark 4.2.2 otherwise builds on CentOS 7's GCC, but GCC 4.8 advertises
C11 without implementing _Generic. Only type dispatch changes; Wireshark's
existing checked arithmetic implementations remain unchanged.
"""
from pathlib import Path
import sys

path=Path(sys.argv[1])/'wsutil/safe-math.h'
text=path.read_text()
begin=text.index('#define PSNIP_SAFE_C11_GENERIC_SELECTION(res, op)')
end=text.index('\n\n#define PSNIP_SAFE_C11_GENERIC_BINARY_OP',begin)
original=text[begin:end]
types=[('char','char'),('unsigned char','uchar'),('short','short'),
       ('unsigned short','ushort'),('int','int'),('unsigned int','uint'),
       ('long','long'),('unsigned long','ulong'),('long long','llong'),
       ('unsigned long long','ullong')]
selection='(void)0'
for typename,suffix in reversed(types):
    selection=f'__builtin_choose_expr(__builtin_types_compatible_p(__typeof__(*(res)), {typename}), psnip_safe_{suffix}_##op, {selection})'
replacement='''#if defined(__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ < 9
#define PSNIP_SAFE_C11_GENERIC_SELECTION(res, op) '''+selection+'\n#else\n'+original+'\n#endif'
if '#if defined(__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ < 9\n'+original.splitlines()[0] in text:
    raise RuntimeError('Compatibility patch already applied')
backup=path.with_suffix('.h.original')
if backup.exists():
    raise RuntimeError('Backup exists; inspect before patching')
backup.write_text(text)
path.write_text(text[:begin]+replacement+text[end:])
print('Applied GCC 4.8 type-dispatch compatibility patch')
