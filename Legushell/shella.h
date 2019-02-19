//
// Created by Administrator on 2018/10/5.
//

#ifndef TXLEGU_SHELLA_H
#define TXLEGU_SHELLA_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//#include <vector>
//#include <string>

#include <jni.h>

#include <fcntl.h>
#include <dlfcn.h>
#include <zlib.h>
#include <sys/mman.h>
#include <sys/system_properties.h>

#include <elf.h>
#include <inttypes.h>
#include <link.h>
#include <unistd.h>
#include <android/log.h>
#include <android/dlext.h>
#include <sys/stat.h>

#define ATTRI_HIDDEN __attribute__((visibility ("hidden")))
//#define ATTRI_HIDDEN

#define ALOGE(tag, ...) __android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__)

#define PREAD(fd, buf, size, offset) do { ; }while(pread(fd, buf, size, offset) != (size))


// sizeof = 0x58
typedef struct __tagHeaderInfo {
  uint32_t min_vaddr;            // +00: 最小虚拟地址 希望内存被分布的地址
  uint32_t size;                 // +04: 需要的内存大小, 最后一个 ZipInfo.vstart + ZipInfo.memsize
  uint16_t self_size_;           // +08: 自身大小
  uint16_t seg_count_;           // +0A: seg 数量
  uint32_t m_0C;                 // +0C:
  uint32_t strtab_;              // +10: .dynstr, size=HeaderInfo.bucket_ - HeaderInfo.strtab_ - 8; 因为字符串表下面就是bucket
  uint32_t symtab_;              // +14: .dynsym, size=HeaderInfo.nchain_ * 0x10; nchain_ 表示符号表的个数
  uint32_t init_func_;           // +18: 初始化函数的偏移
  uint32_t init_array_;          // +1C: 初始化函数数组的偏移
  uint32_t fini_func_;           // +20: 因为没有使用，这是一个猜测
  uint32_t fini_array_;          // +24: 因为没有使用，这是一个猜测
  uint16_t fini_array_count_;    // +28: 因为没有使用，这是一个猜测
  uint16_t init_array_count_;    // +2A: 因为没有使用，这是一个猜测
  int16_t  dt_needed_count_;     // +2C: 在执行解压代码前，需要加载多少个依赖的lib
  uint16_t m_2E;                 // +2E:
  uint32_t needed_lib_table;     // +30: 指定了需要被加载的library字符串表的偏移
  uint32_t nbucket_;             // +34: bucket_ 的数量
  uint32_t nchain_;              // +38: chanin_ 的数量
  uint32_t bucket_;              // +3C: Hash 表的偏移，每一项4字节, size=HeaderInfo.nbucket_ * 4
  uint32_t plt_rel_;             // +40: .rel.plt的偏移
  uint32_t plt_rel_count_;       // +44: .rel.plt的数量，每一项8字节
  uint32_t rel_count_;           // +48: .rel.dyn的数量，每一项8字节
  uint32_t rel_;                 // +4C: .rel.dyn的偏移
  uint32_t ARM_exidx;            // +50: -A8 v56
  uint16_t ARM_exidx_count;      // +54: -A4 v57
  uint16_t m_56;                 // +56: -A2
} HeaderInfo;

// sizeof = 0x18
typedef struct __tagSegInfo {
  uint32_t vstart;              // +00:
  uint32_t memsize;             // +04:
  uint32_t zip_data_offset;     // +08: zip数据距离 HeaderInfo 的偏移
  uint32_t zip_data_size;       // +0C: zip数据在文件中占用的实际大小
  uint32_t flags;               // +10: 标识了读，写，执行的属性: XWR
  uint32_t decrypt_size;        // +14: 在解压这些数据之前，需要被解密的实际大小
} SegInfo;


//////////////////////////////////////////
// for linker.h
#define SOINFO_NAME_LEN 0x80
typedef uint64_t soinfo_list_t;

typedef void (*linker_function_t)();

// sizeof = 0x1A0
typedef struct __tag_soinfo_t {
  char old_name_[SOINFO_NAME_LEN];  // off:0x000, size:0x080: so name

  const ElfW(Phdr) *phdr;           // off:0x080, size:0x004: 指向程序头. Elf32_Phdr; Elf64_Phdr

  size_t phnum;                     // off:0x084, size:0x004: 程序头的数量

  ElfW(Addr) entry;                 // off:0x088, size:0x004: Elf32_Addr; Elf64_Addr

  ElfW(Addr) base;                  // off:0x08C, size:0x004: Elf32_Addr; Elf64_Addr

  size_t size;                      // off:0x090, size:0x004:

  uint32_t unused1;                 // off:0x094, size:0x004: DO NOT USE, maintained for compatibility.

  ElfW(Dyn) *dynamic;               // off:0x098, size:0x004:

  uint32_t unused2;                 // off:0x09C, size:0x004: DO NOT USE, maintained for compatibility.
  uint32_t unused3;                 // off:0x0A0, size:0x004: DO NOT USE, maintained for compatibility.

  struct __tag_soinfo_t *next;                     // off:0x0A4, size:0x004
  uint32_t flags_;                  // off:0x0A8, size:0x004

  const char *strtab_;              // off:0x0AC, size:0x004: .dynstr的地址
  ElfW(Sym) *symtab_;               // off:0x0B0, size:0x004: .dynsym的地址

  size_t nbucket_;                  // off:0x0B4, size:0x004
  size_t nchain_;                   // off:0x0B8, size:0x004
  uint32_t *bucket_;                // off:0x0BC, size:0x004
  uint32_t *chain_;                 // off:0x0C0, size:0x004

  // This is only used by mips and mips64, but needs to be here for all 32-bit architectures to preserve binary compatibility.
  ElfW(Addr) **plt_got_;            // off:0x0C4, size:0x004:

  ElfW(Rel) *plt_rel_;              // off:0x0C8, size:0x004: .rel.plt的地址
  size_t plt_rel_count_;            // off:0x0CC, size:0x004: .rel.plt的数量，每一项8字节
  ElfW(Rel) *rel_;                  // off:0x0D0, size:0x004: .rel.dyn的地址
  size_t rel_count_;                // off:0x0D4, size:0x004: .rel.dyn的数量，每一项8字节

  linker_function_t *preinit_array_;// off:0x0D8, size:0x004
  size_t preinit_array_count_;      // off:0x0DC, size:0x004

  linker_function_t *init_array_;   // off:0x0E0, size:0x004
  size_t init_array_count_;         // off:0x0E4, size:0x004
  linker_function_t *fini_array_;   // off:0x0E8, size:0x004
  size_t fini_array_count_;         // off:0x0EC, size:0x004

  linker_function_t init_func_;     // off:0x0F0, size:0x004
  linker_function_t fini_func_;     // off:0x0F4, size:0x004

  uint32_t ARM_exidx;               // off:0x0F8, size:0x004
  size_t ARM_exidx_count;           // off:0x0FC, size:0x004

  size_t ref_count_;                // off:0x100, size:0x004

  struct link_map link_map_head;           // off:0x104, size:0x014

  bool constructors_called;         // off:0x118, size:0x001

  ElfW(Addr) load_bias;             // off:0x11C, size:0x004

  bool has_text_relocations;        // off:0x120, size:0x001
  bool has_DT_SYMBOLIC;             // off:0x121, size:0x001

  uint32_t version_;                // off:0x124, size:0x004
  dev_t st_dev_;                    // off:0x128, size:0x004
  ino_t st_ino_;                    // off:0x12C, size:0x004
  soinfo_list_t children_;  // off:0x130, size:0x008
  soinfo_list_t parents_;   // off:0x138, size:0x008
  off64_t file_offset_;             // off:0x140, size:0x008
  uint32_t rtld_flags_;             // off:0x148, size:0x004
  uint32_t dt_flags_1_;             // off:0x14C, size:0x004
  size_t strtab_size_;              // off:0x150, size:0x004
  size_t gnu_nbucket_;              // off:0x154, size:0x004
  uint32_t *gnu_bucket_;            // off:0x158, size:0x004
  uint32_t *gnu_chain_;             // off:0x15C, size:0x004
  uint32_t gnu_maskwords_;          // off:0x160, size:0x004
  uint32_t gnu_shift2_;             // off:0x164, size:0x004
  ElfW(Addr) *gnu_bloom_filter_;    // off:0x168, size:0x004
  struct __tag_soinfo_t *local_group_root_;        // off:0x16C, size:0x004
  uint8_t *android_relocs_;         // off:0x170, size:0x004
  size_t android_relocs_size_;      // off:0x174, size:0x004
  const char *soname_;              // off:0x178, size:0x004
  uint32_t realpath_[3];            // off:0x17C, size:0x00C
  const ElfW(Versym) *versym_;      // off:0x188, size:0x004
  ElfW(Addr) verdef_ptr_;           // off:0x18C, size:0x004
  size_t verdef_cnt_;               // off:0x190, size:0x004
  ElfW(Addr) verneed_ptr_;          // off:0x194, size:0x004
  size_t verneed_cnt_;              // off:0x198, size:0x004
  uint32_t target_sdk_version_;     // off:0x19C, size:0x004
} soinfo_t;
//////////////////////////////////////////


#endif //TXLEGU_SHELLA_H
