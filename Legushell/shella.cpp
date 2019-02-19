#include "shella.h"


uint32_t g_4000 = 0;

int g_4004_sdk_version = 0x46B8;

uint32_t g_4008_self_base = 0x10002AB4;

uint32_t g_400C_symtab_size = 0x18A4; // 0x110

uint32_t g_4010_strtab_size = 0x1690; // 0xF6

uint32_t g_4014_symtab_ = 0x401C;

uint32_t g_4018 = 0x7567656C;

void unpack(const char *pszFileName, uint32_t uFileOffset);

typedef jint (*PFUNC_JNI_OnLoad)(JavaVM *vm, void *reserved);

ATTRI_HIDDEN
int getSelfPath(char *buf) {
  char szLine[0x400] = { '\0' };
  char szTmp[0x400] = { '\0' };
  long begin, end;
  FILE *fd = fopen("/proc/self/maps", "r");
  while (!feof(fd)) {
    fgets(szLine, sizeof(szLine), fd);
    sscanf(szLine, "%lx-%lx %s %s %s %s %s", &begin, &end, szTmp, szTmp, szTmp, szTmp, buf);
    if (begin <= g_4008_self_base && g_4008_self_base < end) {
      fclose(fd);
      return 0;
    }
  }
  fclose(fd);
  return -1;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  char szPath[0x400] = { '\0' };
  while (getSelfPath(szPath));

  unpack("/data/local/tmp/bin", 0);
  void *si = dlopen("libshell.so", 0);
  PFUNC_JNI_OnLoad func_JNI_OnLoad = (PFUNC_JNI_OnLoad) dlsym(si, "JNI_OnLoad");
  return func_JNI_OnLoad(vm, reserved);
  //unpack(szPath, g_sdk_version_4004);
  //return JNI_VERSION_1_6;
}

ATTRI_HIDDEN
void decrypt_EA0(uint32_t *key, uint32_t *buf, int size, int align) {
  int i, j;
  uint32_t magic_;
  uint32_t buf_0_;
  uint32_t buf_1_;

  int round_count_ = size >> 3;
  uint32_t key_0_ = key[(round_count_ & 1) * 2 + 0];
  uint32_t key_1_ = key[(round_count_ & 1) * 2 + 1];

  if (key && buf && !(size & 7) && align) {
    for (i = 0; i < round_count_; i++, buf += 2) {
      buf_0_ = buf[0] ^ key_0_;
      buf_1_ = buf[1] ^ key_1_;
      for (j = 0, magic_ = 0x9E3779B9 * align; j < align; j++, magic_ += 0x61C88647) {
        buf_1_ -= ((buf_0_ << 4) + key[2]) ^ (buf_0_ + magic_) ^ ((buf_0_ >> 5) + key[3]);
        buf_0_ -= ((buf_1_ << 4) + key[0]) ^ (buf_1_ + magic_) ^ ((buf_1_ >> 5) + key[1]);
      }
      buf[0] = buf_0_;
      buf[1] = buf_1_;
    }
  }
}

ATTRI_HIDDEN
void fix_rel(soinfo_t *so_, Elf32_Rel *rel_, int rel_cnt_, void **lib_buf_, int lib_buf_cnt_) {
  for (int i = 0; i < rel_cnt_; i++, rel_++) {
    int R_TYPE = rel_->r_info & 0xFF;
    int R_SYM = rel_->r_info >> 8;
    void **p = (void **) (so_->base + rel_->r_offset);
    void *sym_ptr = NULL;
    if (R_TYPE != 0) {
      if (R_SYM) {
        const char *sym_name = so_->strtab_ + so_->symtab_[R_SYM].st_name;
        for (int j = 0; j < lib_buf_cnt_; j++) {
          sym_ptr = dlsym(lib_buf_[j], sym_name);
          if (sym_ptr) {
            break;
          }
        }
        if (!sym_ptr && (g_4004_sdk_version <= 0x15 || !access("/system/lib/libhoudini.so", 4))) {
          ALOGE("txtag", "can not found sym:%s", sym_name);
        }
        if (!sym_ptr && (so_->symtab_[R_SYM].st_info & 0xF)) {
          sym_ptr = (void *) (so_->base + so_->symtab_[R_SYM].st_value);
        }
      }
      switch (R_TYPE) {
        case 2: {
          *p = (void *) ((uint8_t *) sym_ptr + (uint32_t) *p);
          break;
        }
        case 3: {
          *p = ((uint8_t *) sym_ptr - (uint32_t) rel_) + (uint32_t) *p;
          break;
        }
        case 0x15:
        case 0x16: {
          *p = sym_ptr;
          break;
        }
        case 0x17: {
          *p = (uint8_t *) *p + so_->base;
          break;
        }
        default: {
          break;
        }
      }
    }
  }
  return;
}

ATTRI_HIDDEN
void fix_sym_1514(soinfo_t *a1) {
  ALOGE("txtag", "base:%p fix offset!", (void *) g_4008_self_base);
  // symtab_ 的数量和 nchain_ 相等
  for (int i = 0; i < a1->nchain_; i++) {
    ElfW(Sym) *sym = &a1->symtab_[i];
    if ((sym->st_info >> 4) && (sym->st_info >> 4 <= 2) && (sym->st_shndx)) {
      sym->st_value += a1->base - g_4008_self_base;
    }
  }
}


ATTRI_HIDDEN
void flush(long __addr, long __nbytes) {
  cacheflush(__addr, __nbytes, 3);
  cacheflush(__addr, __nbytes, 0);
  cacheflush(__addr, __addr + __nbytes, 3);
  cacheflush(__addr, __addr + __nbytes, 0);
  syscall(0xF0002, __addr, __addr + __nbytes, 0);
}

ATTRI_HIDDEN
void unpack(const char *pszFileName, uint32_t uFileOffset) {
  char szSdkVerBuf[0x40] = { '\0' };
  soinfo_t so = { 0 };
  HeaderInfo header = { 0 };
  uint8_t *base, *load_bias;

  __system_property_get("ro.build.version.sdk", szSdkVerBuf); // 读取SDK版本
  g_4004_sdk_version = atoi(szSdkVerBuf);
  ALOGE("txtag", "version:%d", g_4004_sdk_version);

  int fd = open(pszFileName, 0x80000);

  // 从文件 uFileOffset 处读取 0x58 字节数据作为结构体
  PREAD(fd, &header, sizeof(HeaderInfo), (off_t) uFileOffset);
  ALOGE("txtag", "load library %s at offset 0x%X read count 0x%X\n", pszFileName, uFileOffset, sizeof(HeaderInfo));
  ALOGE("txtag", "min_vaddr:0x%X size:0x%X\n", header.min_vaddr, header.size);

  // 通过mmap创建足够大小的空间存放so数据
  do {
    base = (uint8_t *) mmap((void *) header.min_vaddr, header.size, 0, 0x22, -1, 0);
    if (g_4004_sdk_version <= 10 && base > (uint8_t *) (0x40000000 - header.size) && base <= (uint8_t *) 0x457FFFFF) {
      ALOGE("txtag", "base:%p", (void *) base);
      base = (uint8_t *) -1;
    }
  } while (base == (uint8_t *) -1);

  // load_bias
  load_bias = base - header.min_vaddr;

  so.base = (ElfW(Addr)) base;
  so.load_bias = (ElfW(Addr)) load_bias;

  // .dynsym
  so.symtab_ = (ElfW(Sym) *) (load_bias + header.symtab_);

  // .dynstr
  so.strtab_ = (const char *) (load_bias + header.strtab_);

  // .hash
  so.nbucket_ = header.nbucket_;
  so.bucket_ = (uint32_t *) (load_bias + header.bucket_);
  so.nchain_ = header.nchain_;
  so.chain_ = (uint32_t *) (load_bias + header.bucket_ + header.nbucket_ * sizeof(uint32_t));

  // .rel.dyn
  so.rel_ = (ElfW(Rel) *) (load_bias + header.rel_);
  so.rel_count_ = header.rel_count_;

  // .rel.plt
  so.plt_rel_ = (ElfW(Rel) *) (load_bias + header.plt_rel_);
  so.plt_rel_count_ = header.plt_rel_count_;

  // .text
  // .ARM.exidx
  // .ARM.extab
  // .rodata
  // .fini_array
  // .init_array
  // .data.rel.ro
  // .dynamic
  // .got
  // .data
  // .bbs

  //so.fini_func_ = header.fini_func_ ? (linker_function_t)(load_bias + header.fini_func_) : NULL;
  //so.fini_array_ = header.fini_array_ ? (linker_function_t*)(load_bias + header.fini_array_) : NULL;
  //so.fini_array_count_ = header.fini_array_count_;
  so.init_func_ = header.init_func_ ? (linker_function_t) (load_bias + header.init_func_) : NULL;
  so.init_array_ = header.init_array_ ? (linker_function_t *) (load_bias + header.init_array_) : NULL;
  so.init_array_count_ = header.init_array_count_;
  so.ARM_exidx = header.ARM_exidx;
  so.ARM_exidx_count = header.ARM_exidx_count;

  ALOGE("txtag", "load_bias:%p base:%p\n", (void *) load_bias, (void *) base);

  SegInfo *pSegInfo = (SegInfo *) malloc(header.seg_count_ * sizeof(SegInfo));
  SegInfo *pSegInfo_tmp = pSegInfo;

  PREAD(fd, pSegInfo, header.seg_count_ * sizeof(SegInfo), (off_t) (uFileOffset + header.self_size_));
  ALOGE("txtag", "read count:0x%X", header.seg_count_ * sizeof(SegInfo));

  for (uint32_t i = 0; i < header.seg_count_; i++, pSegInfo++) {
    // 起始地址、结束地址
    uint8_t *pSegStart = load_bias + pSegInfo->vstart;
    uint8_t *pSegEnd = pSegStart + pSegInfo->memsize;

    // 起始地址、结束地址对齐到0x1000
    uint8_t *pAlignStart = (uint8_t *) ((uint32_t) pSegStart & -4096);
    uint8_t *pAlignEnd = (uint8_t *) ((uint32_t) (pSegEnd + 0xFFF) & -4096);
    uint32_t it = 0;

    if (pSegInfo->zip_data_size) {
      // 映射空间，用于存放解密且解压后的数据，空间大小需要对齐到0x1000
      mmap(pAlignStart, pAlignEnd - pAlignStart, 3, 0x32, -1, 0);
      // 初始化 zlib，初始化失败将陷入无限循环
      z_stream zStream = { 0 };
      while (inflateInit2(&zStream, -15));
      uint32_t uCurrFileSize;
      uint32_t uCurrDecrSize;
      // 开始解密和解压数据
      for (uint32_t j = 0; j < pSegInfo->zip_data_size; j += uCurrFileSize) {
        uint8_t buf[0x1000] = { 0 };
        // 最多0x1000字节
        uCurrFileSize = j + 0x1000 <= pSegInfo->zip_data_size ? 0x1000 : pSegInfo->zip_data_size - j;

        // 从文件读取数据
        PREAD(fd, buf, uCurrFileSize, (off_t) (uFileOffset + pSegInfo->zip_data_offset + j));

        // 解密数据
        uCurrDecrSize = j + 0x1000 <= pSegInfo->decrypt_size ? 0x1000 : pSegInfo->decrypt_size - j;
        decrypt_EA0((uint32_t *) "Tx:12345Tx:12345", (uint32_t *) buf, uCurrDecrSize, 0x10);

        // 解压
        zStream.avail_in = uCurrFileSize;
        zStream.next_in = buf;
        ALOGE("txtag", "read count:0x%X", uCurrFileSize);
        zStream.avail_out = 0x100000;
        zStream.next_out = pSegStart + it;
        inflate(&zStream, 0);

        // 解压前可用的缓冲区大小 - 解压后可用的缓冲区大小 = 成功解压出的数据大小
        it = it + (0x100000 - zStream.avail_out);
      }
      // 释放zlib对象
      inflateEnd(&zStream);
      // 刷新缓存
      for (long j = (long) pSegStart; j < (long) (pSegStart + it); j += 0x400) {
        flush(j, 0x400);
      }
      ALOGE("txtag", "seg_start:%p size:0x%X infsize:0x%X file_offset:0x%X\n", (void *) pSegStart, pSegInfo->zip_data_size, it,
            pSegInfo->zip_data_offset);
    }
    if ((pSegInfo->flags & 2) && (it & 0xFFF) > 0) {
      // 这块内存需要"写属性"，但是实际大小不对齐到0x1000。将剩余的字节置0
      memset(pSegStart + it, 0, 0x1000 - ((uint32_t) (pSegStart + it) & 0xFFF));
    }
  }

  // dlopen 所有 DT_NEEDED，并存储在 needed_lib_buf 中
  void *needed_lib_buf[0x400] = { 0 };
  uint32_t *pDT_NEEDED = (uint32_t *) (load_bias + header.needed_lib_table);
  for (uint32_t i = 0; i < header.dt_needed_count_; i++) {
    needed_lib_buf[i] = dlopen(so.strtab_ + pDT_NEEDED[i], 0);
  }
  ALOGE("txtag", "do relocate!\n");
  // fix ELF REL Relocation Table
  fix_rel(&so, so.rel_, so.rel_count_, needed_lib_buf, header.dt_needed_count_);

  // fix ELF JMPREL Relocation Table
  fix_rel(&so, so.plt_rel_, so.plt_rel_count_, needed_lib_buf, header.dt_needed_count_);
  memset(so.rel_, 0, sizeof(Elf32_Rel) * so.rel_count_);
  memset(so.plt_rel_, 0, sizeof(Elf32_Rel) * so.plt_rel_count_);
  ALOGE("txtag", "replace");
  fix_sym_1514(&so);

  g_4014_symtab_ += g_4008_self_base;
  ALOGE("txtag", "syminfo:%p new:%p size:%x", (void *) g_4014_symtab_, so.symtab_, g_400C_symtab_size);
  memcpy((void *) g_4014_symtab_, so.symtab_, g_400C_symtab_size);

  ALOGE("txtag", "strtab:%p size:%x", (void *) (g_4014_symtab_ + g_400C_symtab_size), g_4010_strtab_size);
  memcpy((void *) (g_4014_symtab_ + g_400C_symtab_size), so.strtab_, g_4010_strtab_size);

  void *bucket_ = (void *) (g_4014_symtab_ + g_400C_symtab_size + g_4010_strtab_size + 8);
  ALOGE("txtag", "bucket:%p bucket:%p size:%x", bucket_, so.bucket_, (so.nbucket_ + so.nchain_) * 4);
  memcpy(bucket_, so.bucket_, (so.nbucket_ + so.nchain_) * 4);

  memset((void *) so.symtab_, 0, g_400C_symtab_size);
  memset((void *) so.strtab_, 0, g_4010_strtab_size);
  memset((void *) so.bucket_, 0, (so.nbucket_ + so.nchain_) * 4);

  ALOGE("txtag", "set back protect of the memory\n");
  for (int i = 0; i < header.seg_count_; i++) {
    void *begin = load_bias + (pSegInfo_tmp[i].vstart & -4096);
    void *end = load_bias + ((pSegInfo_tmp[i].vstart + pSegInfo_tmp[i].memsize + 0xFFF) & -4096);
    mprotect(begin, (uint32_t) end - (uint32_t) begin, pSegInfo_tmp[i].flags);
  }

  if (so.init_func_ && so.init_func_ != (void *) -1) {
    ALOGE("txtag", "init func:%p\n", so.init_func_);
    so.init_func_();
  }

  for (int i = 0; i < so.init_array_count_; i++) {
    if (so.init_array_[i] && so.init_array_[i] != (void *) -1) {
      ALOGE("txtag", "init array func:%p\n", so.init_array_[i]);
      so.init_array_[i]();
      so.init_array_[i] = NULL;
    }
  }
  free(pSegInfo_tmp);
  close(fd);
  return;
}


__attribute__ ((constructor))
ATTRI_HIDDEN
void init_array_00() {
  uint32_t *func_self = (uint32_t *) &init_array_00;
  func_self = (uint32_t *) ((uint32_t) func_self & (uint32_t) -4096);
  while (*func_self != 0x464C457F) {
    func_self -= 0x400;
  }

  // 在这里使用轮循异或方式解密JNI_OnLoad

  g_4008_self_base = (uint32_t) func_self;
}

//void _init() {
//  ALOGE("txtag", "_init");
//}
//void _fini() {
//  ALOGE("txtag", "_fini");
//}

/*
int main(int argc, char *argv[], char *envp[]) {
  __android_log_print(ANDROID_LOG_ERROR, "a", "b");
  unpack(argv[1], g_sdk_version_4004);
  return 0;
}
 */

