# -*- coding: utf-8 -*-

import sys
import os
import struct
import ctypes
import platform
import zlib

p = "dll"
c = "x64"
arch = platform.architecture()
if arch[0].find("64bit")==-1:
  c = "x86"
if arch[1].find("Windows") == -1:
  p = "so"

lib_txlegu_TEA = ctypes.CDLL("./Txlegu_TEA_%s.%s" %(c, p))

class Elf32_Shdr:
  format_str = "<IIIIIIIII"
  sizeof = struct.calcsize(format_str)

  def __init__(self, name="", type=0, flags=0, addr=0, offset=0, size=0, link=0, info=0, addralign=0, entsize=0):
    self.sh_name = name
    self.sh_type = type
    self.sh_flags = flags
    self.sh_addr = addr
    self.sh_offset = offset
    self.sh_size = size
    self.sh_link = link
    self.sh_info = info
    self.sh_addralign = addralign
    self.sh_entsize = entsize

  def getFields(self):
    return struct.pack(self.format_str, self.sh_type, \
              self.sh_flags, \
              self.sh_addr, \
              self.sh_offset, \
              self.sh_size, \
              self.sh_link, \
              self.sh_info, \
              self.sh_addralign, \
              self.sh_entsize)


class Elf32_Dyn:
  format_str = "<II"
  sizeof = struct.calcsize(format_str)

  def __init__(self, d_tag, d_val):
    self.d_tag = d_tag
    self.d_val = d_val
  
  def getFields(self):
    return struct.pack(self.format_str, self.d_tag, self.d_val)

# elf 头 sizeof = 0x34
class Elf32_Ehdr:
  format_str = "<HHIIIIIHHHHHH"
  sizeof = struct.calcsize(format_str)

  def __init__(self):
    self.e_type = 3
    self.e_machine = 0x28
    self.e_version = 1
    self.e_entry = 0
    self.e_phoff = 0x34
    self.e_shoff = 0
    self.e_flags = 0x5000200
    self.e_ehsize = 0x34
    self.e_phentsize = 0x20
    self.e_phnum = 0
    self.e_shentsize = 0x28
    self.e_shnum = 0
    self.e_shstrndx = 0

  def getFields(self):
    data_ = struct.pack(self.format_str, 
                        self.e_type, \
                        self.e_machine, \
                        self.e_version, \
                        self.e_entry, \
                        self.e_phoff, \
                        self.e_shoff, \
                        self.e_flags, \
                        self.e_ehsize, \
                        self.e_phentsize, \
                        self.e_phnum, \
                        self.e_shentsize, \
                        self.e_shnum, \
                        self.e_shstrndx)
    return "\x7F\x45\x4C\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + data_


# elf 程序头
class Elf32_Phdr:
  format_str = "<IIIIIIII"
  sizeof = struct.calcsize(format_str)

  def __init__(self):
    self.p_type = 0
    self.p_offset = 0
    self.p_vaddr = 0
    self.p_paddr = 0
    self.p_filesz = 0
    self.p_memsz = 0
    self.p_flags = 0
    self.p_align = 0
  
  def setFields(self, data):
    data = struct.unpack(self.format_str, data)
    self.p_type = data[0]
    self.p_offset = data[1]
    self.p_vaddr = data[2]
    self.p_paddr = data[3]
    self.p_filesz = data[4]
    self.p_memsz = data[5]
    self.p_flags = data[6]
    self.p_align = data[7]
  
  def getFields(self):
    return struct.pack(self.format_str, self.p_type, \
                      self.p_offset, \
                      self.p_vaddr, \
                      self.p_paddr, \
                      self.p_filesz, \
                      self.p_memsz, \
                      self.p_flags, \
                      self.p_align)

# sizeof = 0x10, Also see: http://www.sco.com/developers/gabi/latest/ch4.symtab.html
class Elf32_Sym:
  format_str = "<IIIBBH"
  sizeof = struct.calcsize(format_str)

  def __init__(self):
    self.st_name = 0
    self.st_value = 0
    self.st_size = 0
    self.st_info = 0
    self.st_other = 0
    self.st_shndx = 0
  
  def setFields(self, data):
    data = struct.unpack(Elf32_Sym.format_str, data)
    self.st_name = data[0]
    self.st_value = data[1]
    self.st_size = data[2]
    self.st_info = data[3]
    self.st_other = data[4]
    self.st_shndx = data[5]

# sizeof = 0x08, Also see: http://www.sco.com/developers/gabi/latest/ch4.reloc.html
class Elf32_Rel:
  format_str = "<II"
  sizeof = struct.calcsize(format_str)

  def __init__(self):
    self.r_offset = 0
    self.r_info = 0

  def setFields(self, data):
    data = struct.unpack(Elf32_Rel.format_str, data)
    self.r_offset = data[0]
    self.r_info = data[1]

# sizeof = 0x18
class SegInfo:
  format_str = "<IIIIII"
  sizeof = struct.calcsize(format_str)

  def __init__(self):
    self.vstart = 0
    self.unzip_size = 0
    self.zip_data_offset = 0
    self.size_in_file = 0
    self.flags = 0
    self.decrypt_size = 0
    self.data_ = ""
  
  def setFields(self, data):
    data = struct.unpack(SegInfo.format_str, data)
    self.vstart = data[0]
    self.unzip_size = data[1]
    self.zip_data_offset = data[2]
    self.size_in_file = data[3]
    self.flags = data[4]
    self.decrypt_size = data[5]

# sizeof = 0x58
class HeaderInfo:
  format_str = "<IIHHIIIIIIIHHhHIIIIIIIIIHH"
  sizeof = struct.calcsize(format_str)

  def __init__(self):
    self.min_vaddr = 0
    self.size = 0
    self.self_size_ = 0
    self.seg_count_ = 0
    self.m_0C = 0
    self.strtab_ = 0
    self.symtab_ = 0
    self.init_func_ = 0
    self.init_array_ = 0
    self.fini_func_ = 0
    self.fini_array_ = 0
    self.fini_array_count_ = 0
    self.init_array_count_ = 0
    self.dt_needed_count_ = 0
    self.m_2E = 0
    self.needed_lib_table = 0
    self.nbucket_ = 0
    self.nchain_ = 0
    self.bucket_ = 0
    self.plt_rel_ = 0
    self.plt_rel_count_ = 0
    self.rel_count_ = 0
    self.rel_ = 0
    self.ARM_exidx = 0
    self.ARM_exidx_count = 0
    self.m_56 = 0
  
  def setFields(self, data):
    data = struct.unpack(HeaderInfo.format_str, data)
    self.min_vaddr = data[0]
    self.size = data[1]
    self.self_size_ = data[2]
    self.seg_count_ = data[3]
    self.m_0C = data[4]
    self.strtab_ = data[5]
    self.symtab_ = data[6]
    self.init_func_ = data[7]
    self.init_array_ = data[8]
    self.fini_func_ = data[9]
    self.fini_array_ = data[10]
    self.fini_array_count_ = data[11]
    self.init_array_count_ = data[12]
    self.dt_needed_count_ = data[13]
    self.m_2E = data[14]
    self.needed_lib_table = data[15]
    self.nbucket_ = data[16]
    self.nchain_ = data[17]
    self.bucket_ = data[18]
    self.plt_rel_ = data[19]
    self.plt_rel_count_ = data[20]
    self.rel_count_ = data[21]
    self.rel_ = data[22]
    self.ARM_exidx = data[23]
    self.ARM_exidx_count = data[24]
    self.m_56 = data[25]

# TxLegu 通过分析 so 文件内容。将 so 的 Loadable Segment 提取出来。
# 通常一个 so 文件含有两个 Loadable Segment; 第一个属性为:R-X; 第二个属性为:RW-
# 也就是说，第一个Segment是代码和一些只读数据；第二个是一些全局变量等等。

def main(argc, argv):
  offset = 0x6DE8
  with open("./libshella-2.9.0.2_org.so", "r+b") as fd: #传入乐固加壳之后的so
    headerInfo = HeaderInfo()
    fd.seek(offset)
    headerInfo.setFields(fd.read(HeaderInfo.sizeof))
    
    seg = []
    for i in range(headerInfo.seg_count_):
      segInfo = SegInfo()
      fd.seek(offset + headerInfo.self_size_ + i*SegInfo.sizeof)
      segInfo.setFields(fd.read(SegInfo.sizeof))
      zipData = ""
      j = 0
      while j < segInfo.size_in_file:
        readSize = 0x1000
        if j + 0x1000 > segInfo.size_in_file:
          readSize = segInfo.size_in_file - j
        decrSize = 0x1000
        if j + 0x1000 > segInfo.decrypt_size:
          decrSize = segInfo.decrypt_size - j
        fd.seek(offset + segInfo.zip_data_offset + j)
        data = fd.read(readSize)
        lib_txlegu_TEA.decrypt("Tx:12345Tx:12345", data, decrSize, 0x10)
        zipData += data
        j += readSize
      for j in range(segInfo.vstart):
        segInfo.data_ += '\x00'
      segInfo.data_ += zlib.decompress(zipData, -15)
      seg.append(segInfo)

    program_headers_ = []

    # 程序头
    elf_program_header_ = Elf32_Phdr()
    elf_program_header_.p_type = 6
    elf_program_header_.p_offset = 0x34
    elf_program_header_.p_vaddr = 0x34
    elf_program_header_.p_paddr = 0x34
    elf_program_header_.p_filesz = 0 # 稍后计算
    elf_program_header_.p_memsz = elf_program_header_.p_filesz
    elf_program_header_.p_flags = 4
    elf_program_header_.p_align = 4
    program_headers_.append(elf_program_header_)

    # Loadable Segment 0
    loadable_0 = Elf32_Phdr()
    loadable_0.p_type = 1
    loadable_0.p_offset = 0
    loadable_0.p_vaddr = 0
    loadable_0.p_paddr = 0
    loadable_0.p_filesz = len(seg[0].data_)
    loadable_0.p_memsz = loadable_0.p_filesz
    loadable_0.p_flags = seg[0].flags
    loadable_0.p_align = 0x1000
    program_headers_.append(loadable_0)

    # Loadable Segment 1
    loadable_1 = Elf32_Phdr()
    loadable_1.p_type = 1
    loadable_1.p_offset = 0 # 稍后计算
    loadable_1.p_vaddr = seg[i].vstart
    loadable_1.p_paddr = seg[i].vstart
    loadable_1.p_filesz = len(seg[1].data_) - seg[i].vstart
    loadable_1.p_memsz = seg[1].unzip_size
    loadable_1.p_flags = seg[1].flags
    loadable_1.p_align = 0x1000
    program_headers_.append(loadable_1)

    other_headers_data_ = seg[0].data_[seg[0].vstart + headerInfo.dt_needed_count_ * 4 + 0x14 : headerInfo.symtab_]
    for i in range(0, len(other_headers_data_), 0x20):
      program_header_ = Elf32_Phdr()
      if len(other_headers_data_[i : i + 0x20]) < 0x20:
        break
      program_header_.setFields(other_headers_data_[i : i + 0x20])
      if program_header_.p_type == 0:
        continue
      program_headers_.append(program_header_)

    program_headers_[0].p_filesz = len(program_headers_) * Elf32_Phdr.sizeof
    program_headers_[0].p_memsz = program_headers_[0].p_filesz
    program_headers_[2].p_offset = program_headers_[3].p_offset - (program_headers_[3].p_vaddr - program_headers_[2].p_vaddr)

    sections = []
    sections.append(Elf32_Shdr()) # SHN_UNDEF
    

    # .dynsym: ELF Symbol Table
    symtab_ = headerInfo.symtab_
    symtab_size_ = headerInfo.nchain_ * 0x10
    sections.append(Elf32_Shdr(".dynsym", 0xB, 2, symtab_, symtab_, symtab_size_, 4, 1, 4, 0x10))

    # .dynstr: ELF String Table
    strtab_ = headerInfo.strtab_
    strtab_size_ = (headerInfo.bucket_-8) - headerInfo.strtab_
    strtab_data_ = seg[0].data_[strtab_ : strtab_ + strtab_size_]
    sections.append(Elf32_Shdr(".dynstr", 3, 2, strtab_, strtab_, strtab_size_, 0, 0, 1, 0))

    # .hash: ELF Hash Table
    nbucket_ = headerInfo.nbucket_
    nchain_ = headerInfo.nchain_
    bucket_ = headerInfo.bucket_
    chain_ = headerInfo.bucket_ + 4 * headerInfo.nbucket_
    sections.append(Elf32_Shdr(".hash", 5, 2, bucket_-8, bucket_-8, nbucket_*4+nchain_*4+8, 3, 0, 4, 4))

    # .rel.dyn: ELF REL Relocation Table
    rel_ = headerInfo.rel_
    rel_size_ = headerInfo.rel_count_ * 8
    sections.append(Elf32_Shdr(".rel.dyn", 9, 2, rel_, rel_, rel_size_, 3, 0, 4, 8))
    DT_RELCOUNT__ = 0
    for i in range(rel_, rel_ + rel_size_, 8):
      __rel = seg[0].data_[i : i + 8]
      if __rel[4 : 8] == "\x17\x00\x00\x00":
        DT_RELCOUNT__ += 1

    # .rel.plt: ELF JMPREL Relocation Table
    plt_rel_ = headerInfo.plt_rel_
    plt_rel_size_ = headerInfo.plt_rel_count_ * 8
    sections.append(Elf32_Shdr(".rel.plt", 9, 0x42, plt_rel_, plt_rel_, plt_rel_size_, 3, 0x14, 4, 8))

    # .plt: .plt 中的每一项和 .rel.plt 是一一对应的
    # size = .plt 第一项的大小 + .rel.plt数量 * 0xC
    plt_ = plt_rel_ + plt_rel_size_
    plt_size_ = 0x14 + headerInfo.plt_rel_count_ * 0xC
    sections.append(Elf32_Shdr(".plt", 1, 6, plt_, plt_, plt_size_, 0, 0, 4, 0))

    # .text: 第一个 Loadable Segment 包含: ELF头; 程序头; .dynsym; .dynstr; .hash; .rel.dyn; .rel.plt; .plt; .text; .ARM.exidx; .ARM.extab; .rodata
    # .text 以重定位代码而结束，特征码: "\x78\x47\xC0\x46\x00\xC0\x9F\xE5\x0F\xF0\x8C\xE0"
    # 因为无法定位 .ARM.exidx; .ARM.extab; .rodata 的位置，所以只能通过在第一个 Loadable Segment 中搜索特征码来定位 .text 的结束
    text_ = plt_ + plt_size_

    # .ARM.exidx .ARM.extab
    arm_exidx_ = 0
    arm_exidx_size_ = 0
    arm_extab_ = 0
    arm_extab_size_ = 0

    for i in range(len(program_headers_)):
      if program_headers_[i].p_type == 0x70000001:
        arm_exidx_ = program_headers_[i].p_vaddr
        arm_exidx_size_ = program_headers_[i].p_filesz
    text_size_ = seg[0].data_[0 : arm_exidx_].rfind("\x78\x47\xC0\x46\x00\xC0\x9F\xE5\x0F\xF0\x8C\xE0") + 0x10 - (plt_ + plt_size_)
    arm_extab_ = text_ + text_size_
    arm_extab_size_ = arm_exidx_ - arm_extab_
    sections.append(Elf32_Shdr(".text", 1, 6, text_, text_, text_size_, 0, 0, 4, 0))
    sections.append(Elf32_Shdr(".ARM.exidx", 0x70000001, 0x82, arm_exidx_, arm_exidx_, arm_exidx_size_, 0xC, 0, 4, 8))
    sections.append(Elf32_Shdr(".ARM.extab", 1, 2, arm_extab_, arm_extab_, arm_extab_size_, 0, 0, 4, 0))

    # .rodata
    rodata_ = arm_exidx_ + arm_exidx_size_
    rodata_size_ = len(seg[0].data_) - rodata_
    sections.append(Elf32_Shdr(".rodata", 1, 2, rodata_, rodata_, rodata_size_, 0, 0, 0x10, 0))

    # .fini_array
    fini_array_ = headerInfo.fini_array_
    fini_array_size_ = headerInfo.fini_array_count_ * 4
    sections.append(Elf32_Shdr(".fini_array", 0xF, 3, fini_array_, program_headers_[2].p_offset + (fini_array_ - program_headers_[2].p_vaddr), fini_array_size_, 0, 0, 4, 4))

    # .init_array
    init_array_ = headerInfo.init_array_
    init_array_size_ = headerInfo.init_array_count_ * 4
    sections.append(Elf32_Shdr(".init_array", 0xE, 3, init_array_, program_headers_[2].p_offset + (init_array_ - program_headers_[2].p_vaddr), init_array_size_, 0, 0, 4, 4))

    # .data.rel.ro
    # 起始地址需要对齐到0x10
    # .data.rel.ro 位于 .dynamic 之上
    data_rel_ro_ = init_array_ + init_array_size_
    if data_rel_ro_ & 0xF != 0: # 对齐到 0x10
      data_rel_ro_ += 0x10 - (data_rel_ro_ & 0xF)

    # .dynamic
    dynamic_ = 0
    dynamic_size_ = 0
    for i in range(len(program_headers_)):
      if program_headers_[i].p_type == 2:
        dynamic_ = program_headers_[i].p_vaddr
        dynamic_size_ = program_headers_[i].p_filesz
    data_rel_ro_size_ = dynamic_ - data_rel_ro_
    sections.append(Elf32_Shdr(".data.rel.ro", 1, 3, data_rel_ro_, program_headers_[2].p_offset + (data_rel_ro_ - program_headers_[2].p_vaddr), data_rel_ro_size_, 0, 0, 0x10, 0))
    sections.append(Elf32_Shdr(".dynamic", 6, 3, dynamic_, program_headers_[2].p_offset + (dynamic_ - program_headers_[2].p_vaddr), dynamic_size_, 4, 0, 4, 8))



    # .got
    # 可以通过 .plt 定位到 _GLOBAL_OFFSET_TABLE_;
    # _GLOBAL_OFFSET_TABLE_ 位于 .got 中；且 _GLOBAL_OFFSET_TABLE_ 前面是 .rel.dyn 重定位结构；后面是 .rel.plt 重定位结构；
    got_ = dynamic_ + dynamic_size_
    _GLOBAL_OFFSET_TABLE_ = plt_ + 0x10 + struct.unpack("<I", seg[0].data_[plt_ + 0x10 : plt_ + 0x14])[0]
    got_end_ = _GLOBAL_OFFSET_TABLE_ + 0xC + headerInfo.plt_rel_count_ * 4
    got_size_ = got_end_ - got_
    sections.append(Elf32_Shdr(".got", 1, 3, got_, program_headers_[2].p_offset + (got_ - program_headers_[2].p_vaddr), got_size_, 0, 0, 4, 0))

    # .data: 剩余字节全部作为 .data 处理
    data_ = got_ + got_size_
    data_size_ = len(seg[1].data_[data_ : len(seg[1].data_)])
    sections.append(Elf32_Shdr(".data", 1, 3, data_, program_headers_[2].p_offset + (data_ - program_headers_[2].p_vaddr), data_size_, 0, 0, 4, 0))

    elf_dyns_ = []
    elf_dyns_.append(Elf32_Dyn(3, _GLOBAL_OFFSET_TABLE_)) # DT_PLTGOT
    elf_dyns_.append(Elf32_Dyn(2, plt_rel_size_)) # DT_PLTRELSZ
    elf_dyns_.append(Elf32_Dyn(0x17, plt_rel_)) # DT_JMPREL, .rel.plt
    elf_dyns_.append(Elf32_Dyn(0x14, 0X11)) # DT_PLTREL
    elf_dyns_.append(Elf32_Dyn(0x11, rel_)) # DT_REL
    elf_dyns_.append(Elf32_Dyn(0x12, rel_size_)) # DT_RELSZ
    elf_dyns_.append(Elf32_Dyn(0x13, 8)) # DT_RELENT
    elf_dyns_.append(Elf32_Dyn(0x6FFFFFFA, DT_RELCOUNT__)) # DT_RELCOUNT: .rel.dyn 中有多少项 R_ARM_RELATIVE
    elf_dyns_.append(Elf32_Dyn(6, symtab_)) # DT_SYMTAB
    elf_dyns_.append(Elf32_Dyn(0xB, 0x10)) # DT_SYMENT
    elf_dyns_.append(Elf32_Dyn(5, strtab_)) # DT_STRTAB
    elf_dyns_.append(Elf32_Dyn(0xA, strtab_size_)) # DT_STRSZ
    elf_dyns_.append(Elf32_Dyn(4, bucket_ - 8)) # DT_HASH: bucket_ 向上8字节即 .hash 的起始位置

    # DT_NEEDED
    for i in range(headerInfo.dt_needed_count_):
      idx = headerInfo.needed_lib_table + i*4
      elf_dyns_.append(Elf32_Dyn(1, struct.unpack("<I", seg[0].data_[idx : idx + 4])[0]))

    # DT_SONAME
    i = 0
    while True:
      i += 1
      if strtab_data_[elf_dyns_[len(elf_dyns_)-1].d_val : len(strtab_data_)][i-1] == "\x00":
        break
    elf_dyns_.append(Elf32_Dyn(0xE, elf_dyns_[len(elf_dyns_)-1].d_val + i + 1))

    # DT_INIT
    if headerInfo.init_func_ != 0:
      elf_dyns_.append(Elf32_Dyn(0xC, headerInfo.init_func_)) # DT_FINI_ARRAY

    # DT_FINI
    if headerInfo.fini_func_ != 0:
      elf_dyns_.append(Elf32_Dyn(0xD, headerInfo.fini_func_)) # DT_FINI_ARRAY

    elf_dyns_.append(Elf32_Dyn(0x1a, fini_array_)) # DT_FINI_ARRAY
    elf_dyns_.append(Elf32_Dyn(0x1C, fini_array_size_)) # DT_FINI_ARRAYSZ
    elf_dyns_.append(Elf32_Dyn(0x19, init_array_)) # DT_INIT_ARRAY
    elf_dyns_.append(Elf32_Dyn(0x1B, init_array_size_)) # DT_INIT_ARRAYSZ

    #elf_dyns_.append(Elf32_Dyn(0x1e, 8)) # DT_FLAGS
    #elf_dyns_.append(Elf32_Dyn(0x6FFFFFFB, 1)) # DT_FLAGS_1
    #elf_dyns_.append(Elf32_Dyn(0x6FFFFFF0, 0x3B18)) # DT_VERSYM
    #elf_dyns_.append(Elf32_Dyn(0x6FFFFFFC, 0x3E08)) # DT_VERDEF
    #elf_dyns_.append(Elf32_Dyn(0x6FFFFFFD, 1)) # DT_VERDEFNUM
    #elf_dyns_.append(Elf32_Dyn(0x6FFFFFFE, 0x3E24)) # DT_VERNEED
    #elf_dyns_.append(Elf32_Dyn(0x6FFFFFFF, 2)) # DT_VERNEEDNUM
    elf_dyns_.append(Elf32_Dyn(0, 0)) # DT_NULL

    elf_header_ = Elf32_Ehdr()
    elf_header_.e_ident = "\x7F\x45\x4C\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    elf_header_.e_type = 3
    elf_header_.e_machine = 0x28
    elf_header_.e_version = 1
    elf_header_.e_entry = 0
    elf_header_.e_phoff = 0x34
    elf_header_.e_shoff = 0
    elf_header_.e_flags = 0x5000200
    elf_header_.e_ehsize = 0x34
    elf_header_.e_phentsize = 0x20
    elf_header_.e_phnum = len(program_headers_)
    elf_header_.e_shentsize = 0x28
    elf_header_.e_shnum = 0x1B
    elf_header_.e_shstrndx = 0x1A

    with open("./dump.so", "w+b") as fd1:
      for i in range(symtab_):
        fd1.write("\x00")
      fd1.write(seg[0].data_[symtab_ : len(seg[0].data_)])

      for i in range(program_headers_[2].p_offset - len(seg[0].data_)):
        fd1.write("\x00")
      fd1.write(seg[1].data_[seg[1].vstart : len(seg[1].data_)])

      fd1.seek(elf_header_.e_phoff)
      for i in range(len(program_headers_)):
        fd1.write(program_headers_[i].getFields())

      for i in range(len(program_headers_)):
        if program_headers_[i].p_type == 2:
          fd1.seek(program_headers_[i].p_offset)
          for j in range(len(elf_dyns_)):
            if j >= program_headers_[i].p_filesz / Elf32_Dyn.sizeof:
              break
            fd1.write(elf_dyns_[j].getFields())

      fd1.seek(0, 2)
      shstrtab_offset = fd1.tell()
      if shstrtab_offset & 0xFFF != 0:
        for i in range(0x1000 - (shstrtab_offset & 0xFFF)):
          fd1.write("\x00")
      fd1.seek(0, 2)
      shstrtab_offset = fd1.tell()

      for i in range(0x200):
        fd1.write("\x00")
      sections_offset = fd1.tell()

      name_ = ""
      for i in range(len(sections)):
        fd1.write(struct.pack("<I", len(name_)) + sections[i].getFields())
        name_ += sections[i].sh_name + "\x00"
      
      fd1.write(struct.pack("<I", len(name_)) + Elf32_Shdr(".shstrtab", 3, 0, 0, shstrtab_offset, len(name_) + len(".shstrtab\x00"), 0, 0, 1, 0).getFields())
      name_ += ".shstrtab\x00"
      fd1.seek(shstrtab_offset)
      fd1.write(name_)

      fd1.seek(0)
      elf_header_.e_shoff = sections_offset
      elf_header_.e_shnum = len(sections) + 1
      elf_header_.e_shstrndx = len(sections)
      fd1.write(elf_header_.getFields())

  return 0

if __name__ == "__main__":
  #print len(sys.argv), sys.argv
  main(len(sys.argv), sys.argv)