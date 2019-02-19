#include "TEA.h"

__inline void __fastcall TEA_encrypt(uint32_t *key_, uint32_t *buf_, int round_count_) {
  int i;
  uint32_t magic_ = 0;
  for (i = 0; i < round_count_; i++) {
    magic_ += 0x9E3779B9;
    buf_[0] += ((buf_[1] << 4) + key_[0]) ^ (buf_[1] + magic_) ^ ((buf_[1] >> 5) + key_[1]);
    buf_[1] += ((buf_[0] << 4) + key_[2]) ^ (buf_[0] + magic_) ^ ((buf_[0] >> 5) + key_[3]);
  }
}

__inline void __fastcall TEA_decrypt(uint32_t *key_, uint32_t *buf_, int round_count_) {
  int i;
  uint32_t magic_ = 0x9E3779B9 * round_count_;
  for (i = 0; i < round_count_; i++) {
    buf_[1] -= ((buf_[0] << 4) + key_[2]) ^ (buf_[0] + magic_) ^ ((buf_[0] >> 5) + key_[3]);
    buf_[0] -= ((buf_[1] << 4) + key_[0]) ^ (buf_[1] + magic_) ^ ((buf_[1] >> 5) + key_[1]);
    magic_ += 0x61C88647;
  }
}


void __stdcall decrypt(uint32_t *key_, uint32_t *buf_, int buf_size_, int round_count_) {
  int i;
  uint32_t key_0_;
  uint32_t key_1_;
  int count_ = buf_size_ / 8; // 每次8字节，所以输入缓冲区大小必须整除8
  key_0_ = key_[(count_ & 1) * 2 + 0];
  key_1_ = key_[(count_ & 1) * 2 + 1];
  if (key_ && buf_ && buf_size_ % 8 == 0 && round_count_) {
    for (i = 0; i < count_*2; i += 2) {
      buf_[i + 0] ^= key_0_;
      buf_[i + 1] ^= key_1_;
      TEA_decrypt(key_, &buf_[i], round_count_);
    }
  }
}

void __stdcall encrypt(uint32_t *key_, uint32_t *buf_, int buf_size_, int round_count_) {
  int i;
  uint32_t key_0_;
  uint32_t key_1_;
  int count_ = buf_size_ / 8; // 每次8字节，所以输入缓冲区大小必须整除8
  key_0_ = key_[(count_ & 1) * 2 + 0];
  key_1_ = key_[(count_ & 1) * 2 + 1];
  if (key_ && buf_ && (buf_size_ % 8 == 0) && round_count_) {
    for (i = 0; i < count_*2; i += 2) {
      TEA_encrypt(key_, &buf_[i], round_count_);
      buf_[i + 0] ^= key_0_;
      buf_[i + 1] ^= key_1_;
    }
  }
}

