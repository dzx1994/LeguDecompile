#ifndef TEA_H_
#define TEA_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)
void __stdcall decrypt(uint32_t *key_, uint32_t *buf_, int buf_size_, int round_count_);

__declspec(dllexport)
void __stdcall encrypt(uint32_t *key_, uint32_t *buf_, int buf_size_, int round_count_);

#ifdef __cplusplus
}
#endif

#endif