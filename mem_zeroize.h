#ifndef __MEM_ZEROIZE_H__
#define __MEM_ZEROIZE_H__

#include <stddef.h>

void __attribute__((optimize("O0"))) mem_zeroize(void *buf, size_t len);


#endif /* __MEM_ZEROIZE_H__ */
