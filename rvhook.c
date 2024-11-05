#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "rvhook.h"


uint8_t jump_code[] = 
{
    0x97, 0x02, 0x00, 0x00,  //auipc      t0,0x0
    0xb1, 0x02,              //c.addi     t0,0xc
    0x03, 0xb3, 0x02, 0x00,  //ld         t1,0x0
    0x02, 0x83,              //c.jr       t1
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF //destination address (dstaddr)
};

uint32_t offset_dstaddr = 12;

bool RVHook(uintptr_t src, uintptr_t dst,void **orig)
{

    uint64_t page_size = sysconf(_SC_PAGESIZE);

    if (mprotect((const void *)(src & ~(page_size - 1)), page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        return false;
    }

    void *trampoline = mmap(0, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (MAP_FAILED == trampoline)
    {
        return false;
    }

    *orig = trampoline;
    

    uint32_t save_size = sizeof(jump_code);

    // check instruction boundary.
    uint8_t mask_32 = 0b00000011;  
    if((mask_32 & *(uint8_t*)(src + sizeof(jump_code) - 2)) == mask_32)
    {
        save_size += 2;
    }

    // save orignal instructions.
    memcpy(trampoline, (void *)src, save_size);
    // prepare jump code return to original function.
    uint64_t orig_func_return = src + save_size;
    memcpy(jump_code + offset_dstaddr, &orig_func_return, 8);
    // write jump code on trampoline.
    memcpy(trampoline + save_size, jump_code, sizeof(jump_code));
    // prepare hook jump.
    memcpy(jump_code + offset_dstaddr, &dst, 8);
    // write hook.
    memcpy((void *)src, jump_code, sizeof(jump_code));

    return true;
}