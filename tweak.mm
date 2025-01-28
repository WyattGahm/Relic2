#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include <mach-o/dyld.h>
#include <stdio.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <fcntl.h>
#include <unistd.h>
#import <AudioToolbox/AudioToolbox.h>

#include <sys/mman.h>

#include <mach/vm_prot.h>
#include <mach/vm_types.h>
#include <mach/mach.h>
#include <stdint.h>
#include <ptrauth.h>

#include <mach/arm/kern_return.h>

//https://github.com/opensource-apple/objc4/blob/cd5e62a5597ea7a31dccef089317abb3a661c154/runtime/Messengers.subproj/objc-msg-arm.s#L110


//memory protection from litehook
__attribute__((noinline, naked)) volatile kern_return_t syscall_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection){
	__asm("mov x16, #-14");
	__asm("svc 0x80");
	__asm("ret");
}



//Checks which executable we are injected into
int selectiveInjection(const char *binaryName){
    char path[1024];
    uint32_t s_path = sizeof(path);
    if(_NSGetExecutablePath(path, &s_path) == 0)
        if(strstr(path, binaryName) != NULL)
            return 1;
    return 0;
}

//encodes movz (64 bit)
uint32_t inst_generate_movz(uint8_t reg, uint16_t imm, uint8_t shift){
    uint32_t fmt = 0b11010010100000000000000000000000;
    uint32_t hw = (uint32_t)(shift >> 4) << 21;
    uint32_t imm16 = (uint32_t)imm << 5;
    uint32_t rd = reg & 0x1f;
    return fmt | hw | imm16 | rd;
}
//encodes movk (64 bit)
uint32_t inst_generate_movk(uint8_t reg, uint16_t imm, uint8_t shift){
    uint32_t fmt = 0b11110010100000000000000000000000;
    uint32_t hw = (uint32_t)(shift >> 4) << 21;
    uint32_t imm16 = (uint32_t)imm << 5;
    uint32_t rd = reg & 0x1f;
    return fmt | hw | imm16 | rd;
}
//encodes br
uint32_t inst_generate_br(uint8_t reg){
	uint32_t fmt = 0b11010110000111110000000000000000;
	uint32_t rn = ((uint32_t)reg & 0x1F) << 5;
	return fmt | rn;
}


__attribute__((noinline, naked)) volatile void patched_handler(){
    /* DONT MODIFY THIS

    Scratchable registers: the one the ldr and and instructions dont set, anything above x7
    - load address for ble return and regular return into 


    */
    __asm__ volatile ("nop"); //loads orig addr into x16
    __asm__ volatile ("nop"); //loads orig addr into x16
    __asm__ volatile ("nop"); //loads orig addr into x16
    
    __asm__ volatile ("cmp x0, #0");
    __asm__ volatile ("b.ge #8");
    __asm__ volatile ("b overwritten_stff");
    __asm__ volatile ("add x16, x16, x?"); //add the original offset for the jump
    __asm__ volatile ("");
}


//patches the messaging apparatus to manipulate calls
//idea: prep pointers, unlock memory, perform a copy, relock pointers, invalidate cache
int patchMessageApparatus(void *source, void *target){
    /* DONT MODIFY THIS SHIT 
    
    Original function:
    ==================
    ENTRY:
    cmp x0, #0
    b.le #0xd0
    ldr x14, [x0]
    and x16, x14, ISA_MASK
    ==================


    Replaced code:
    ==================
    ENTRY:
    movz x14, #0x1234, lsl #32
    movk x14, #0x5678, lsl #16
    movk x14, #0x9abc, lsl #0
    br x14
    ==================
    */
    uint32_t *victim = (uint32_t*)ptrauth_strip(source, ptrauth_key_process_independent_code);
    uint64_t handler = (uint64_t)ptrauth_strip(target, ptrauth_key_process_independent_code);


    //APPLY PATCH FOR VICTIM FUNCTION

    size_t patch_size = 4 * 4;

    kern_return_t kr_unlock = syscall_vm_protect(mach_task_self(), (vm_address_t)victim, patch_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if(kr_unlock != KERN_SUCCESS) return kr_unlock;
    
    uint8_t sacrificial_reg = 14; //inst_decode_add_dest(victim_pointer[1]); 

    victim[0] = inst_generate_movz(sacrificial_reg, (handler >> 32) & 0xFFFF, 32);
    victim[1] = inst_generate_movk(sacrificial_reg, (handler >> 16) & 0xFFFF, 16);
    victim[2] = inst_generate_movk(sacrificial_reg, (handler >> 0) & 0xFFFF, 0);
    victim[3] = inst_generate_br(sacrificial_reg);
    //no patch on victim_pointer[4];
    //victim[5] = 0xDAC147F0; //PAC clear

    kern_return_t kr_relock = syscall_vm_protect(mach_task_self(), (vm_address_t)victim, patch_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if(kr_relock != KERN_SUCCESS) return kr_relock;

    return KERN_SUCCESS;

}

__attribute__((constructor)) void prepare(){
    if(selectiveInjection("APPLICATION HERE") == 0) return;

    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
	
    void *victim = dlsym(RTLD_DEFAULT, "objc_msgSend");

    patchMessageApparatus(victim, (void*)&patched_handler);
}
