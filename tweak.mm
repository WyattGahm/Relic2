#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
@import ObjectiveC.message;
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

static FILE *log_file = NULL;

void init_log(const char *filename) {
    if (log_file != NULL) {
        fclose(log_file); // Close any previously opened log file
    }
    log_file = fopen(filename, "w"); // Open file in append mode
    if (log_file == NULL) {
        sleep(10);
    }
}

void close_log() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

void printx(const char *format, ...) {
    if (log_file == NULL) {
        return;
    }

    va_list args;
    va_start(args, format);

    vfprintf(log_file, format, args);

    va_end(args);
}



void doNothing(id self, SEL _cmd){
    printx("DOING NOTHING\n");
}

struct OrigAndReturn {
  uintptr_t orig;
  uintptr_t ret;
};

typedef id (*relic_callback)(id self, SEL _cmd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);

struct OrigAndReturn hookmanager(id self, SEL _cmd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) asm("hookman");


struct OrigAndReturn hookmanager(id self, SEL _cmd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    //__builtin_arm_clear_pac
    if(!class_isMetaClass(self)){
        if(object_getClass(self) == objc_getClass("SpectrumViewController")){
            printx("Found target class to hook\n");
            if(sel_registerName("singleTapped") == _cmd){
                printx("Selector FOUND\n");
                relic_callback replacement = (relic_callback)doNothing;
                return (struct OrigAndReturn) {0, (uintptr_t)replacement(self, _cmd, arg2, arg3, arg4, arg5, arg6)};
            }else{
                printx("Selector is not target\n");
            }
        }
    }
    return (struct OrigAndReturn) {(uintptr_t)objc_msgSend, 0};
}


#include <ptrauth.h>

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
//decodes 
uint32_t inst_decode_b_le(uint32_t inst){
    return 0;
}


__attribute__((__naked__)) static void patched_handler(){
  __asm("nop"); //loads orig addr into x16
  __asm("nop"); //loads orig addr into x16
  __asm("nop"); //loads orig addr into x16

  __asm("ret");
}



//patches the messaging apparatus to manipulate calls
int patchMessageApparatus(void *source, void *target){
    /* DONT MODIFY THIS SHIT 
    
    Original function:
    ==================
    cmp x0, #0
    b.le #0xd0
    ldr x14, [x0]
    and x16, x14, ISA_MASK
    ==================


    Replaced code:
    ==================
    movz x14, #0x1234, lsl #32
    movk x14, #0x5678, lsl #16
    movk x14, #0x9abc, lsl #0
    br x14
    ==================
    
    */

    uint32_t *victim = (uint32_t*)ptrauth_strip(source, ptrauth_key_process_independent_code);
    uint64_t handler = (uint64_t)ptrauth_strip(target, ptrauth_key_process_independent_code);

    size_t patch_size = 6 * 4;

    kern_return_t kr_unlock = syscall_vm_protect(mach_task_self(), (vm_address_t)victim_pointer, patch_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if(kr_unlock != KERN_SUCCESS) return kr_unlock;
    
    uint8_t sacrificial_reg = 14; //inst_decode_add_dest(victim_pointer[1]); 

    victim_pointer[0] = inst_generate_movz(sacrificial_reg, (handler >> 32) & 0xFFFF, 32);
    victim_pointer[1] = inst_generate_movk(sacrificial_reg, (handler >> 16) & 0xFFFF, 16);
    victim_pointer[2] = inst_generate_movk(sacrificial_reg, (handler >> 0) & 0xFFFF, 0);
    victim_pointer[3] = inst_generate_br(sacrificial_reg);
    //no patch on victim_pointer[4];
    //victim_pointer[5] = 0xDAC147F0; //PAC clear

    kern_return_t kr_relock = syscall_vm_protect(mach_task_self(), (vm_address_t)victim_pointer, patch_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if(kr_unlcok != KERN_SUCCESS) return kr_relock;


    //idea: prep pointers, unlock memory, perform a copy, relock pointers, invalidate cache


}




__attribute__((constructor)) static void prepare(){
    if(selectiveInjection("Sonic Tools") == 0) return;

    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);

    void *victim = dlsym(RTLD_DEFAULT, "objc_msgSend");
    patchMessageApparatus(victim, (void*)&patched_handler);

}

void old_tests(){
    //test: base image offset
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    printx("Base address of image 0 is: %p\n", slide);

    //test: look for symbols we have to omit
    const char *sus_symbols[] = {"MSHookFunction", "MSHookFunctionEx"};
    for(int i = 0; i < 2; i++){
        void *symbol_address = dlsym(RTLD_DEFAULT, sus_symbols[i]);
        char *error = dlerror();
        if (error != NULL) {
            printx("Error finding symbol %s: %s\n", sus_symbols[i], error);
        } else {
            printx("Address of function %s (dlsym, RTLD_DEFAULT): %p\n",sus_symbols[i], symbol_address);
        }
    }
    
    //test: look for snapchat classes
    const char *snap_classes[] = {"SCNMessagingMessage", "SCLocationManager", "SCOperaPageViewController"};
    for(int i = 0; i < 3; i++){
        const char* className = snap_classes[i];
        Class cls = objc_getClass(className);
        if (cls) {
            printx("Class '%s' found at address: %p\n", className, cls);
        } else {
            printx("Class '%s' not found in this runtime.\n", className);
        }
    }

    //deinit
    

}

__attribute__((destructor)) void finishup(){
    close_log();
}
