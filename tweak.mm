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


/*
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

*/


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
//decodes b.cond
int32_t inst_extract_b_cond_imm(uint32_t inst){
    return (inst >>5) & 0x7FFFF;
}

int inst_decode_is_b_le(uint32_t inst){
    uint32_t fmt = 0b01010100000000000000000000000000;
    uint8_t cond = inst & 0x0F;
    return (cond == 0b1011 && fmt & inst == fmt) ? 1 : 0;
}



__attribute__((noinline, naked)) volatile void patched_handler(){
    /* DONT MODIFY THIS SHIT

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

    Code to return to default flow::
    ==================
    movz x14, #0x1234, lsl #32 //address of LNilOrTagged
    movk x14, #0x5678, lsl #16
    movk x14, #0x9abc, lsl #0

    movz x15, #0x1234, lsl #32 //address of LgetIsaDone
    movk x15, #0x5678, lsl #16
    movk x15, #0x9abc, lsl #0

    cmp x0, #0
    b.gt 8
    br x14 //LNilOrTagged
    ldr x14, [x0]           //original, pure
    and x16, x14, ISA_MASK  //original, pure
    br x15
    ==================
    
    */

    uint32_t *victim = (uint32_t*)ptrauth_strip(source, ptrauth_key_process_independent_code);
    uint64_t handler = (uint64_t)ptrauth_strip(target, ptrauth_key_process_independent_code);


    //APPLY PATCH FOR VICTIM FUNCTION

    size_t patch_size = 6 * 4;

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


void dump_data(void *target){
    int pointer_table_size = 16;
    int function_body_size = 400;
    uint64_t *tagged_pointer_table = (uint64_t*)((uintptr_t)target - pointer_table_size*8);
    uint32_t *function_body = (uint32_t*)target;

    for(int i = 0; i < pointer_table_size; i++){
        printx("tagged_pointer_table[%02d] = %8x\n", i, tagged_pointer_table[i]);
    }

    printx("START function body:\n")

    for(int i = 0; i < function_body_size; i++){
        printx("%04x\n", function_body[i]);
    }
    
}



__attribute__((constructor)) void prepare(){
    if(selectiveInjection("Sonic Tools") == 0) return;

    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
	
    void *victim = dlsym(RTLD_DEFAULT, "objc_msgSend");

    sleep(3);
    //patchMessageApparatus(victim, (void*)&patched_handler);
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
