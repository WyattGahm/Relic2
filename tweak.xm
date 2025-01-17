#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include <stdio.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <fcntl.h>
#include <unistd.h>

static FILE *log_file = NULL;

void init_log(const char *filename) {
    if (log_file != NULL) {
        fclose(log_file); // Close any previously opened log file
    }
    log_file = fopen(filename, "a"); // Open file in append mode
    if (log_file == NULL) {
        perror("Failed to open log file");
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
        fprintf(stderr, "Log file is not initialized.\n");
        return;
    }

    va_list args;
    va_start(args, format);

    vfprintf(log_file, format, args);

    va_end(args);
}

__attribute__((constructor)) static void prepare(){
    //init: LOGGING
    init_log("exp_relic_log.txt");
    printx("###################### LOGGING STARTING ######################\n");
    
    //test: determine which process we are loading into
    uint32_t imageCount = _dyld_image_count();
    printx("Total libraries loaded: %u\n", imageCount);
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName) {
            printx("Library %u: %s\n", i, imageName);
        }
    }

    //test: find appropriate symbols
    void *symbol_address = dlsym(RTLD_DEFAULT, "objc_msgSend");
    char *error = dlerror();
    if (error != NULL) {
        printx("Error finding symbol: %s\n", error);
    } else {
        printx("Address of function (dlsym, RTLD_DEFAULT): %p\n", symbol_address);
        unsigned char *byte_ptr = (unsigned char *)direct_symbol_address;
        printx("First 16 bytes at the address of symbol:\n");
        for (int i = 0; i < 16; i++) {
            printx("%02x ", byte_ptr[i]); // Print each byte as a 2-digit hex value
        }
        printx("\n");
    }

    //test: manually find symbols
    void *direct_symbol_address = (void *)&objc_msgSend;
    printx("Address of function (manual): %p\n", direct_symbol_address);
    unsigned char *byte_ptr = (unsigned char *)direct_symbol_address;
    printx("First 16 bytes at the address of symbol:\n");
    for (int i = 0; i < 16; i++) {
        printx("%02x ", byte_ptr[i]); // Print each byte as a 2-digit hex value
    }
    printx("\n");

    //test: base image offset
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    printx("Base address of image 0 is: %p\n", slide);

    //test: look for symbols we have to omit
    char *sus_symbols = {"MSHookFunction", "MSHookFunctionEx"};
    for(int i = 0; i < sizeof(sus_symbols); i++){
        void *symbol_address = dlsym(RTLD_DEFAULT, sus_symbols[i]);
        char *error = dlerror();
        if (error != NULL) {
            printx("Error finding symbol %s: %s\n", sus_symbols[i], error);
        } else {
            printx("Address of function %s (dlsym, RTLD_DEFAULT): %p\n",sus_symbols[i], symbol_address);
        }
    }
    
    //test: look for snapchat classes
    char *snap_classes[] = {"SCNMessagingMessage", "SCLocationManager", "SCOperaPageViewController"}
    for(int i = 0; i < sizeof(snap_classes); i++){
        char* className = snap_classes[i];
        Class cls = objc_getClass(className);
        if (cls) {
            printx("Class '%s' found at address: %p\n", className, cls);
        } else {
            printx("Class '%s' not found in this runtime.\n", className);
        }
    }

    //deinit
    printx("###################### LOGGING ENDED ######################\n\n");
    close_log();

}

