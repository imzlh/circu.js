
#ifdef _WIN32
    #include <windows.h>
    #include <libloaderapi.h>
	#include <windows.h>
    #include <io.h>
    #define access _access
    #define F_OK 0
#else
    #include <unistd.h>
    #include <limits.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

char* tjs__get_self() {
    static char path[4096] = {0};

	if (path[0]) return path;	// cache result
    
#ifdef _WIN32
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule) {
		// todo: use GetModuleFileNameW for Unicode paths
        DWORD size = GetModuleFileNameA(hModule, path, sizeof(path) - 1);
        if (size > 0) {
            path[size] = '\0';
            return path;
        }
    }
#else
    #if defined(__linux__)
        ssize_t count = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (count >= 0) {
            path[count] = '\0';
            return path;
        }
    #elif defined(__APPLE__)
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0) {
            char real_path[4096];
            if (realpath(path, real_path) != NULL) {
                strcpy(path, real_path);
                return path;
            }
        }
    #elif defined(__FreeBSD__)
        ssize_t count = readlink("/proc/curproc/file", path, sizeof(path) - 1);
        if (count >= 0) {
            path[count] = '\0';
            return path;
        }
    #endif
    
    if (strlen(path) == 0) {
        const char* argv0 = getenv("_");
        if (argv0 && argv0[0] == '/') {
            strncpy(path, argv0, sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
            return path;
        }
    }
#endif
    return NULL;
}

static uint8_t* read_file(FILE* file, size_t *file_size) {
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    *file_size = ftello(file);
    fseek(file, 0, SEEK_SET);
    
    if (*file_size < 4){
		return NULL;
	}
    
    unsigned char *buffer = malloc(*file_size);
    if (!buffer) {
        return NULL;
    }
    
    if (fread(buffer, 1, *file_size, file) != *file_size) {
        free(buffer);
        return NULL;
    }
    
    return buffer;
}

uint8_t* tjs__read_attached(FILE* file, uint32_t *text_length) {
    size_t file_size;
    uint8_t *file_data = read_file(file, &file_size);
    if (!file_data) {
        return NULL;
    }
    
    *text_length = *(uint32_t*)(file_data + file_size - 4);
    
    assert (*text_length + 4 <= file_size);
    
    uint8_t *attach = malloc(*text_length);
    if (!attach) {
        return NULL;
    }
    
    memcpy(attach, file_data + file_size - 4 - *text_length, *text_length);
    
    free(file_data);
    return attach;
}

static int tjs__write_attached(FILE* file, const unsigned char *data,
						size_t size, const char *text, uint32_t text_length) {
	fseek(file, 0, SEEK_SET);
	if (fwrite(data, 1, size, file) != size) {
        return -1;
    }
    
    if (text && text_length > 0 && fwrite(text, 1, text_length, file) != text_length) {
        return -1;
    }

    if (fwrite(&text_length, 1, 4, file) != 4) {
        perror("fwrite length");
        return -1;
    }
    
    return 0;
}

int tjs__build_binary(FILE* file, uint8_t *binary, uint32_t size, int create) {
    size_t original_size;
    unsigned char *original_data = read_file(file, &original_size);
    if (!original_data) {
        return -1;
    }
    
    size_t program_size;
    if (!create) {
        uint32_t old_text_length;
        char *old_text = tjs__read_attached(file, &old_text_length);
        if (old_text) {
            program_size = original_size - old_text_length - 4;
            free(old_text);
        } else {
            program_size = original_size;
        }
    } else {
        program_size = original_size;
    }
    
    int result = tjs__write_attached(file, original_data, program_size, 
                                    binary, size);
    
    free(original_data);
    return result;
}

uint8_t* tjs__read_self_attached(uint32_t *text_length){
	static uint8_t* js = NULL;
	static uint32_t size = 0;
	static char* self_exe_path = NULL;
	if(size == 0){
		self_exe_path = tjs__get_self();
		assert(self_exe_path != NULL);
		FILE* fp = fopen(self_exe_path, "rb");
		assert(fp != NULL);
		js = tjs__read_attached(fp, &size);
		fclose(fp);
	}
	*text_length = size;
	return js;
}

int tjs__set_self_attached(uint8_t *binary, uint32_t text_length, bool overwrite) {
	static char* self_exe_path = NULL;
	if(self_exe_path == NULL){
		self_exe_path = tjs__get_self();
	}

	// in windows, we need to copy&move
#ifdef _WIN32
	// todo
#endif

	FILE* self_exe_file = fopen(self_exe_path, "rb+");
	assert(self_exe_file != NULL);
	int ret = tjs__build_binary(self_exe_file, binary, text_length, overwrite);
	fclose(self_exe_file);
	return ret;
}