#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

char* tjs__get_self() {
    static char path[4096] = {0};

	if (path[0]) return path;	// cache result
    if(-1 == uv_exepath(path, sizeof(path))) return NULL;
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

uint8_t* tjs__read_attached(FILE* file, uint32_t *binary_length) {
    size_t file_size;
    uint8_t *file_data = read_file(file, &file_size);
    if (!file_data) {
        return NULL;
    }
    
    *binary_length = *(uint32_t*)(file_data + file_size - 4);
    
    assert (*binary_length + 4 <= file_size);
    
    uint8_t *attach = malloc(*binary_length);
    if (!attach) {
        return NULL;
    }
    
    memcpy(attach, file_data + file_size - 4 - *binary_length, *binary_length);
    
    free(file_data);
    return attach;
}

static int tjs__write_attached(FILE* file, uint8_t *data,
						size_t size, uint8_t *binary, uint32_t binary_length) {
	fseek(file, 0, SEEK_SET);
	if (fwrite(data, 1, size, file) != size) {
        return -1;
    }
    
    if (binary && binary_length > 0 && fwrite(binary, 1, binary_length, file) != binary_length) {
        return -1;
    }

    if (fwrite(&binary_length, 1, 4, file) != 4) {
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
        uint32_t old_binary_length;
        uint8_t *old_binary = tjs__read_attached(file, &old_binary_length);
        if (old_binary) {
            program_size = original_size - old_binary_length - 4;
            free(old_binary);
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

uint8_t* tjs__read_self_attached(uint32_t *binary_length){
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
	*binary_length = size;
	return js;
}

int tjs__set_self_attached(uint8_t *binary, uint32_t binary_length, bool overwrite) {
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
	int ret = tjs__build_binary(self_exe_file, binary, binary_length, overwrite);
	fclose(self_exe_file);
	return ret;
}