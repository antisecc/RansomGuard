// hash_monitor.c

#include "hash_monitor.h"
#include "entropy_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

typedef struct {
    char path[PATH_MAX];
    unsigned char hash[HASH_SIZE];
    double entropy;
    time_t last_check;
    bool valid;
} file_hash_t;

static file_hash_t *tracked_hashes = NULL;
static int max_tracked_files = 0;
static int file_count = 0;
static int suspicious_changes = 0;
static pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

// Replace the SHA256 direct calls with EVP interface
static bool calculate_file_hash(const char *path, unsigned char *hash) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return false;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return false;
    }
    
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return false;
    }
    
    unsigned char buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytes_read)) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return false;
        }
    }
    
    unsigned int digest_len;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &digest_len)) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return false;
    }
    
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    
    return true;
}

// Compare two hashes and return similarity score (0.0 - 1.0)
static double hash_similarity(const unsigned char *hash1, const unsigned char *hash2) {
    int matching_bits = 0;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned char xor_result = hash1[i] ^ hash2[i];
        
        for (int bit = 0; bit < 8; bit++) {
            if ((xor_result & (1 << bit)) == 0) {
                matching_bits++;
            }
        }
    }
    
    return matching_bits / (double)(HASH_SIZE * 8);
}

bool init_hash_monitor(int max_files) {
    pthread_mutex_lock(&hash_mutex);
    
    if (tracked_hashes != NULL) {
        free(tracked_hashes);
    }
    
    max_tracked_files = max_files > 0 ? max_files : 1000;
    tracked_hashes = calloc(max_tracked_files, sizeof(file_hash_t));
    if (tracked_hashes == NULL) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    file_count = 0;
    suspicious_changes = 0;
    
    pthread_mutex_unlock(&hash_mutex);
    return true;
}

bool monitor_file_hash(const char *path) {
    if (path == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&hash_mutex);
    
    for (int i = 0; i < file_count; i++) {
        if (strcmp(tracked_hashes[i].path, path) == 0) {
            pthread_mutex_unlock(&hash_mutex);
            return true;
        }
    }
    
    if (file_count >= max_tracked_files) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    file_hash_t *entry = &tracked_hashes[file_count];
    strncpy(entry->path, path, PATH_MAX - 1);
    entry->path[PATH_MAX - 1] = '\0';
    
    if (!calculate_file_hash(path, entry->hash)) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    entry->entropy = calculate_file_entropy(path);
    entry->last_check = time(NULL);
    entry->valid = true;
    
    file_count++;
    
    pthread_mutex_unlock(&hash_mutex);
    return true;
}

bool check_file_changed(const char *path, hash_change_event_t *event) {
    if (path == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&hash_mutex);
    
    int index = -1;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(tracked_hashes[i].path, path) == 0) {
            index = i;
            break;
        }
    }
    
    if (index == -1) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    file_hash_t *entry = &tracked_hashes[index];
    unsigned char new_hash[HASH_SIZE];
    
    if (!calculate_file_hash(path, new_hash)) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    double new_entropy = calculate_file_entropy(path);
    double entropy_change = new_entropy - entry->entropy;
    
    double similarity = hash_similarity(entry->hash, new_hash);
    bool significant_change = similarity < 0.9;  // Less than 90% similar
    
    bool entropy_increased = entropy_change > 0.3;  // Significant entropy increase
    
    bool suspicious = significant_change && entropy_increased;
    
    if (event != NULL) {
        strncpy(event->path, path, PATH_MAX - 1);
        event->path[PATH_MAX - 1] = '\0';
        memcpy(event->original_hash, entry->hash, HASH_SIZE);
        memcpy(event->new_hash, new_hash, HASH_SIZE);
        event->similarity = similarity;
        event->entropy_change = entropy_change;
    }
    
    if (significant_change) {
        memcpy(entry->hash, new_hash, HASH_SIZE);
        entry->entropy = new_entropy;
        entry->last_check = time(NULL);
        
        if (suspicious) {
            suspicious_changes++;
        }
    }
    
    pthread_mutex_unlock(&hash_mutex);
    return suspicious;
}

int get_suspicious_hash_change_count(void) {
    return suspicious_changes;
}

void cleanup_hash_monitor(void) {
    pthread_mutex_lock(&hash_mutex);
    
    if (tracked_hashes != NULL) {
        free(tracked_hashes);
        tracked_hashes = NULL;
    }
    
    file_count = 0;
    suspicious_changes = 0;
    
    pthread_mutex_unlock(&hash_mutex);
}