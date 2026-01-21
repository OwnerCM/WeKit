#include <jni.h>
#include <string>
#include <android/log.h>
#include <vector>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <zlib.h>
#include <iomanip>
#include "sha256.h"
#include "secrets.h"
#include <sys/system_properties.h>
#include "generated_checksums.h"

#define LOG_TAG "[WeKit-TAG] wekit-native"

#define ENABLE_WEKIT_LOGS

#if defined(ENABLE_WEKIT_LOGS) || !defined(NDEBUG)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#else
    #define LOGE(...)
    #define LOGI(...)
    #define LOGW(...)
#endif


volatile const uint32_t NSIZE __attribute__((used)) = 0x1A2B3C4D;

// 全局校验状态
static bool g_signature_valid = false;
static bool g_dex_valid = false;
static int g_verification_score = 0;

const char* get_target_so_path() {
#if defined(__aarch64__)
    return "lib/arm64-v8a/libwekit.so";
#elif defined(__arm__)
    return "lib/armeabi-v7a/libwekit.so";
#else
    return "lib/x86_64/libwekit.so";
#endif
}

static void process_string_data(const unsigned char *data, unsigned char key, char *output) {
    for (int i = 0; i < 16; i++) {
        output[i] = (data[i] ^ key);
    }
}

static bool load_config_segment(int segment, char* buffer) {
    switch(segment) {
        case 0:
            process_string_data(ENC_PART1, KEY1, buffer);
            return true;
        case 1:
            process_string_data(ENC_PART2, KEY2, buffer);
            return true;
        case 2:
            process_string_data(ENC_PART3, KEY3, buffer);
            return true;
        case 3:
            process_string_data(ENC_PART4, KEY4, buffer);
            return true;
        default:
            return false;
    }
}

// 解密并组装预埋的 Hash 字符串
static std::string assemble_verification_data() {
    char parts[4][17]; // 16 bytes + null terminator
    for (int i = 0; i < 4; i++) {
        memset(parts[i], 0, 17);
        if (!load_config_segment(i, parts[i])) {
            return "";
        }
    }

    std::string result;
    for (auto & part : parts) {
        result.append(part, 16);
    }
    return result;
}

static std::string sha256_bytes_to_hex(const uint8_t* hash_bytes) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (int i = 0; i < 32; ++i) {
        ss << std::setw(2) << (int)hash_bytes[i];
    }
    return ss.str();
}

static bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (tolower(a[i]) != tolower(b[i])) {
            return false;
        }
    }
    return true;
}

static bool verify_checksum_internal(const char* input) {
    if (!input) return false;
    std::string expected = assemble_verification_data();
    if (expected.empty()) return false;
    return iequals(std::string(input), expected);
}

static std::string get_apk_path() {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", getpid());

    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        LOGE("Failed to open maps file");
        return "";
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(".apk") != std::string::npos) {
            size_t path_start = line.find('/');
            if (path_start != std::string::npos) {
                std::string apk_path = line.substr(path_start);
                size_t space_pos = apk_path.find(' ');
                if (space_pos != std::string::npos) {
                    apk_path = apk_path.substr(0, space_pos);
                }
                // LOGI("Found APK path: %s", apk_path.c_str());
                return apk_path;
            }
        }
    }
    LOGE("APK path not found in maps");
    return "";
}

// ==================== ZIP文件结构定义 ====================

#pragma pack(push, 1)
struct ZipLocalFileHeader {
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_length;
    uint16_t extra_length;
};

struct ZipCentralDirHeader {
    uint32_t signature;
    uint16_t version_made;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_length;
    uint16_t extra_length;
    uint16_t comment_length;
    uint16_t disk_start;
    uint16_t internal_attr;
    uint32_t external_attr;
    uint32_t local_header_offset;
};

struct ZipEndOfCentralDir {
    uint32_t signature;
    uint16_t disk_number;
    uint16_t central_dir_disk;
    uint16_t num_entries_disk;
    uint16_t num_entries;
    uint32_t central_dir_size;
    uint32_t central_dir_offset;
    uint16_t comment_length;
};

struct DexHeader {
    uint8_t magic[8];
    uint32_t checksum;
    uint8_t signature[20];
    uint32_t file_size;
    uint32_t header_size;
    uint32_t endian_tag;
    uint32_t link_size;
    uint32_t link_off;
    uint32_t map_off;
    uint32_t string_ids_size;
    uint32_t string_ids_off;
    uint32_t type_ids_size;
    uint32_t type_ids_off;
    uint32_t proto_ids_size;
    uint32_t proto_ids_off;
    uint32_t field_ids_size;
    uint32_t field_ids_off;
    uint32_t method_ids_size;
    uint32_t method_ids_off;
    uint32_t class_defs_size;
    uint32_t class_defs_off;
    uint32_t data_size;
    uint32_t data_off;
};
#pragma pack(pop)

// ==================== DEX完整性校验 ====================

static bool find_eocd(int fd, off_t file_size, ZipEndOfCentralDir* eocd) {
    const size_t max_search = 65535 + sizeof(ZipEndOfCentralDir);
    const size_t search_size = (file_size < max_search) ? file_size : max_search;
    off_t search_start = file_size - search_size;
    if (lseek(fd, search_start, SEEK_SET) < 0) return false;
    std::vector<uint8_t> buffer(search_size);
    if (read(fd, buffer.data(), search_size) != (ssize_t)search_size) return false;
    for (ssize_t i = search_size - sizeof(ZipEndOfCentralDir); i >= 0; i--) {
        uint32_t sig = *reinterpret_cast<uint32_t*>(&buffer[i]);
        if (sig == 0x06054b50) {
            memcpy(eocd, &buffer[i], sizeof(ZipEndOfCentralDir));
            return true;
        }
    }
    return false;
}

static bool find_entry_in_apk(int fd, const ZipEndOfCentralDir& eocd, const char* target_filename, uint32_t* entry_offset, uint32_t* entry_size) {
    if (lseek(fd, eocd.central_dir_offset, SEEK_SET) < 0) return false;
    for (uint16_t i = 0; i < eocd.num_entries; i++) {
        ZipCentralDirHeader header{};
        if (read(fd, &header, sizeof(header)) != sizeof(header)) return false;
        if (header.signature != 0x02014b50) return false;
        std::vector<char> filename(header.filename_length + 1);
        if (read(fd, filename.data(), header.filename_length) != header.filename_length) return false;
        filename[header.filename_length] = '\0';
        if (lseek(fd, header.extra_length + header.comment_length, SEEK_CUR) < 0) return false;
        if (strstr(filename.data(), target_filename) != nullptr) {
            off_t current_pos = lseek(fd, 0, SEEK_CUR);
            lseek(fd, header.local_header_offset, SEEK_SET);
            ZipLocalFileHeader local_header{};
            if (read(fd, &local_header, sizeof(local_header)) == sizeof(local_header)) {
                if (local_header.signature == 0x04034b50) {
                    *entry_offset = header.local_header_offset + sizeof(ZipLocalFileHeader) + local_header.filename_length + local_header.extra_length;
                    *entry_size = header.uncompressed_size;
                    return true;
                }
            }
            lseek(fd, current_pos, SEEK_SET);
        }
    }
    return false;
}



static bool verify_single_entry_crc(int fd, const ZipEndOfCentralDir& eocd, const char* filename, uint32_t expected_crc) {
    uint32_t offset, size;

    // 使用你现有的通用查找函数
    if (!find_entry_in_apk(fd, eocd, filename, &offset, &size)) {
        LOGE("[!] Missing expected DEX file: %s", filename);
        return false;
    }

    if (lseek(fd, offset, SEEK_SET) < 0) {
        LOGE("[!] Failed to seek to DEX data: %s", filename);
        return false;
    }

    // 分块读取并计算 CRC32
    std::vector<uint8_t> buffer(8192);
    uLong crc = crc32(0L, Z_NULL, 0);
    uint32_t total_read = 0;

    while (total_read < size) {
        size_t to_read = std::min((size_t)8192, (size_t)(size - total_read));
        ssize_t n = read(fd, buffer.data(), to_read);
        if (n <= 0) break;
        crc = crc32(crc, buffer.data(), n);
        total_read += n;
    }

    if ((uint32_t)crc != expected_crc) {
        LOGE("[!] DEX MODIFIED: %s | Real: %08x, Expected: %08x", filename, (uint32_t)crc, expected_crc);
        return false;
    }

    LOGI("[V] Verified: %s", filename);
    return true;
}

static bool verify_dex_content_directly(const std::string& apk_path) {
    int fd = open(apk_path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    off_t file_size = st.st_size;

    ZipEndOfCentralDir eocd{};
    if (!find_eocd(fd, file_size, &eocd)) { close(fd); return false; }

    bool all_passed = true;

    for (int i = 0; i < EXPECTED_DEX_COUNT; ++i) {
        std::string filename;
        if (i == 0) {
            filename = "classes.dex";
        } else {
            std::ostringstream ss;
            ss << "classes" << (i + 1) << ".dex";
            filename = ss.str();
        }

        uint32_t expected_crc = EXPECTED_DEX_CRCS[i];

        if (!verify_single_entry_crc(fd, eocd, filename.c_str(), expected_crc)) {
            all_passed = false;
            break;
        }
    }

    close(fd);

    if (all_passed) {
        LOGI("[V] All %d DEX files verified successfully.", EXPECTED_DEX_COUNT);
    }

    return all_passed;
}

static const uint8_t APK_SIG_BLOCK_MAGIC[] = {
        0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
};
static const uint32_t APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;

static void calculate_sha256(const uint8_t* data, size_t length, uint8_t* output) {
    compute_sha256(data, length, output);
}

static bool find_apk_signing_block(int fd, off_t file_size, const ZipEndOfCentralDir& eocd, off_t* block_offset, uint64_t* block_size) {
    off_t central_dir_offset = eocd.central_dir_offset;
    if (central_dir_offset < 32) return false;
    off_t magic_offset = central_dir_offset - 16;
    if (lseek(fd, magic_offset, SEEK_SET) < 0) return false;
    uint8_t magic_buffer[16];
    if (read(fd, magic_buffer, 16) != 16) return false;
    if (memcmp(magic_buffer, APK_SIG_BLOCK_MAGIC, 16) != 0) return false;
    off_t size_offset = magic_offset - 8;
    if (lseek(fd, size_offset, SEEK_SET) < 0) return false;
    uint64_t size_footer;
    if (read(fd, &size_footer, 8) != 8) return false;
    *block_size = size_footer;
    *block_offset = central_dir_offset - size_footer - 8;
    if (lseek(fd, *block_offset, SEEK_SET) < 0) return false;
    uint64_t size_header;
    if (read(fd, &size_header, 8) != 8) return false;
    if (size_header != size_footer) return false;
    return true;
}

static bool extract_v2_signature(int fd, off_t block_offset, uint64_t block_size, std::vector<uint8_t>& signature_data) {
    off_t pairs_offset = block_offset + 8;
    uint64_t pairs_size = block_size - 24;
    if (lseek(fd, pairs_offset, SEEK_SET) < 0) return false;
    std::vector<uint8_t> pairs_data(pairs_size);
    if (read(fd, pairs_data.data(), pairs_size) != (ssize_t)pairs_size) return false;
    size_t offset = 0;
    while (offset < pairs_size) {
        if (offset + 12 > pairs_size) break;
        uint64_t pair_len;
        memcpy(&pair_len, &pairs_data[offset], 8);
        offset += 8;
        if (offset + pair_len > pairs_size) break;
        uint32_t id;
        memcpy(&id, &pairs_data[offset], 4);
        offset += 4;
        uint64_t value_len = pair_len - 4;
        if (id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
            signature_data.resize(value_len);
            memcpy(signature_data.data(), &pairs_data[offset], value_len);
            return true;
        }
        offset += value_len;
    }
    return false;
}

static bool extract_certificate_from_v2(const std::vector<uint8_t>& signature_data, std::vector<uint8_t>& certificate) {
    if (signature_data.size() < 4) return false;
    size_t offset = 0;

    uint32_t signers_len;
    if (offset + 4 > signature_data.size()) return false;
    memcpy(&signers_len, &signature_data[offset], 4);
    offset += 4;

    uint32_t signer_len;
    if (offset + 4 > signature_data.size()) return false;
    memcpy(&signer_len, &signature_data[offset], 4);
    offset += 4;

    uint32_t signed_data_len;
    if (offset + 4 > signature_data.size()) return false;
    memcpy(&signed_data_len, &signature_data[offset], 4);
    offset += 4;

    size_t signed_data_end = offset + signed_data_len;
    if (signed_data_end > signature_data.size()) return false;
    uint32_t digests_len;
    if (offset + 4 > signed_data_end) return false;
    memcpy(&digests_len, &signature_data[offset], 4);
    offset += 4 + digests_len;
    uint32_t certificates_len;
    if (offset + 4 > signed_data_end) return false;
    memcpy(&certificates_len, &signature_data[offset], 4);
    offset += 4;

    uint32_t cert_len;
    if (offset + 4 > signed_data_end) return false;
    memcpy(&cert_len, &signature_data[offset], 4);
    offset += 4;

    if (offset + cert_len > signed_data_end) return false;

    certificate.resize(cert_len);
    memcpy(certificate.data(), &signature_data[offset], cert_len);

    LOGI("Extracted certificate: size=%u", cert_len);
    return true;
}

static bool verify_apk_signature_direct(const std::string& apk_path) {
    int fd = open(apk_path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOGE("Failed to open APK");
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }
    off_t file_size = st.st_size;

    ZipEndOfCentralDir eocd;
    if (!find_eocd(fd, file_size, &eocd)) {
        close(fd);
        LOGE("EOCD not found");
        return false;
    }

    off_t block_offset;
    uint64_t block_size;
    if (!find_apk_signing_block(fd, file_size, eocd, &block_offset, &block_size)) {
        close(fd);
        LOGW("No V2 Signing Block found");
        return false;
    }

    std::vector<uint8_t> signature_data;
    if (!extract_v2_signature(fd, block_offset, block_size, signature_data)) {
        close(fd);
        return false;
    }

    std::vector<uint8_t> certificate;
    if (!extract_certificate_from_v2(signature_data, certificate)) {
        close(fd);
        return false;
    }
    close(fd);

    uint8_t calculated_hash[32];
    calculate_sha256(certificate.data(), certificate.size(), calculated_hash);
    std::string calculated_hex = sha256_bytes_to_hex(calculated_hash);
    std::string expected_hex = assemble_verification_data();

    if (calculated_hex == expected_hex) {
        LOGI("[V] Certificate Verification PASSED");
        return true;
    } else {
        LOGE("[!] Certificate Verification FAILED!");
        LOGE("[!] Calculated: %s", calculated_hex.c_str());
        LOGE("[!] Expected:   %s", expected_hex.c_str());
        return false;
    }

    if (iequals(calculated_hex, expected_hex)) {
        LOGI("[V] Certificate Verification PASSED");
        return true;
    } else {
        LOGE("[!] Certificate Verification FAILED! Hash mismatch.");
        return false;
    }
}

static bool verify_so_integrity(int fd, const ZipEndOfCentralDir& eocd) {
    uint32_t offset, size;

    const char* target_path = get_target_so_path();

    if (!find_entry_in_apk(fd, eocd, target_path, &offset, &size)) {
        LOGE("Could not find SO in APK: %s", target_path);
        return false;
    }

    uint32_t expected_size = NSIZE;

    if (expected_size == 0x1A2B3C4D) {
#ifdef NDEBUG
        LOGE("[!] FATAL: SO integrity check failed. Binary not patched!");
        return false;
#else
        LOGW("[!] Debug build detected. Skipping SO size check.");
        return true;
#endif
    }

    if (size != expected_size) {
        LOGE("[!] SO MODIFIED! Expected Size: %u, Actual Size in APK: %u", expected_size, size);
        return false;
    }

    LOGI("[V] SO size verified: %u", size);
    return true;
}

void* fix_thread(void* arg) {
    srand(time(nullptr));
    int delay = 5 + (rand() % 16);
    std::this_thread::sleep_for(std::chrono::seconds(delay));
    abort();
    return nullptr;
}

static void onFailed(JNIEnv* env) {
    pthread_t thread_id;
    int result = pthread_create(&thread_id, nullptr, fix_thread, nullptr);
    if (result == 0) pthread_detach(thread_id);
    else abort();
}

static int perform_multi_dimensional_verification(JNIEnv* env, const char* signature_hash) {
#if !defined(NDEBUG) || defined(DEBUG)
    LOGW("[WeKit-Debug] Debug Build detected. Bypassing verification.");

    g_signature_valid = true;
    g_dex_valid = true;
    g_verification_score = 100;
    return 100;
#endif

    int score = 0;
    std::string apk_path = get_apk_path();

    if (verify_checksum_internal(signature_hash)) {
        LOGI("[V] Java-layer signature verification passed");
        score += 20;
        g_signature_valid = true;
    } else {
        LOGE("[X] FATAL: Java-layer signature verification failed!");
        g_signature_valid = false;
        onFailed(env);
        return 0;
    }

    if (!apk_path.empty()) {
        if (verify_apk_signature_direct(apk_path)) {
            LOGI("[V] Native APK signature direct verification passed");
            score += 20;
        } else {
            LOGW("[!] FATAL: Native APK signature direct verification failed!");
            onFailed(env);
            return 0;
        }
    }

    if (!apk_path.empty() && verify_apk_signature_direct(apk_path)) {
        score += 20;
        g_dex_valid = true;
    } else {
        LOGE("[X] FATAL: DEX integrity verification failed!");
        g_dex_valid = false;
        onFailed(env);
        return 0;
    }

    if (!apk_path.empty() && verify_dex_content_directly(apk_path)) {
        score += 20;
        g_dex_valid = true;
    } else {
        LOGE("[X] FATAL: DEX integrity verification failed!");
        g_dex_valid = false;
        onFailed(env);
        return 0;
    }

    bool so_check_passed = false;
    if (!apk_path.empty()) {
        int fd = open(apk_path.c_str(), O_RDONLY);
        if (fd >= 0) {
            struct stat st{};
            if (fstat(fd, &st) == 0) {
                ZipEndOfCentralDir eocd{};
                if (find_eocd(fd, st.st_size, &eocd)) {
                    if (verify_so_integrity(fd, eocd)) {
                        so_check_passed = true;
                    }
                } else {
                    LOGE("Failed to find EOCD for SO check");
                }
            }
            close(fd);
        } else {
            LOGE("Failed to open APK for SO check");
        }
    }

    if (so_check_passed) {
        score += 20;
    } else {
        LOGE("[X] FATAL: SO integrity verification failed!");
        onFailed(env);
        return 0;
    }

    LOGI("=== Verification Passed. Score: %d/100 ===", score);
    return score;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_moe_ouom_wekit_loader_core_WeKitNative_doInit(JNIEnv* env, jclass clazz, jstring signatureHash) {
    if (signatureHash == nullptr) { onFailed(env); return JNI_FALSE; }
    const char* hashStr = env->GetStringUTFChars(signatureHash, nullptr);
    if (hashStr == nullptr) { onFailed(env); return JNI_FALSE; }
    g_verification_score = perform_multi_dimensional_verification(env, hashStr);
    env->ReleaseStringUTFChars(signatureHash, hashStr);
    if (g_verification_score >= 80) {
        LOGI("Verification SUCCESS");
        return JNI_TRUE;
    } else {
        LOGE("Verification FAILED finally (score: %d)", g_verification_score);
        onFailed(env);
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_moe_ouom_wekit_loader_core_WeKitNative_nativeCheck(JNIEnv* env, jclass clazz) {
    if (!g_signature_valid || !g_dex_valid) {
        LOGE("Integrity check failed: invalid state");
        onFailed(env);
        return JNI_FALSE;
    }
    if (g_verification_score < 80) {
        LOGE("Integrity check failed: score too low (%d)", g_verification_score);
        onFailed(env);
        return JNI_FALSE;
    }
    LOGI("Integrity check passed");
    return JNI_TRUE;
}


extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    LOGI("WeKit native library loaded");
    return JNI_VERSION_1_6;
}