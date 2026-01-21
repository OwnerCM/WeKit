#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <array>

class SHA256 {
public:
    static const size_t DIGEST_SIZE = 32;

    SHA256() {
        reset();
    }

    void reset() {
        m_state[0] = 0x6a09e667;
        m_state[1] = 0xbb67ae85;
        m_state[2] = 0x3c6ef372;
        m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f;
        m_state[5] = 0x9b05688c;
        m_state[6] = 0x1f83d9ab;
        m_state[7] = 0x5be0cd19;
        m_data_len = 0;
        m_bit_len = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            m_data[m_data_len] = data[i];
            m_data_len++;
            if (m_data_len == 64) {
                transform();
                m_bit_len += 512;
                m_data_len = 0;
            }
        }
    }

    void update(const std::string& data) {
        update(reinterpret_cast<const uint8_t*>(data.c_str()), data.size());
    }

    void update(const std::vector<uint8_t>& data) {
        update(data.data(), data.size());
    }

    void final(uint8_t* digest) {
        uint32_t i = m_data_len;

        // Append 1 bit
        m_data[i++] = 0x80;

        // Pad with zeros
        if (i > 56) {
            while (i < 64) m_data[i++] = 0x00;
            transform();
            memset(m_data, 0, 56);
        } else {
            while (i < 56) m_data[i++] = 0x00;
        }

        // Append total message length in bits and transform
        m_bit_len += static_cast<uint64_t>(m_data_len) * 8;

        // SHA256 uses Big-Endian for length
        m_data[63] = m_bit_len;
        m_data[62] = m_bit_len >> 8;
        m_data[61] = m_bit_len >> 16;
        m_data[60] = m_bit_len >> 24;
        m_data[59] = m_bit_len >> 32;
        m_data[58] = m_bit_len >> 40;
        m_data[57] = m_bit_len >> 48;
        m_data[56] = m_bit_len >> 56;

        transform();

        // Copy state to output (Big-Endian)
        for (i = 0; i < 4; ++i) {
            digest[i]      = (m_state[0] >> (24 - i * 8)) & 0x000000ff;
            digest[i + 4]  = (m_state[1] >> (24 - i * 8)) & 0x000000ff;
            digest[i + 8]  = (m_state[2] >> (24 - i * 8)) & 0x000000ff;
            digest[i + 12] = (m_state[3] >> (24 - i * 8)) & 0x000000ff;
            digest[i + 16] = (m_state[4] >> (24 - i * 8)) & 0x000000ff;
            digest[i + 20] = (m_state[5] >> (24 - i * 8)) & 0x000000ff;
            digest[i + 24] = (m_state[6] >> (24 - i * 8)) & 0x000000ff;
            digest[i + 28] = (m_state[7] >> (24 - i * 8)) & 0x000000ff;
        }
    }

    // 方便的一站式静态函数
    static std::string hash_to_hex(const std::string& input) {
        SHA256 sha;
        sha.update(input);
        uint8_t digest[32];
        sha.final(digest);

        char buf[65];
        for (int i = 0; i < 32; i++) {
            sprintf(buf + (i * 2), "%02x", digest[i]);
        }
        buf[64] = 0;
        return std::string(buf);
    }

private:
    uint8_t m_data[64];
    uint32_t m_data_len;
    uint64_t m_bit_len;
    uint32_t m_state[8]; // A, B, C, D, E, F, G, H

    static const uint32_t K[64];

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
        return (e & f) ^ (~e & g);
    }

    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
        return (a & (b | c)) | (b & c);
    }

    static uint32_t sig0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static uint32_t sig1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transform() {
        uint32_t maj, xor_f, sum_a, sum_e, t1, t2;
        uint32_t m[64];
        uint32_t a = m_state[0];
        uint32_t b = m_state[1];
        uint32_t c = m_state[2];
        uint32_t d = m_state[3];
        uint32_t e = m_state[4];
        uint32_t f = m_state[5];
        uint32_t g = m_state[6];
        uint32_t h = m_state[7];

        for (int i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | (m_data[j + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
        }

        for (int i = 0; i < 64; ++i) {
            maj = majority(a, b, c);
            xor_f = choose(e, f, g);
            sum_a = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            sum_e = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            t1 = h + sum_e + xor_f + K[i] + m[i];
            t2 = sum_a + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }
};

// SHA-256 Constants
const uint32_t SHA256::K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static void compute_sha256(const uint8_t* data, size_t len, uint8_t* output) {
    SHA256 sha;
    sha.update(data, len);
    sha.final(output);
}

#endif // SHA256_H