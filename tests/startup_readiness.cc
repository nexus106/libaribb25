// Synthetic transport streams and keys only; no card or broadcast recording.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <stdexcept>
#include <vector>

#include "arib_std_b25.h"
#include "arib_std_b25_error_code.h"
#include "multi2.h"

namespace {
using Bytes = std::vector<uint8_t>;
void require(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}
B_CAS_INIT_STATUS status() {
    B_CAS_INIT_STATUS s = {};
    s.ca_system_id = 5;
    for (unsigned i = 0; i < sizeof(s.system_key); ++i) s.system_key[i] = uint8_t(i * 7 + 1);
    for (unsigned i = 0; i < sizeof(s.init_cbc); ++i) s.init_cbc[i] = uint8_t(i + 11);
    return s;
}
Bytes key(unsigned id) {
    Bytes k(16);
    for (unsigned i = 0; i < k.size(); ++i) k[i] = uint8_t(id * 53 + i * 3 + 1);
    return k;
}
int card_status(void *, B_CAS_INIT_STATUS *s) { *s = status(); return 0; }
int card_id(void *, B_CAS_ID *id) { id->data = NULL; id->count = 0; return 0; }
int card_ecm(void *, B_CAS_ECM_RESULT *r, uint8_t *p, int n) {
    if (n < 1) return -1;
    Bytes k = key(p[0]);
    std::memcpy(r->scramble_key, k.data(), k.size());
    r->return_code = p[0] == 0xff ? 0xa901 : 0x0800;
    return 0;
}
struct Decoder {
    B_CAS_CARD card = {};
    ARIB_STD_B25 *d;
    Bytes output;
    Decoder() : d(create_arib_std_b25()) {
        require(d != NULL, "create decoder");
        card.get_init_status = card_status;
        card.get_id = card_id;
        card.proc_ecm = card_ecm;
        require(d->set_b_cas_card(d, &card) == 0, "attach fake card");
        require(d->set_unit_size(d, 188) == 0, "set packet size");
    }
    ~Decoder() { d->release(d); }
    int put(const Bytes &bytes, size_t chunk) {
        int code = 0;
        for (size_t at = 0; at < bytes.size(); at += chunk) {
            ARIB_STD_B25_BUFFER b = {const_cast<uint8_t *>(bytes.data() + at),
                uint32_t(std::min(chunk, bytes.size() - at))};
            code = d->put(d, &b);
            get();
            if (code < 0) break;
        }
        return code;
    }
    void get() {
        ARIB_STD_B25_BUFFER b = {};
        require(d->get(d, &b) == 0, "get output");
        if (b.size) output.insert(output.end(), b.data, b.data + b.size);
    }
    void finish() { require(d->flush(d) >= 0, "flush output"); get(); }
};
void crc(Bytes &s) {
    uint32_t c = 0xffffffff;
    for (uint8_t b : s) {
        c ^= uint32_t(b) << 24;
        for (int i = 0; i < 8; ++i) c = (c << 1) ^ ((c & 0x80000000) ? 0x04c11db7 : 0);
    }
    for (int shift = 24; shift >= 0; shift -= 8) s.push_back(uint8_t(c >> shift));
}
Bytes section(uint8_t tid, const Bytes &body, bool syntax = true) {
    size_t len = body.size() + 4;
    Bytes s = {tid, uint8_t((syntax ? 0xb0 : 0x30) | (len >> 8)), uint8_t(len)};
    s.insert(s.end(), body.begin(), body.end()); crc(s); return s;
}
Bytes pat() {
    return section(0, {0, 1, 0xc1, 0, 0, 0, 1, 0xe1, 0, 0, 2, 0xe2, 0});
}
Bytes pmt(unsigned program, unsigned video, unsigned ecm = 0) {
    Bytes b = {0, uint8_t(program), 0xc1, 0, 0,
        uint8_t(0xe0 | (video >> 8)), uint8_t(video), 0xf0, uint8_t(ecm ? 6 : 0)};
    if (ecm) {
        Bytes ca = {9, 4, 0, 5, uint8_t(0xe0 | (ecm >> 8)), uint8_t(ecm)};
        b.insert(b.end(), ca.begin(), ca.end());
    }
    Bytes es = {2, uint8_t(0xe0 | (video >> 8)), uint8_t(video), 0xf0, 0};
    b.insert(b.end(), es.begin(), es.end()); return section(2, b);
}
struct Stream {
    Bytes bytes, plain;
    std::map<unsigned, unsigned> counters;
    void packet(unsigned pid, const Bytes &payload, bool start = false, int crypt = -1) {
        require(payload.size() <= 184, "payload size");
        Bytes p(188, 0xff);
        p[0] = 0x47; p[1] = uint8_t((start ? 0x40 : 0) | (pid >> 8)); p[2] = uint8_t(pid);
        p[3] = uint8_t(0x10 | (counters[pid]++ & 15));
        std::copy(payload.begin(), payload.end(), p.begin() + 4);
        plain.insert(plain.end(), p.begin(), p.end());
        if (crypt >= 0) {
            MULTI2 *m = create_multi2(); require(m != NULL, "create cipher");
            B_CAS_INIT_STATUS s = status(); Bytes k = key(unsigned(crypt));
            require(m->set_system_key(m, s.system_key) == 0 &&
                m->set_init_cbc(m, s.init_cbc) == 0 &&
                m->set_scramble_key(m, k.data()) == 0, "configure cipher");
            require(m->encrypt(m, 2, p.data() + 4, 184) == 0, "encrypt payload");
            m->release(m); p[3] |= 0x80;
        }
        bytes.insert(bytes.end(), p.begin(), p.end());
    }
    void psi(unsigned pid, const Bytes &s) {
        Bytes payload(1, 0); payload.insert(payload.end(), s.begin(), s.end()); packet(pid, payload, true);
    }
    void media(unsigned pid, int crypt) {
        Bytes p(184); for (unsigned i = 0; i < p.size(); ++i) p[i] = uint8_t(i * 37 + pid);
        packet(pid, p, false, crypt);
    }
    void nulls(unsigned count = 2) { while (count--) packet(0x1fff, {}); }
};
void delayed(bool ecm_delay, size_t chunk, bool reset = false, unsigned repeats = 0) {
    Decoder d;
    for (unsigned pass = 0; pass < (reset ? 2u : 1u); ++pass) {
        if (pass) {
            require(d.d->reset(d.d) == 0, "reset decoder");
            require(d.d->set_unit_size(d.d, 188) == 0, "reset packet size");
            d.output.clear();
        }
        Stream s;
        s.psi(0, pat()); s.media(0x201, 1);
        s.psi(0x100, pmt(1, 0x101, ecm_delay ? 0x301 : 0));
        if (ecm_delay) {
            s.psi(0x200, pmt(2, 0x201, 0x302));
            s.psi(0x301, section(0x82, {0}, false));
            s.psi(0x301, section(0x82, {0}, false));
        } else {
            s.psi(0x100, pmt(1, 0x101));
        }
        for (unsigned i = 0; i < repeats; ++i) {
            if (ecm_delay) s.psi(0x301, section(0x82, {0}, false));
            else s.psi(0x100, pmt(1, 0x101));
        }
        s.nulls();
        require(d.put(s.bytes, chunk) >= 0, "buffer delayed tables");
        require(d.output.empty(), ecm_delay ? "output before all ECMs" : "output before all PMTs");
        size_t boundary = s.bytes.size();
        if (!ecm_delay) s.psi(0x200, pmt(2, 0x201, 0x302));
        s.psi(0x302, section(0x82, {1}, false));
        s.media(0x201, 1); s.nulls();
        Bytes suffix(s.bytes.begin() + boundary, s.bytes.end());
        require(d.put(suffix, chunk) >= 0, "supply missing table");
        d.finish();
        require(d.output == s.plain, "decrypted stream differs from plaintext");
    }
}
void missing(bool ecm_delay) {
    Decoder d; Stream s;
    s.psi(0, pat()); s.psi(0x100, pmt(1, 0x101, ecm_delay ? 0x301 : 0));
    if (ecm_delay) {
        s.psi(0x200, pmt(2, 0x201, 0x302));
        s.psi(0x301, section(0x82, {0}, false));
        s.psi(0x301, section(0x82, {0}, false));
    } else s.psi(0x100, pmt(1, 0x101));
    s.media(0x201, 1);
    s.nulls(); require(d.put(s.bytes, 188) >= 0, "buffer missing table");
    require(d.output.empty(), "output with missing table");
    Stream padding; padding.nulls(128);
    int code = 0;
    for (unsigned i = 0; i < 1500 && code >= 0; ++i) {
        code = d.put(padding.bytes, padding.bytes.size());
        require(d.output.empty(), "output while missing table");
    }
    require(code == (ecm_delay ? ARIB_STD_B25_ERROR_NO_ECM_IN_HEAD_32M :
        ARIB_STD_B25_ERROR_NO_PMT_IN_HEAD_32M), "missing-table buffer limit");
}
// EOF must still decrypt available programs when a PAT entry has no PMT.
void sparse_pat(size_t chunk) {
    Decoder d; Stream s; s.psi(0, pat());
    s.psi(0x100, pmt(1, 0x101, 0x301));
    s.media(0x101, 0);
    s.psi(0x100, pmt(1, 0x101, 0x301));
    s.psi(0x301, section(0x82, {0}, false));
    s.psi(0x301, section(0x82, {0}, false)); s.nulls();
    require(d.put(s.bytes, chunk) >= 0, "sparse PAT input");
    require(!d.output.empty(), "inactive PAT entry blocked streaming output");
    d.finish(); require(d.output == s.plain, "sparse PAT lost initial decryption at EOF");
}
void sparse_ecm(size_t chunk) {
    Decoder d; Stream s; s.psi(0, pat());
    s.psi(0x100, pmt(1, 0x101, 0x301));
    s.psi(0x200, pmt(2, 0x201, 0x302));
    s.media(0x101, 0);
    s.psi(0x301, section(0x82, {0}, false));
    s.psi(0x301, section(0x82, {0}, false)); s.nulls();
    require(d.put(s.bytes, chunk) >= 0, "sparse ECM input");
    require(!d.output.empty(), "inactive ECM blocked streaming output");
    d.finish(); require(d.output == s.plain, "sparse ECM decryption");
}
void long_sparse(bool missing_ecm) {
    Decoder d; Stream s; s.psi(0, pat());
    s.psi(0x100, pmt(1, 0x101, 0x301));
    if (missing_ecm) s.psi(0x200, pmt(2, 0x201, 0x302));
    s.media(0x101, 0); s.psi(0x100, pmt(1, 0x101, 0x301));
    s.psi(0x301, section(0x82, {0}, false));
    s.psi(0x301, section(0x82, {0}, false)); s.nulls();
    require(d.put(s.bytes, 188) >= 0 && !d.output.empty(), "start long sparse stream");
    Stream padding; padding.nulls(128);
    const unsigned chunks = 1500; // More than the 32 MiB probing limit.
    for (unsigned i = 0; i < chunks; ++i)
        require(d.put(padding.bytes, padding.bytes.size()) >= 0, "long sparse stream stalled");
    d.finish();
    require(d.output.size() == s.plain.size() + chunks * padding.bytes.size(), "long sparse stream packet loss");
    require(std::equal(s.plain.begin(), s.plain.end(), d.output.begin()), "long sparse stream prefix decryption");
}
// PMTs and ECMs first seen by the normal streaming path must count as ready.
void streaming_tables(bool late_ecm, size_t chunk, bool unpurchased = false) {
    Decoder d; Stream initial;
    initial.psi(0, pat());
    initial.psi(0x100, pmt(1, 0x101, 0x301));
    if (late_ecm) initial.psi(0x200, pmt(2, 0x201, 0x302));
    initial.media(0x101, 0);
    initial.psi(0x100, pmt(1, 0x101, 0x301));
    initial.psi(0x301, section(0x82, {0}, false));
    initial.psi(0x301, section(0x82, {0}, false));
    initial.nulls();
    require(d.put(initial.bytes, chunk) >= 0 && !d.output.empty(), "start partial streaming tables");
    Stream ready;
    if (late_ecm) ready.psi(0x302, section(0x82, {uint8_t(unpurchased ? 0xff : 1)}, false));
    else ready.psi(0x200, pmt(2, 0x201, 0x301));
    ready.nulls();
    require(d.put(ready.bytes, chunk) >= 0, "complete tables during streaming");
    size_t before = d.output.size();
    Stream media;
    media.media(0x333, 0); // Private PID not described by any PMT.
    media.media(0x101, 0);
    media.media(0x201, late_ecm ? 1 : 0);
    media.nulls();
    require(d.put(media.bytes, chunk) >= 0, "continue after streaming tables");
    require(d.output.size() > before, "already received tables blocked private PID");
    d.finish();
    Bytes expected = initial.plain;
    expected.insert(expected.end(), ready.plain.begin(), ready.plain.end());
    // Existing behavior cannot select a key for an unlisted PID with two ECMs.
    if (late_ecm) std::copy(media.bytes.begin(), media.bytes.begin() + 188, media.plain.begin());
    if (unpurchased) std::copy(media.bytes.begin() + 376, media.bytes.begin() + 564, media.plain.begin() + 376);
    expected.insert(expected.end(), media.plain.begin(), media.plain.end());
    require(d.output == expected, "streaming table decryption changed");
}
void clear_stream() {
    Decoder d; Stream s; s.psi(0, pat());
    s.psi(0x100, pmt(1, 0x101)); s.psi(0x200, pmt(2, 0x201));
    s.media(0x101, -1); s.media(0x201, -1); s.nulls();
    require(d.put(s.bytes, 1) >= 0, "clear stream input"); d.finish();
    require(d.output == s.plain, "clear stream changed");
}
}
int main() {
    unsigned failures = 0;
    for (size_t chunk : {size_t(1), size_t(188), size_t(32712)}) {
        for (bool ecm : {false, true}) {
            try { delayed(ecm, chunk); }
            catch (const std::exception &e) {
                std::fprintf(stderr, "delayed %s chunk=%zu: %s\n", ecm ? "ECM" : "PMT", chunk, e.what()); ++failures;
            }
        }
    }
    for (bool ecm : {false, true}) {
        try { delayed(ecm, 32712, false, 20); }
        catch (const std::exception &e) { std::fprintf(stderr, "repeat-heavy %s: %s\n", ecm ? "ECM" : "PMT", e.what()); ++failures; }
    }
    for (size_t chunk : {size_t(1), size_t(188), size_t(32712)}) {
        try { sparse_pat(chunk); sparse_ecm(chunk); }
        catch (const std::exception &e) { std::fprintf(stderr, "sparse PAT chunk=%zu: %s\n", chunk, e.what()); ++failures; }
    }
    for (size_t chunk : {size_t(1), size_t(188), size_t(32712)}) {
        for (bool ecm : {false, true}) {
            try { streaming_tables(ecm, chunk); if (ecm) streaming_tables(true, chunk, true); }
            catch (const std::exception &e) { std::fprintf(stderr, "streaming %s chunk=%zu: %s\n", ecm ? "ECM" : "PMT", chunk, e.what()); ++failures; }
        }
    }
    try { delayed(false, 188, true); clear_stream(); missing(false); missing(true); long_sparse(false); long_sparse(true); }
    catch (const std::exception &e) { std::fprintf(stderr, "edge case: %s\n", e.what()); ++failures; }
    return failures ? 1 : 0;
}
