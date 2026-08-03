#ifdef _WIN32
#define _WIN32_WINNT 0x0601
#endif

// Cross-platform TCP using Boost.Asio (works on Windows/VS too)
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
using boost::asio::ip::tcp;

// Crypto++ (RSA/AES) for end-to-end encryption
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/oaep.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

// =====================
// Protocol constants
// =====================
static const uint8_t  VERSION = 1;

// Request codes
static const uint16_t CODE_REGISTER     = 700;
static const uint16_t CODE_LIST_CLIENTS = 701;
static const uint16_t CODE_GET_PUBKEY   = 702;
static const uint16_t CODE_SEND_MSG     = 703;
static const uint16_t CODE_PULL_MSGS    = 704;

// Response codes
static const uint16_t RES_REGISTER_OK   = 2100;
static const uint16_t RES_LIST_CLIENTS  = 2101;
static const uint16_t RES_PUBKEY        = 2102;
static const uint16_t RES_MSG_STORED    = 2103;
static const uint16_t RES_WAITING_MSGS  = 2104;
static const uint16_t RES_ERROR         = 9000;

// Fixed sizes (per spec)
static const size_t NAME_FIELD_SIZE = 255;
static const size_t PUBKEY_SIZE     = 160;
static const size_t AES_KEY_SIZE    = 16;
static const size_t AES_BLOCK_SIZE  = 16;

// Files (per spec)
static const char* SERVER_INFO_FILE = "server.info";
static const char* ID_FILE = "my.info";

// =====================
// Small helpers
// =====================

// Trim whitespace from input lines
static std::string trim(std::string s) {
    auto notspace = [](unsigned char c){ return c!=' ' && c!='\t' && c!='\r' && c!='\n'; };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
    return s;
}

// Must print exactly this string on server errors (per spec)
static void server_error() {
    std::cout << "server responded with an error" << std::endl;
}

// Print the exact menu format (per spec)
static void print_menu() {
    std::cout << "MessageU client at your service.\n\n";
    std::cout << "110) Register\n";
    std::cout << "120) Request for clients list\n";
    std::cout << "130) Request for public key\n";
    std::cout << "140) Request for waiting messages\n";
    std::cout << "150) Send a text message\n";
    std::cout << "151) Send a request for symmetric key\n";
    std::cout << "152) Send your symmetric key\n";
    std::cout << " 0) Exit client\n";
    std::cout << "?\n";
}

// Convert 16-byte UUID to hex for files / maps
static std::string bytes_to_hex(const uint8_t* data, size_t n) {
    std::ostringstream oss;
    for (size_t i = 0; i < n; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

// Parse 32-hex string into 16 bytes
static bool hex_to_bytes_16(const std::string& hex, uint8_t out[16]) {
    if (hex.size() != 32) return false;
    auto hexval = [](char c)->int{
        if ('0'<=c && c<='9') return c-'0';
        if ('a'<=c && c<='f') return 10+(c-'a');
        if ('A'<=c && c<='F') return 10+(c-'A');
        return -1;
    };
    for (int i=0;i<16;i++){
        int hi = hexval(hex[2*i]);
        int lo = hexval(hex[2*i+1]);
        if (hi<0 || lo<0) return false;
        out[i] = (uint8_t)((hi<<4)|lo);
    }
    return true;
}

// Little-endian helpers for protocol fields
static void append_le16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back((uint8_t)(v & 0xFF));
    b.push_back((uint8_t)((v >> 8) & 0xFF));
}
static void append_le32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back((uint8_t)(v & 0xFF));
    b.push_back((uint8_t)((v >> 8) & 0xFF));
    b.push_back((uint8_t)((v >> 16) & 0xFF));
    b.push_back((uint8_t)((v >> 24) & 0xFF));
}
static uint16_t read_le16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t read_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Pack username into 255 bytes (null-terminated)
static std::vector<uint8_t> pack_name_255(const std::string& name) {
    std::vector<uint8_t> out(NAME_FIELD_SIZE, 0);
    size_t n = std::min<size_t>(name.size(), 254);
    std::memcpy(out.data(), name.data(), n);
    out[n] = 0;
    return out;
}

// =====================
// Transport (Polymorphism)
// =====================

// Interface = allows replacing transport implementation without changing protocol logic
class ITransport {
public:
    virtual ~ITransport() = default;
    virtual bool write_all(const void* buf, size_t n) = 0;
    virtual bool read_exact(void* buf, size_t n) = 0;
};

// Boost.Asio implementation of transport
class BoostTransport final : public ITransport {
public:
    BoostTransport(const std::string& host, const std::string& port)
        : io_(), sock_(io_) {
        tcp::resolver resolver(io_);
        boost::system::error_code ec;
        auto endpoints = resolver.resolve(host, port, ec);
        if (ec) throw std::runtime_error("resolve failed");
        boost::asio::connect(sock_, endpoints, ec);
        if (ec) throw std::runtime_error("connect failed");
    }

    bool write_all(const void* buf, size_t n) override {
        boost::system::error_code ec;
        boost::asio::write(sock_, boost::asio::buffer(buf, n), ec);
        return !ec;
    }

    bool read_exact(void* buf, size_t n) override {
        boost::system::error_code ec;
        boost::asio::read(sock_, boost::asio::buffer(buf, n), ec);
        return !ec;
    }

    void close() {
        boost::system::error_code ec;
        sock_.close(ec);
    }

private:
    boost::asio::io_context io_;
    tcp::socket sock_;
};

// =====================
// Protocol client
// =====================

struct Response {
    uint8_t version;
    uint16_t code;
    std::vector<uint8_t> payload;
};

// Packs requests and parses responses according to the protocol
class ProtocolClient {
public:
    explicit ProtocolClient(ITransport& t) : t_(t) {}

    Response request(const uint8_t client_id[16], uint16_t code, const std::vector<uint8_t>& payload) {
        // Request header: client_id(16) + version(1) + code(2) + payload_size(4)
        std::vector<uint8_t> hdr;
        hdr.reserve(23);
        hdr.insert(hdr.end(), client_id, client_id + 16);
        hdr.push_back(VERSION);
        append_le16(hdr, code);
        append_le32(hdr, (uint32_t)payload.size());

        if (!t_.write_all(hdr.data(), hdr.size())) throw std::runtime_error("send header failed");
        if (!payload.empty() && !t_.write_all(payload.data(), payload.size())) throw std::runtime_error("send payload failed");

        // Response header: version(1) + code(2) + payload_size(4)
        uint8_t rhdr[7];
        if (!t_.read_exact(rhdr, sizeof(rhdr))) throw std::runtime_error("recv response header failed");

        Response r;
        r.version = rhdr[0];
        r.code = read_le16(&rhdr[1]);
        uint32_t psz = read_le32(&rhdr[3]);

        r.payload.resize(psz);
        if (psz > 0 && !t_.read_exact(r.payload.data(), psz)) throw std::runtime_error("recv response payload failed");
        return r;
    }

private:
    ITransport& t_;
};

// =====================
// Identity store (my.info)
// =====================

// Handles reading/writing identity file:
// line1: name
// line2: UUID hex (32 chars)
// line3: private key base64
class IdentityStore {
public:
    bool exists() const {
        return file_exists(ID_FILE);
    }

    bool load(std::string& name, uint8_t id[16], CryptoPP::RSA::PrivateKey& priv) const {
        return try_load(ID_FILE, name, id, priv);
    }

    void save(const std::string& name, const uint8_t id[16], const CryptoPP::RSA::PrivateKey& priv) const {
        write_file(ID_FILE, name, id, priv);
    }

private:
    static bool file_exists(const char* path) {
        std::ifstream in(path);
        return (bool)in;
    }

    static std::string base64_encode_bytes(const std::vector<uint8_t>& data) {
        std::string out;
        CryptoPP::StringSource ss(
            data.data(), data.size(), true,
            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false)
        );
        return out;
    }

    static std::vector<uint8_t> base64_decode_bytes(const std::string& b64) {
        std::string decoded;
        CryptoPP::StringSource ss(
            b64, true,
            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded))
        );
        return std::vector<uint8_t>(decoded.begin(), decoded.end());
    }

    static std::string rsa_priv_to_base64(const CryptoPP::RSA::PrivateKey& priv) {
        CryptoPP::ByteQueue q;
        priv.Save(q);
        std::vector<uint8_t> raw(q.CurrentSize());
        q.Get(raw.data(), raw.size());
        return base64_encode_bytes(raw);
    }

    static CryptoPP::RSA::PrivateKey rsa_priv_from_base64(const std::string& b64) {
        std::vector<uint8_t> raw = base64_decode_bytes(b64);
        CryptoPP::ByteQueue q;
        q.Put(raw.data(), raw.size());
        CryptoPP::RSA::PrivateKey priv;
        priv.Load(q);
        return priv;
    }

    static bool try_load(const char* path, std::string& name, uint8_t id[16], CryptoPP::RSA::PrivateKey& priv) {
        std::ifstream in(path);
        if (!in) return false;

        std::string l1, l2, l3;
        std::getline(in, l1);
        std::getline(in, l2);
        std::getline(in, l3);
        l1 = trim(l1); l2 = trim(l2); l3 = trim(l3);
        if (l1.empty() || l2.empty() || l3.empty()) return false;

        uint8_t tmp[16];
        if (!hex_to_bytes_16(l2, tmp)) return false;

        priv = rsa_priv_from_base64(l3);
        name = l1;
        std::memcpy(id, tmp, 16);
        return true;
    }

    static void write_file(const char* path, const std::string& name, const uint8_t id[16], const CryptoPP::RSA::PrivateKey& priv) {
        std::ofstream out(path, std::ios::trunc);
        if (!out) throw std::runtime_error("failed to write identity file");
        out << name << "\n";
        out << bytes_to_hex(id, 16) << "\n";
        out << rsa_priv_to_base64(priv) << "\n";
    }
};

// =====================
// Crypto manager (RSA + AES)
// =====================

class CryptoManager {
public:
    // Generate RSA-1024 keypair
    void generate_rsa(CryptoPP::RSA::PrivateKey& priv, CryptoPP::RSA::PublicKey& pub) const {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 1024);
        priv = CryptoPP::RSA::PrivateKey(params);
        pub  = CryptoPP::RSA::PublicKey(params);
    }

    // Serialize public key into a 160-byte blob (as required by the protocol)
    std::vector<uint8_t> pub_blob_160(const CryptoPP::RSA::PublicKey& pub) const {
        CryptoPP::ByteQueue q;
        pub.Save(q);
        size_t n = q.CurrentSize();
        if (n != PUBKEY_SIZE) throw std::runtime_error("public key size mismatch (expected 160)");
        std::vector<uint8_t> out(n);
        q.Get(out.data(), out.size());
        return out;
    }

    CryptoPP::RSA::PublicKey pub_from_blob(const std::vector<uint8_t>& blob) const {
        if (blob.size() != PUBKEY_SIZE) throw std::runtime_error("Invalid public key blob size");
        CryptoPP::ByteQueue q;
        q.Put(blob.data(), blob.size());
        CryptoPP::RSA::PublicKey pub;
        pub.Load(q);
        return pub;
    }

    // RSA OAEP-SHA encryption/decryption for symmetric key transfer (type 2)
    std::vector<uint8_t> rsa_encrypt(const CryptoPP::RSA::PublicKey& pub, const std::vector<uint8_t>& plain) const {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Encryptor enc(pub);
        std::string cipher;
        CryptoPP::StringSource ss(
            plain.data(), plain.size(), true,
            new CryptoPP::PK_EncryptorFilter(rng, enc, new CryptoPP::StringSink(cipher))
        );
        return std::vector<uint8_t>(cipher.begin(), cipher.end());
    }

    std::vector<uint8_t> rsa_decrypt(const CryptoPP::RSA::PrivateKey& priv, const std::vector<uint8_t>& cipher) const {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Decryptor dec(priv);
        std::string plain;
        CryptoPP::StringSource ss(
            cipher.data(), cipher.size(), true,
            new CryptoPP::PK_DecryptorFilter(rng, dec, new CryptoPP::StringSink(plain))
        );
        return std::vector<uint8_t>(plain.begin(), plain.end());
    }

    // AES-CBC with IV=0 for message encryption (type 3)
    std::vector<uint8_t> aes_encrypt_iv0(const std::vector<uint8_t>& key16, const std::vector<uint8_t>& plain) const {
        if (key16.size() != AES_KEY_SIZE) throw std::runtime_error("AES key must be 16 bytes");
        byte iv[AES_BLOCK_SIZE] = {0};

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key16.data(), key16.size(), iv);

        std::string cipher;
        CryptoPP::StringSource ss(
            plain.data(), plain.size(), true,
            new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(cipher))
        );
        return std::vector<uint8_t>(cipher.begin(), cipher.end());
    }

    std::vector<uint8_t> aes_decrypt_iv0(const std::vector<uint8_t>& key16, const std::vector<uint8_t>& cipher) const {
        if (key16.size() != AES_KEY_SIZE) throw std::runtime_error("AES key must be 16 bytes");
        byte iv[AES_BLOCK_SIZE] = {0};

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key16.data(), key16.size(), iv);

        std::string plain;
        CryptoPP::StringSource ss(
            cipher.data(), cipher.size(), true,
            new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(plain))
        );
        return std::vector<uint8_t>(plain.begin(), plain.end());
    }
};

// =====================
// Directory (name <-> uuid mapping)
// =====================

class ClientDirectory {
public:
    // Parse 2101 payload: repeated (UUID(16) + Name(255))
    void update_from_list_payload(const std::vector<uint8_t>& pl, bool print_names) {
        const size_t recSize = 16 + 255;
        if (pl.size() % recSize != 0) throw std::runtime_error("bad list payload");

        for (size_t i = 0; i < pl.size(); i += recSize) {
            const uint8_t* p = pl.data() + i;
            std::string idhex = bytes_to_hex(p, 16);
            const uint8_t* namep = p + 16;

            size_t nlen = 0;
            while (nlen < 255 && namep[nlen] != 0) nlen++;
            std::string nm((const char*)namep, (const char*)namep + nlen);

            name_to_idhex_[nm] = idhex;
            idhex_to_name_[idhex] = nm;

            if (print_names) std::cout << nm << "\n";
        }
    }

    // Resolve a username to UUID; refresh list once if missing
    bool resolve_user_to_id(ProtocolClient& proto, const uint8_t my_id[16], const std::string& user, uint8_t out_id[16]) {
        auto it = name_to_idhex_.find(user);
        if (it == name_to_idhex_.end()) {
            std::vector<uint8_t> empty;
            auto r = proto.request(my_id, CODE_LIST_CLIENTS, empty);
            if (r.code != RES_LIST_CLIENTS) return false;
            try { update_from_list_payload(r.payload, false); }
            catch (...) { return false; }
            it = name_to_idhex_.find(user);
            if (it == name_to_idhex_.end()) return false;
        }
        return hex_to_bytes_16(it->second, out_id);
    }

    // Resolve UUID to username; refresh list once if missing
    std::string name_from_idhex(ProtocolClient& proto, const uint8_t my_id[16], const std::string& idhex) {
        auto it = idhex_to_name_.find(idhex);
        if (it != idhex_to_name_.end()) return it->second;

        std::vector<uint8_t> empty;
        auto r = proto.request(my_id, CODE_LIST_CLIENTS, empty);
        if (r.code == RES_LIST_CLIENTS) {
            try { update_from_list_payload(r.payload, false); } catch (...) {}
        }
        it = idhex_to_name_.find(idhex);
        return (it != idhex_to_name_.end()) ? it->second : "<unknown>";
    }

    void set_self(const uint8_t my_id[16], const std::string& name) {
        idhex_to_name_[bytes_to_hex(my_id, 16)] = name;
        name_to_idhex_[name] = bytes_to_hex(my_id, 16);
    }

private:
    std::unordered_map<std::string, std::string> name_to_idhex_;
    std::unordered_map<std::string, std::string> idhex_to_name_;
};

// =====================
// App (menu + commands)
// =====================

class MessageUClientApp {
public:
    MessageUClientApp(ITransport& t)
        : proto_(t) {}

    void run() {
        while (true) {
            print_menu();
            std::string cmd;
            if (!std::getline(std::cin, cmd)) break;
            cmd = trim(cmd);

            if (cmd == "0") break;
            if (cmd == "110") { on_register(); continue; }
            if (cmd == "120") { on_list(); continue; }
            if (cmd == "130") { on_get_pubkey(); continue; }
            if (cmd == "140") { on_pull(); continue; }
            if (cmd == "150") { on_send_text(); continue; }
            if (cmd == "151") { on_req_sym(); continue; }
            if (cmd == "152") { on_send_sym(); continue; }
        }
    }

    void load_identity_if_exists() {
        if (store_.load(my_name_, my_id_, my_priv_)) {
            registered_ = true;
            have_priv_ = true;
            dir_.set_self(my_id_, my_name_);
        }
    }

    bool is_registered() const { return registered_; }

private:
    // 110: Register (only if my.info does not exist)
    void on_register() {
        if (store_.exists() || registered_) {
            std::cout << "client already registered" << std::endl;
            std::string throwaway;
            std::getline(std::cin, throwaway); // consume username line if user typed it
            return;
        }

        std::string name;
        std::getline(std::cin, name);
        name = trim(name);

        CryptoPP::RSA::PrivateKey priv;
        CryptoPP::RSA::PublicKey pub;
        crypto_.generate_rsa(priv, pub);
        std::vector<uint8_t> pub_blob = crypto_.pub_blob_160(pub);

        std::vector<uint8_t> payload;
        auto name255 = pack_name_255(name);
        payload.insert(payload.end(), name255.begin(), name255.end());
        payload.insert(payload.end(), pub_blob.begin(), pub_blob.end());

        uint8_t zeros[16] = {0};
        auto r = proto_.request(zeros, CODE_REGISTER, payload);

        if (r.code != RES_REGISTER_OK || r.payload.size() != 16) {
            server_error();
            return;
        }

        std::memcpy(my_id_, r.payload.data(), 16);
        my_name_ = name;
        my_priv_ = priv;
        have_priv_ = true;
        registered_ = true;

        store_.save(my_name_, my_id_, my_priv_);
        dir_.set_self(my_id_, my_name_);
    }

    // 120: Request clients list (print only names)
    void on_list() {
        if (!registered_) { server_error(); return; }
        std::vector<uint8_t> empty;
        auto r = proto_.request(my_id_, CODE_LIST_CLIENTS, empty);
        if (r.code != RES_LIST_CLIENTS) { server_error(); return; }

        try { dir_.update_from_list_payload(r.payload, true); }
        catch (...) { server_error(); }
    }

    // 130: Request target public key (cached in RAM)
    void on_get_pubkey() {
        if (!registered_) { server_error(); return; }

        std::string target_user;
        std::getline(std::cin, target_user);
        target_user = trim(target_user);

        uint8_t target_id[16];
        if (!dir_.resolve_user_to_id(proto_, my_id_, target_user, target_id)) { server_error(); return; }

        std::vector<uint8_t> req(target_id, target_id + 16);
        auto r = proto_.request(my_id_, CODE_GET_PUBKEY, req);
        if (r.code != RES_PUBKEY || r.payload.size() != 16 + PUBKEY_SIZE) { server_error(); return; }

        std::string idhex = bytes_to_hex(target_id, 16);
        pubkey_cache_[idhex] = std::vector<uint8_t>(r.payload.begin() + 16, r.payload.end());
    }

    // 151: Send type=1 "Request for symmetric key"
    void on_req_sym() {
        if (!registered_) { server_error(); return; }

        std::string target_user;
        std::getline(std::cin, target_user);
        target_user = trim(target_user);

        uint8_t to_id[16];
        if (!dir_.resolve_user_to_id(proto_, my_id_, target_user, to_id)) { server_error(); return; }

        std::vector<uint8_t> payload;
        payload.insert(payload.end(), to_id, to_id + 16);
        payload.push_back(1);
        append_le32(payload, 0);

        auto r = proto_.request(my_id_, CODE_SEND_MSG, payload);
        if (r.code != RES_MSG_STORED) server_error();
    }

    // 152: Send type=2 RSA-encrypted AES key
    void on_send_sym() {
        if (!registered_ || !have_priv_) { server_error(); return; }

        std::string target_user;
        std::getline(std::cin, target_user);
        target_user = trim(target_user);

        uint8_t to_id[16];
        if (!dir_.resolve_user_to_id(proto_, my_id_, target_user, to_id)) { server_error(); return; }
        std::string to_hex = bytes_to_hex(to_id, 16);

        // Fetch public key if not cached
        if (pubkey_cache_.find(to_hex) == pubkey_cache_.end()) {
            std::vector<uint8_t> req(to_id, to_id + 16);
            auto rpk = proto_.request(my_id_, CODE_GET_PUBKEY, req);
            if (rpk.code != RES_PUBKEY || rpk.payload.size() != 16 + PUBKEY_SIZE) { server_error(); return; }
            pubkey_cache_[to_hex] = std::vector<uint8_t>(rpk.payload.begin() + 16, rpk.payload.end());
        }

        // Create symmetric key if missing
        if (symkey_cache_.find(to_hex) == symkey_cache_.end()) {
            CryptoPP::AutoSeededRandomPool rng;
            std::vector<uint8_t> k(AES_KEY_SIZE);
            rng.GenerateBlock(k.data(), k.size());
            symkey_cache_[to_hex] = k;
        }

        CryptoPP::RSA::PublicKey pub = crypto_.pub_from_blob(pubkey_cache_[to_hex]);
        std::vector<uint8_t> enc_key = crypto_.rsa_encrypt(pub, symkey_cache_[to_hex]);

        std::vector<uint8_t> payload;
        payload.insert(payload.end(), to_id, to_id + 16);
        payload.push_back(2);
        append_le32(payload, (uint32_t)enc_key.size());
        payload.insert(payload.end(), enc_key.begin(), enc_key.end());

        auto r = proto_.request(my_id_, CODE_SEND_MSG, payload);
        if (r.code != RES_MSG_STORED) server_error();
    }

    // 150: Send type=3 AES-encrypted text
    void on_send_text() {
        if (!registered_) { server_error(); return; }

        std::string target_user;
        std::getline(std::cin, target_user);
        target_user = trim(target_user);

        std::string text;
        std::getline(std::cin, text);

        uint8_t to_id[16];
        if (!dir_.resolve_user_to_id(proto_, my_id_, target_user, to_id)) { server_error(); return; }

        std::string to_hex = bytes_to_hex(to_id, 16);
        if (symkey_cache_.find(to_hex) == symkey_cache_.end()) { server_error(); return; }

        std::vector<uint8_t> plain(text.begin(), text.end());
        std::vector<uint8_t> cipher = crypto_.aes_encrypt_iv0(symkey_cache_[to_hex], plain);

        std::vector<uint8_t> payload;
        payload.insert(payload.end(), to_id, to_id + 16);
        payload.push_back(3);
        append_le32(payload, (uint32_t)cipher.size());
        payload.insert(payload.end(), cipher.begin(), cipher.end());

        auto r = proto_.request(my_id_, CODE_SEND_MSG, payload);
        if (r.code != RES_MSG_STORED) server_error();
    }

    // 140: Pull pending messages and print in required format
    void on_pull() {
        if (!registered_) { server_error(); return; }

        std::vector<uint8_t> empty;
        auto r = proto_.request(my_id_, CODE_PULL_MSGS, empty);
        if (r.code != RES_WAITING_MSGS) { server_error(); return; }
        if (r.payload.empty()) return;

        size_t i = 0;
        while (i < r.payload.size()) {
            // Message record: from(16) + id(4) + type(1) + size(4) + content
            if (i + 16 + 4 + 1 + 4 > r.payload.size()) { server_error(); break; }

            const uint8_t* from_id_ptr = &r.payload[i]; i += 16;
            std::string from_hex = bytes_to_hex(from_id_ptr, 16);

            uint32_t msg_id = read_le32(&r.payload[i]); (void)msg_id; i += 4;
            uint8_t msg_type = r.payload[i]; i += 1;
            uint32_t sz = read_le32(&r.payload[i]); i += 4;

            if (i + sz > r.payload.size()) { server_error(); break; }

            std::vector<uint8_t> content(r.payload.begin() + i, r.payload.begin() + i + sz);
            i += sz;

            std::string from_name = dir_.name_from_idhex(proto_, my_id_, from_hex);

            std::string content_text;
            if (msg_type == 1) {
                content_text = "Request for symmetric key";
            } else if (msg_type == 2) {
                content_text = "symmetric key received";
                // Decrypt and store AES key
                if (have_priv_) {
                    try {
                        std::vector<uint8_t> plain_key = crypto_.rsa_decrypt(my_priv_, content);
                        if (plain_key.size() == AES_KEY_SIZE) {
                            symkey_cache_[from_hex] = plain_key;
                        }
                    } catch (...) {}
                }
            } else if (msg_type == 3) {
                // Decrypt message if AES key exists, else show required error text
                auto itk = symkey_cache_.find(from_hex);
                if (itk == symkey_cache_.end()) {
                    content_text = "can't decrypt message";
                } else {
                    try {
                        std::vector<uint8_t> plain = crypto_.aes_decrypt_iv0(itk->second, content);
                        content_text.assign(plain.begin(), plain.end());
                    } catch (...) {
                        content_text = "can't decrypt message";
                    }
                }
            } else {
                content_text = "";
            }

            std::cout << "From: " << from_name << "\n";
            std::cout << "Content:\n";
            std::cout << content_text << "\n";
            std::cout << "-----<EOM>-----\n\n";
        }
    }

private:
    ProtocolClient proto_;
    IdentityStore store_;
    CryptoManager crypto_;
    ClientDirectory dir_;

    bool registered_ = false;
    bool have_priv_ = false;
    std::string my_name_;
    uint8_t my_id_[16] = {0};
    CryptoPP::RSA::PrivateKey my_priv_;

    // In-RAM caches only (as required)
    std::unordered_map<std::string, std::vector<uint8_t>> pubkey_cache_;
    std::unordered_map<std::string, std::vector<uint8_t>> symkey_cache_;
};

// =====================
// main
// =====================

// Read server address from server.info: "IP:PORT"
static bool read_server_file(std::string& host, std::string& port) {
    std::ifstream in(SERVER_INFO_FILE);
    if (!in) return false;
    std::string line;
    std::getline(in, line);
    line = trim(line);
    auto pos = line.find(':');
    if (pos == std::string::npos) return false;
    host = trim(line.substr(0, pos));
    port = trim(line.substr(pos + 1));
    return !(host.empty() || port.empty());
}

int main() {
    try {
        std::string host, port;
        if (!read_server_file(host, port)) return 1;

        BoostTransport transport(host, port);
        MessageUClientApp app(transport);

        app.load_identity_if_exists();
        app.run();

        transport.close();
        return 0;
    }
    catch (...) {
        return 1;
    }
}