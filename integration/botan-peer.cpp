// A peer for the interop matrix, written against Botan.
//
//     botan-peer client <host> <port> <ca.pem> [alpn=a,b] [versions=12|13] [cert=PATH key=PATH]
//     botan-peer server <port> <chain.pem> <key.pem> [clientca=PATH] [versions=12|13]
//
// Both sides speak lines: the server answers every line it reads with the same line, and the
// client sends one, reads it back, and prints where the connection landed.
//
// Botan is the second C++ stack in the matrix and the only one here that is not a descendant of
// OpenSSL. Its server has no constructor argument for the ALPN list, so a server case does not
// negotiate one — a limitation of this peer, recorded where the case is declared rather than
// worked around. Its client does offer ALPN, and what comes back is the server's answer.

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/pem.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/x509cert.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

[[noreturn]] void fail(const std::string& message) {
   std::fprintf(stderr, "botan-peer: %s\n", message.c_str());
   std::exit(1);
}

/// Every certificate in a PEM file, not just the first: the matrix hands a peer a bundle of the
/// leaf and its intermediates, and a peer that sent only the leaf would fail every chain check that
/// has an intermediate in it.
std::vector<Botan::X509_Certificate> load_chain(const std::string& path) {
   std::ifstream file(path);
   if(!file) {
      fail("cannot read " + path);
   }
   std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
   static const std::string begin_label = "-----BEGIN CERTIFICATE-----";
   static const std::string end_label = "-----END CERTIFICATE-----";
   std::vector<Botan::X509_Certificate> chain;
   size_t at = 0;
   while(true) {
      const size_t begin = text.find(begin_label, at);
      if(begin == std::string::npos) {
         break;
      }
      const size_t end = text.find(end_label, begin);
      if(end == std::string::npos) {
         break;
      }
      const size_t after = end + end_label.size();
      std::string label;
      const auto der = Botan::PEM_Code::decode(text.substr(begin, after - begin), label);
      chain.emplace_back(der.data(), der.size());
      at = after;
   }
   if(chain.empty()) {
      fail(path + ": no certificate");
   }
   return chain;
}

struct Options {
   std::string sni = "localhost";
   std::vector<std::string> alpn;
   std::string cert;
   std::string key;
   std::string client_ca;
   std::string versions;
   std::vector<uint16_t> groups;
};

/// The code points a TLS 1.3 client may offer. Botan's default list also carries the brainpool
/// code points of RFC 7027, which RFC 8446 retires for 1.3 and this library's server refuses the
/// way tlsfuzzer's `obsolete-curves` expects — so the peer offers the modern set unless it is told
/// otherwise. `groups=` overrides it, which is how the single-group cases are driven.
std::vector<uint16_t> modern_groups() { return {29, 23, 24, 25, 30}; }

uint16_t group_code(const std::string& name) {
   if(name == "X25519") return 29;
   if(name == "X448") return 30;
   if(name == "P-256" || name == "secp256r1") return 23;
   if(name == "P-384" || name == "secp384r1") return 24;
   if(name == "P-521" || name == "secp521r1") return 25;
   if(name == "secp192r1") return 19;
   if(name == "secp224r1") return 21;
   if(name == "ffdhe2048") return 256;
   if(name == "ffdhe3072") return 257;
   fail("unknown group: " + name);
}

Options parse(int argc, char** argv) {
   Options opts;
   for(int i = 0; i < argc; ++i) {
      const std::string_view arg = argv[i];
      const auto split = [&](std::string_view prefix) -> std::optional<std::string> {
         if(arg.rfind(prefix, 0) != 0) {
            return std::nullopt;
         }
         return std::string(arg.substr(prefix.size()));
      };
      if(auto v = split("sni=")) {
         opts.sni = *v;
      } else if(auto v = split("alpn=")) {
         opts.alpn.clear();
         std::string rest = *v;
         size_t at = 0;
         while(at <= rest.size()) {
            const size_t comma = rest.find(',', at);
            const std::string one = rest.substr(at, comma == std::string::npos ? std::string::npos : comma - at);
            if(!one.empty()) {
               opts.alpn.push_back(one);
            }
            if(comma == std::string::npos) {
               break;
            }
            at = comma + 1;
         }
      } else if(auto v = split("cert=")) {
         opts.cert = *v;
      } else if(auto v = split("key=")) {
         opts.key = *v;
      } else if(auto v = split("clientca=")) {
         opts.client_ca = *v;
      } else if(auto v = split("cafile=")) {
         opts.client_ca = *v;
      } else if(auto v = split("groups=")) {
         opts.groups.clear();
         std::string rest = *v;
         size_t at = 0;
         while(at <= rest.size()) {
            const size_t comma = rest.find(',', at);
            opts.groups.push_back(group_code(rest.substr(at, comma == std::string::npos ? std::string::npos : comma - at)));
            if(comma == std::string::npos) {
               break;
            }
            at = comma + 1;
         }
      } else if(auto v = split("versions=")) {
         opts.versions = *v;
      } else if(arg == "resume" || arg == "early") {
         // Botan's in-memory session manager keeps tickets, but a resumption needs the same manager
         // across two connections and a peer that runs once per case. The case lives with the peers
         // whose client can be asked for two connections in one process.
      } else {
         fail("unknown option: " + std::string(arg));
      }
   }
   return opts;
}

int connect_to(const std::string& host, uint16_t port) {
   const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
   if(fd < 0) {
      fail("socket");
   }
   sockaddr_in addr{};
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   if(::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
      fail("address: " + host);
   }
   if(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      fail("connect: " + std::string(std::strerror(errno)));
   }
   timeval tv{};
   tv.tv_sec = 20;
   ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
   ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
   return fd;
}

void write_all(int fd, const uint8_t* data, size_t size) {
   while(size > 0) {
      const ssize_t sent = ::send(fd, data, size, 0);
      if(sent <= 0) {
         fail("send");
      }
      data += sent;
      size -= static_cast<size_t>(sent);
   }
}

/// What the handshake settled on, recorded where Botan reports it once.
struct Landed {
   std::string version = "-";
   std::string suite = "-";
   bool resumed = false;
};

class Callbacks final : public Botan::TLS::Callbacks {
   public:
      Callbacks(int fd, Landed& landed) : m_fd(fd), m_landed(landed) {}

      void tls_emit_data(std::span<const uint8_t> data) override {
         write_all(m_fd, data.data(), data.size());
      }

      void tls_record_received(uint64_t, std::span<const uint8_t> data) override {
         m_plain.append(reinterpret_cast<const char*>(data.data()), data.size());
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         if(alert.is_fatal()) {
            std::fprintf(stderr, "botan-peer: alert %s\n", alert.type_string().c_str());
         }
      }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         const auto version = session.version();
         m_landed.version = (version.minor_version() == 4) ? "1.3" : "1.2";
         m_landed.suite = session.ciphersuite().to_string();
         m_landed.resumed = session.was_resumption();
      }

      /// Everything the peer has received in the clear and not yet handed out.
      std::string take_line() {
         const size_t at = m_plain.find('\n');
         if(at == std::string::npos) {
            return {};
         }
         std::string line = m_plain.substr(0, at + 1);
         m_plain.erase(0, at + 1);
         return line;
      }

      bool has_line() const { return m_plain.find('\n') != std::string::npos; }

   private:
      int m_fd;
      Landed& m_landed;
      std::string m_plain;
};

class Credentials final : public Botan::Credentials_Manager {
   public:
      Credentials(std::string cert_path, std::string key_path, std::string ca_path) :
            m_cert_path(std::move(cert_path)),
            m_key_path(std::move(key_path)),
            m_store(ca_path.empty() ? nullptr : std::make_unique<Botan::Certificate_Store_In_Memory>(ca_path)) {}

      std::vector<Botan::X509_Certificate> find_cert_chain(
         const std::vector<std::string>&,
         const std::vector<Botan::AlgorithmIdentifier>&,
         const std::vector<Botan::X509_DN>&,
         const std::string& type,
         const std::string&) override {
         if(m_cert_path.empty()) {
            return {};
         }
         // Either role: a client that was given a certificate offers it when the server asks, and a
         // peer that was not given one says so by returning nothing.
         (void)type;
         return load_chain(m_cert_path);
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate&,
                                                          const std::string& type,
                                                          const std::string&) override {
         if(m_key_path.empty()) {
            return nullptr;
         }
         (void)type;
         Botan::DataSource_Stream source(m_key_path);
         return Botan::PKCS8::load_key(source);
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string&,
                                                                             const std::string&) override {
         if(!m_store) {
            return {};
         }
         return {m_store.get()};
      }

   private:
      std::string m_cert_path;
      std::string m_key_path;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> m_store;
};

class Policy final : public Botan::TLS::Policy {
   public:
      Policy(bool allow12, bool allow13, bool require_client_cert,
             std::vector<uint16_t> groups = {}) :
            m_allow12(allow12),
            m_allow13(allow13),
            m_require_client_cert(require_client_cert),
            m_groups(std::move(groups)) {}

      std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
         if(m_groups.empty()) {
            return Botan::TLS::Policy::key_exchange_groups();
         }
         std::vector<Botan::TLS::Group_Params> out;
         for(const auto code : m_groups) {
            out.push_back(static_cast<Botan::TLS::Group_Params>(code));
         }
         return out;
      }

      bool allow_tls12() const override { return m_allow12; }

      bool allow_tls13() const override { return m_allow13; }

      bool require_client_certificate_authentication() const override { return m_require_client_cert; }

      // The test PKI issues no OCSP responses and publishes no CRLs, and Botan's default asks for
      // one; a peer that refused every certificate in the matrix would measure nothing.
      bool require_cert_revocation_info() const override { return false; }

   private:
      bool m_allow12;
      bool m_allow13;
      bool m_require_client_cert;
      std::vector<uint16_t> m_groups;
};

Policy policy_for(const Options& opts, bool require_client_cert,
                  std::vector<uint16_t> groups = {}) {
   const bool allow12 = opts.versions.empty() || opts.versions.find("12") != std::string::npos;
   const bool allow13 = opts.versions.empty() || opts.versions.find("13") != std::string::npos;
   return Policy(allow12, allow13, require_client_cert, std::move(groups));
}

void client(int argc, char** argv) {
   if(argc < 3) {
      fail("client <host> <port> <ca.pem> [options]");
   }
   const std::string host = argv[0];
   const auto port = static_cast<uint16_t>(std::stoi(argv[1]));
   const std::string ca = argv[2];
   const Options opts = parse(argc - 3, argv + 3);

   const int fd = connect_to(host, port);
   Landed landed;
   auto callbacks = std::make_shared<Callbacks>(fd, landed);
   auto creds = std::make_shared<Credentials>(opts.cert, opts.key, ca);
   auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
   auto sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
   auto policy = std::make_shared<Policy>(policy_for(
      opts, false, opts.groups.empty() ? modern_groups() : opts.groups));

   auto tls = std::make_unique<Botan::TLS::Client>(callbacks, sessions, creds, policy, rng,
                                                   Botan::TLS::Server_Information(host, port),
                                                   (policy_for(opts, false).allow_tls13()
                                                       ? Botan::TLS::Protocol_Version(Botan::TLS::Protocol_Version::TLS_V13)
                                                       : Botan::TLS::Protocol_Version(Botan::TLS::Protocol_Version::TLS_V12)),
                                                   opts.alpn);

   bool sent = false;
   bool got = false;
   std::string first;
   std::vector<uint8_t> buffer(16384);
   while(!got) {
      const ssize_t n = ::recv(fd, buffer.data(), buffer.size(), 0);
      if(n <= 0) {
         fail("closed before an answer");
      }
      tls->received_data(std::span<const uint8_t>(buffer.data(), static_cast<size_t>(n)));
      if(!sent && tls->is_active()) {
         const uint8_t line[] = {'p', 'i', 'n', 'g', '\n'};
         tls->send(line);
         sent = true;
      }
      if(callbacks->has_line()) {
         first = callbacks->take_line();
         got = true;
      }
   }

   const std::string alpn = tls->application_protocol().empty() ? "-" : tls->application_protocol();
   std::printf("ok version=%s suite=%s alpn=%s sni=%s resumed=%d early=0 bytes=%zu first=%s\n",
               landed.version.c_str(), landed.suite.c_str(), alpn.c_str(), opts.sni.c_str(),
               landed.resumed ? 1 : 0, first.size(),
               first.substr(0, first.find_last_not_of("\r\n") + 1).c_str());
   tls->close();
   std::fflush(stdout);
   std::exit(0);
}

void server(int argc, char** argv) {
   if(argc < 3) {
      fail("server <port> <chain.pem> <key.pem> [options]");
   }
   const auto port = static_cast<uint16_t>(std::stoi(argv[0]));
   const std::string chain = argv[1];
   const std::string key = argv[2];
   const Options opts = parse(argc - 3, argv + 3);

   const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
   if(listener < 0) {
      fail("socket");
   }
   const int one = 1;
   ::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
   sockaddr_in addr{};
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   addr.sin_addr.s_addr = htonl(INADDR_ANY);
   if(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      fail("bind");
   }
   if(::listen(listener, 16) != 0) {
      fail("listen");
   }
   std::fprintf(stderr, "listening on %u\n", port);

   Landed landed;
   auto creds = std::make_shared<Credentials>(chain, key, opts.client_ca);
   auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
   auto sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
   auto policy = std::make_shared<Policy>(policy_for(opts, !opts.client_ca.empty()));

   while(true) {
      const int fd = ::accept(listener, nullptr, nullptr);
      if(fd < 0) {
         continue;
      }
      timeval tv{};
      tv.tv_sec = 20;
      ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

      auto callbacks = std::make_shared<Callbacks>(fd, landed);
      auto tls = std::make_unique<Botan::TLS::Server>(callbacks, sessions, creds, policy, rng);
      std::vector<uint8_t> buffer(16384);
      try {
         while(true) {
            const ssize_t n = ::recv(fd, buffer.data(), buffer.size(), 0);
            if(n <= 0) {
               break;
            }
            tls->received_data(std::span<const uint8_t>(buffer.data(), static_cast<size_t>(n)));
            while(tls->is_active() && callbacks->has_line()) {
               tls->send(std::string_view(callbacks->take_line()));
            }
         }
      } catch(const std::exception& e) {
         std::fprintf(stderr, "connection: %s\n", e.what());
      }
      ::close(fd);
   }
}

}  // namespace

int main(int argc, char** argv) {
   if(argc < 2) {
      fail("client|server");
   }
   try {
      const std::string mode = argv[1];
      if(mode == "client") {
         client(argc - 2, argv + 2);
      } else if(mode == "server") {
         server(argc - 2, argv + 2);
      }
      fail("unknown mode " + mode);
   } catch(const std::exception& e) {
      fail(e.what());
   }
}
