
#ifndef AKENO_RATE_LIMITER_H
#define AKENO_RATE_LIMITER_H

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <unordered_map>

namespace uWS {
	template <bool> struct HttpResponse;
	struct HttpRequest;
}

namespace Akeno {
	class RateLimiter {
	public:
		RateLimiter(uint32_t limit = 0, uint64_t intervalMs = 0)
			: limit_(limit), intervalMs_(intervalMs) {
			reset();
		}

		void reset() {
			entries_.clear();
		}

		template <bool SSL>
		bool check(uWS::HttpRequest *req, uWS::HttpResponse<SSL> *res) {
			(void)req;
			const IpKey key = getIpKey(res);
			return checkInternal(key);
		}

		template <bool SSL>
		bool pass(uWS::HttpRequest *req, uWS::HttpResponse<SSL> *res) {
			if (check(req, res)) {
				return true;
			}
			if (res) {
				res->writeStatus("429 Too Many Requests");
				res->end();
			}
			return false;
		}

	private:
		struct IpKey {
			std::array<unsigned char, 16> bytes{};
			uint8_t len = 0;
		};

		struct Entry {
			uint64_t windowStartMs = 0;
			uint32_t count = 0;
		};

		struct IpKeyHash {
			size_t operator()(const IpKey &key) const noexcept {
				uint64_t hash = 1469598103934665603ull;
				for (uint8_t i = 0; i < key.len; ++i) {
					hash ^= key.bytes[i];
					hash *= 1099511628211ull;
				}
				return static_cast<size_t>(hash);
			}
		};

		struct IpKeyEq {
			bool operator()(const IpKey &a, const IpKey &b) const noexcept {
				return a.len == b.len && std::memcmp(a.bytes.data(), b.bytes.data(), a.len) == 0;
			}
		};

		uint32_t limit_ = 0;
		uint64_t intervalMs_ = 0;
		std::unordered_map<IpKey, Entry, IpKeyHash, IpKeyEq> entries_;

		static uint64_t nowMs() {
			return static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now().time_since_epoch())
					.count());
		}

		template <bool SSL>
		IpKey getIpKey(uWS::HttpResponse<SSL> *res) {
			IpKey key;
			if (!res) {
				return key;
			}

			std::string_view ip;
#ifdef UWS_WITH_PROXY
			ip = res->getProxiedRemoteAddress();
			if (ip.empty()) {
				ip = res->getRemoteAddress();
			}
#else
			ip = res->getRemoteAddress();
#endif

			if (!ip.empty()) {
				const size_t len = ip.size() > 16 ? 16 : ip.size();
				key.len = static_cast<uint8_t>(len);
				std::memcpy(key.bytes.data(), ip.data(), len);
			}
			return key;
		}

		bool checkInternal(const IpKey &key) {
			if (limit_ == 0) {
				return false;
			}

			const uint64_t now = nowMs();
			Entry &entry = entries_[key];
			if (now - entry.windowStartMs >= intervalMs_) {
				entry.windowStartMs = now;
				entry.count = 1;
				return true;
			}

			if (entry.count < limit_) {
				++entry.count;
				return true;
			}

			return false;
		}
	};
}

#endif // AKENO_RATE_LIMITER_H
