/*
	Author: Lukas (thelstv)
	Copyright: (c) https://lstv.space

	Last modified: 2026
	License: GPL-3.0
	Version: 2.0.0-cpp
	Description: A performance optimized cache for Akeno.
*/

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <akeno/external/ankerl/unordered_dense.h>
#include <filesystem>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <memory>
#include <cerrno>
#include <iostream>

#ifdef __linux__
#include <sys/inotify.h>
#include <unistd.h>
#endif

// #include <mutex> // Future

#include "akeno/MimeType.h"

// Deflate/Gzip compression
#include "libdeflate.h"

// Brotli compression
#ifndef UWS_NO_BROTLI
#include <brotli/encode.h>
#endif

using namespace std::literals;

static constexpr std::string_view doNotCompress[] = {
    "image/",
    "audio/",
    "video/",
    "application/zip",
    "application/octet-stream",
    "application/pdf"
};

namespace Akeno {

enum CompressionVariant : uint8_t {
    NONE = 0,
    GZIP = 1,
    BROTLI = 2,
    DEFLATE = 3
};

const size_t MIN_COMPRESSION_SIZE = 512; // Don't try to compress small files

uint8_t getUsedCompression(std::string_view acceptEncoding, std::string_view mimeType = {}) {
    for (auto prefix : doNotCompress) {
        if (mimeType.starts_with(prefix)) {
            return CompressionVariant::NONE;
        }
    }

	#ifndef UWS_NO_BROTLI
	if (acceptEncoding.find("br") != std::string_view::npos) {
        return CompressionVariant::BROTLI;
	} else
	#endif
	if (acceptEncoding.find("gzip") != std::string_view::npos) {
        return CompressionVariant::GZIP;
    } else if (acceptEncoding.find("deflate") != std::string_view::npos) {
        return CompressionVariant::DEFLATE;
    }

	return CompressionVariant::NONE;
}

class FileCache {
public:
	struct PathInfo {
		std::string path;
		std::filesystem::file_time_type mtime;
	};

	struct SharedMeta {
		bool watchDirty = false;
		std::vector<PathInfo> paths;
		std::filesystem::file_time_type lastModified{};
		std::chrono::steady_clock::time_point lastChecked{};
		size_t templateChunkSplit = 0;
		std::string templatePath;
		std::vector<int> watchDescriptors;
		ankerl::unordered_dense::map<std::string, std::string> headers;
		std::filesystem::file_time_type templateMtime{};

		SharedMeta() {
			headers.reserve(8);
		}

		void setHeader(std::string name, std::string value) {
			headers[std::move(name)] = std::move(value);
		}

		void reserveHeaders(size_t count) {
			headers.reserve(count);
		}

		bool hasHeader(const std::string &name) const {
			return headers.find(name) != headers.end();
		}

		bool hasHeader(std::string_view name) const {
			return headers.find(std::string(name)) != headers.end();
		}

		bool hasHeader(const char *name) const {
			return hasHeader(std::string_view{name});
		}

		std::string_view getHeader(std::string_view name) const {
			auto it = headers.find(std::string(name));
			if (it == headers.end()) {
				return {};
			}
			return it->second;
		}

		void removeHeader(const std::string &name) {
			auto it = headers.find(name);
			if (it != headers.end()) {
				headers.erase(it);
			}
		}

		void removeHeader(std::string_view name) {
			auto it = headers.find(std::string(name));
			if (it != headers.end()) {
				headers.erase(it);
			}
		}
	};

	struct CacheEntry {
		std::string buffer;
		uint8_t variant = 0;
        bool enableCompression = true;
		std::string extension;
		std::string mimeType;
		std::chrono::steady_clock::time_point lastAccessed{};
		ankerl::unordered_dense::map<std::string, std::string> headers;
		std::shared_ptr<SharedMeta> shared;

		CacheEntry() {
			headers.reserve(8);
		}

		void setHeader(std::string name, std::string value) {
			headers[std::move(name)] = std::move(value);
		}

		void reserveHeaders(size_t count) {
			headers.reserve(count);
		}

		bool hasHeader(const std::string &name) const {
			return headers.find(name) != headers.end();
		}

		bool hasHeader(std::string_view name) const {
			return headers.find(std::string(name)) != headers.end();
		}

		bool hasHeader(const char *name) const {
			return hasHeader(std::string_view{name});
		}

		std::string_view getHeader(const std::string &name) const {
			auto it = headers.find(name);
			if (it == headers.end()) {
				return {};
			}
			return it->second;
		}

		std::string_view getHeader(std::string_view name) const {
			auto it = headers.find(std::string(name));
			if (it == headers.end()) {
				return {};
			}
			return it->second;
		}

		void removeHeader(const std::string &name) {
			auto it = headers.find(name);
			if (it != headers.end()) {
				headers.erase(it);
			}
		}

		void removeHeader(std::string_view name) {
			auto it = headers.find(std::string(name));
			if (it != headers.end()) {
				headers.erase(it);
			}
		}

		const std::vector<PathInfo> &getPaths() const {
			static const std::vector<PathInfo> empty;
			return shared ? shared->paths : empty;
		}

		std::filesystem::file_time_type getLastModified() const {
			return shared ? shared->lastModified : std::filesystem::file_time_type{};
		}

		std::chrono::steady_clock::time_point getLastChecked() const {
			return shared ? shared->lastChecked : std::chrono::steady_clock::time_point{};
		}

		std::string precomputedHeaders;

		void precomputeHeaders() {
			precomputedHeaders.clear();

			// Reserve a reasonable amount of space to avoid reallocations
			precomputedHeaders.reserve(512);

            // TODO: Move this to a better place
			precomputedHeaders.append(
				"Access-Control-Allow-Origin: *\r\n"
				"Access-Control-Allow-Headers: Authorization,*\r\n"
				"Access-Control-Allow-Methods: GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS\r\n"
				"X-Content-Type-Options: nosniff\r\n"
				"Connection: keep-alive\r\n"
				"Content-Length: "
			);

			precomputedHeaders.append(std::to_string(buffer.size()));
			precomputedHeaders.append("\r\n");

            precomputedHeaders.append("Content-Type: ").append(mimeType);
            if(isTextMimeType(mimeType)) {
                precomputedHeaders.append("; charset=utf-8");
            }
            precomputedHeaders.append("\r\n");

			for (const auto &[key, value] : headers) {
				if (key == "Content-Length") continue;
				precomputedHeaders.append(key).append(": ").append(value).append("\r\n");
			}

			if (shared) {
				for (const auto &[key, value] : shared->headers) {
					if (key == "Content-Length") continue;
					if (headers.find(key) != headers.end()) continue; // Local header takes precedence

					precomputedHeaders.append(key).append(": ").append(value).append("\r\n");
				}
			}

			bool hasCacheControl = (headers.find("Cache-Control") != headers.end());
			if (!hasCacheControl && shared && (shared->headers.find("Cache-Control") != shared->headers.end())) {
				hasCacheControl = true;
			}

			if (!hasCacheControl) {
				if (mimeType == "text/html") {
                    // Don't cache dynamic content
                    // There is a 2s window (may not be what you want)
					precomputedHeaders.append("Cache-Control: max-age=2, must-revalidate\r\n");
				} else {
					// Static assets can be cached for a long time
					precomputedHeaders.append("Cache-Control: public, max-age=31536000, immutable\r\n");
				}
			}
		}
	};

	struct KeyEntry {
		ankerl::unordered_dense::map<uint8_t, CacheEntry> variants;
		std::shared_ptr<SharedMeta> shared = std::make_shared<SharedMeta>();

		KeyEntry() {
			variants.reserve(4);
		}
	};

	explicit FileCache(std::chrono::milliseconds checkInterval = std::chrono::milliseconds(1000))
		: checkInterval(checkInterval) {
#ifdef __linux__
		inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
		if (inotifyFd >= 0) {
			watchSlots.reserve(64);
			pathToWatch.reserve(64);
		}
#endif
	}

	~FileCache() {
#ifdef __linux__
		for (auto &item : entries) {
			if (item.second.shared) {
				detachWatchers(*item.second.shared);
			}
		}
		if (inotifyFd >= 0) {
			close(inotifyFd);
			inotifyFd = -1;
		}
#endif
	}

	void reserve(size_t count) {
		entries.reserve(count);
	}

	void setCheckInterval(std::chrono::milliseconds interval) {
		checkInterval = interval;
	}

	void set(std::string_view key, std::string buffer, uint8_t variant = 0) {
		setInternal(key, std::move(buffer), variant, nullptr);
	}

	void set(std::string_view key, std::string buffer, uint8_t variant, const std::vector<std::string> &paths) {
		setInternal(key, std::move(buffer), variant, &paths);
	}

	CacheEntry* update(std::string_view key, std::string buffer, std::string_view mimeType = {}) {
		std::string keyStr(key);
		auto it = entries.find(keyStr);
		if (it == entries.end()) {
			auto [newIt, inserted] = entries.emplace(std::move(keyStr), KeyEntry{});
			(void) inserted;
			it = newIt;

			CacheEntry &base = it->second.variants[0];
			base.buffer = std::move(buffer);
			base.variant = 0;
			base.extension = extractExtension(key);
            base.mimeType = mimeType.empty() ? getMimeTypeFromExt(base.extension) : std::string(mimeType);
			base.lastAccessed = std::chrono::steady_clock::now();
			base.shared = it->second.shared;
			base.enableCompression = base.buffer.size() >= MIN_COMPRESSION_SIZE;

			it->second.shared->lastModified = std::filesystem::file_time_type::clock::now();
			auto ms = it->second.shared->lastModified.time_since_epoch().count();
			it->second.shared->setHeader("ETag", std::to_string(ms) + std::string(variantToString(base.variant)));

			base.precomputeHeaders();

			return &base;
		}

		KeyEntry &entry = it->second;
		for (auto vIt = entry.variants.begin(); vIt != entry.variants.end();) {
			if (vIt->first != 0) {
				vIt = entry.variants.erase(vIt);
			} else {
				++vIt;
			}
		}

		CacheEntry &base = entry.variants[0];
		base.buffer = std::move(buffer);
		base.variant = 0;
		base.extension = extractExtension(key);
		base.lastAccessed = std::chrono::steady_clock::now();
		base.shared = entry.shared;

        // NOTE: We currently share one ETag for every variant
        // It should be fine but is probably not ideal
        entry.shared->lastModified = std::filesystem::file_time_type::clock::now();
        auto ms = entry.shared->lastModified.time_since_epoch().count();
        entry.shared->setHeader("ETag", std::to_string(ms) + std::string(variantToString(base.variant)));

        base.precomputeHeaders();
        return &base;
	}

	CacheEntry* update(std::string_view key, std::string buffer, const std::vector<std::string> &paths, std::string_view mimeType = {}) {
		CacheEntry *entry = update(key, std::move(buffer), mimeType);
		if (!entry || !entry->shared) {
			return entry;
		}

		assignPaths(*entry->shared, paths);
		if (entry->shared->lastModified.time_since_epoch().count() == 0) {
			entry->shared->lastModified = std::filesystem::file_time_type::clock::now();
		}

		auto ms = entry->shared->lastModified.time_since_epoch().count();
		entry->shared->setHeader("ETag", std::to_string(ms) + std::string(variantToString(entry->variant)));

		auto keyIt = entries.find(std::string(key));
		if (keyIt != entries.end()) {
			for (auto &[idx, variantEntry] : keyIt->second.variants) {
				variantEntry.precomputeHeaders();
			}
		}

		return entry;
	}

	std::string_view variantToString(uint8_t variant) const {
		switch (variant) {
			case CompressionVariant::GZIP:
				return "-gzip"sv;
			case CompressionVariant::BROTLI:
				return "-br"sv;
			case CompressionVariant::DEFLATE:
				return "-deflate"sv;
			default:
				return ""sv;
		}
	}

	bool hasVariant(std::string_view key, uint8_t variant = 0) const {
		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			return false;
		}
		return it->second.variants.find(variant) != it->second.variants.end();
	}

	bool exists(std::string_view key) const {
		return entries.find(std::string(key)) != entries.end();
	}

	CacheEntry *get(std::string_view key, uint8_t variant = 0) {
		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			return nullptr;
		}
		auto vIt = it->second.variants.find(variant);
		if (vIt == it->second.variants.end()) {
			return nullptr;
		}
		vIt->second.lastAccessed = std::chrono::steady_clock::now();
		return &vIt->second;
	}

	const CacheEntry *get(std::string_view key, uint8_t variant = 0) const {
		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			return nullptr;
		}
		auto vIt = it->second.variants.find(variant);
		if (vIt == it->second.variants.end()) {
			return nullptr;
		}
		return &vIt->second;
	}

    template<bool SSL>
    bool tryServe(CacheEntry *entry, uWS::HttpResponse<SSL> *res, std::string_view status = "200 OK"sv) {
        if (!entry || entry->buffer.empty()) {
            return false;
        }

        bool headersNeedUpdate = false;
        // if(entry->shared->lastModified.time_since_epoch().count() == 0) {
        //     // The entry was created without setting the last modified time, so we set it now
        //     entry->shared->lastModified = std::filesystem::file_time_type::clock::now();
        //     auto ms = entry->shared->lastModified.time_since_epoch().count();
        //     entry->shared->setHeader("ETag", std::to_string(ms) + std::string(variantToString(entry->variant)));
        //     headersNeedUpdate = true;
        // }

        if (entry->precomputedHeaders.empty() || headersNeedUpdate) {
            entry->precomputeHeaders();
        }

		// The cork makes it 5x slower...
		// res->cork([res, &status, &entry]() {
			res->writeStatus(status);

			// Note: for http3, we'll have to do something else for headers
			res->writeRaw(entry->precomputedHeaders);

			// Serve the file content (we already set the Content-Length header)
			res->endWithoutContentLength(std::string_view(entry->buffer.data(), entry->buffer.size()));
		// });

		return true;
    }

	template<bool SSL>
	bool tryServe(std::string_view key, uint8_t variant, uWS::HttpResponse<SSL> *res, std::string_view status = "200 OK") {
        CacheEntry *entry = get(key, variant);
        return tryServe(entry, res, status);
    }

	template<bool SSL>
	bool tryServeWithCompression(std::string_view key, std::string_view acceptEncoding, std::string_view mimeType, uWS::HttpResponse<SSL> *res, std::string_view status = "200 OK") {
        uint8_t variant = getUsedCompression(acceptEncoding, mimeType);
        return tryServeWithCompression(key, variant, res, status);
    }

	template<bool SSL>
	bool tryServeWithCompression(std::string_view key, uint8_t variant, uWS::HttpResponse<SSL> *res, std::string_view status = "200 OK") {
        // Send default if no compression
        if(variant == CompressionVariant::NONE) {
            return tryServe(key, 0, res, status);
        }

        if(!hasVariant(key, variant)) {
            // Try compressing
            // Otherwise fallback to uncompressed
            // Compression is further decided based on file size, so compress() may still return the uncompressed version
            // Headers are handled properly later in any case
            auto *compressed = compress(key, variant);
            if(compressed && !compressed->buffer.empty()) {
                return tryServe(compressed, res, status);
            }

            std::cerr << "Warning: Failed to compress file \"" << key << "\" with variant " << variant << ", serving uncompressed version instead." << std::endl;

            // Fallback to uncompressed
            return tryServe(key, 0, res, status);
        }

        // Send cached compressed version
        return tryServe(key, variant, res, status);
    }

	CacheEntry *compress(std::string_view key, uint8_t variant) {
		if (variant == CompressionVariant::NONE) {
			return nullptr;
		}

		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			return nullptr;
		}

		KeyEntry &entry = it->second;
		
		// Get the base (uncompressed) variant
		auto baseIt = entry.variants.find(0);
		if (baseIt == entry.variants.end()) {
			return nullptr;
		}

        // Compression not enabled for this entry, returns uncompressed version and doesn't cache the compressed variant
        if (!baseIt->second.enableCompression) {
            return &baseIt->second;
        }

		const CacheEntry &base = baseIt->second;
		std::string compressed;

		// Perform compression based on variant
		if (variant == CompressionVariant::GZIP) {
			struct libdeflate_compressor *compressor = libdeflate_alloc_compressor(6);
			if (!compressor) {
				return nullptr;
			}

			size_t bound = libdeflate_gzip_compress_bound(compressor, base.buffer.size());
			compressed.resize(bound);
			
			size_t actualSize = libdeflate_gzip_compress(
				compressor,
				base.buffer.data(),
				base.buffer.size(),
				compressed.data(),
				compressed.size()
			);

			libdeflate_free_compressor(compressor);

			if (actualSize == 0) {
				return nullptr;
			}
			compressed.resize(actualSize);

		} else if (variant == CompressionVariant::BROTLI) {
			#ifdef UWS_NO_BROTLI
			return nullptr;
			#else
			size_t bound = BrotliEncoderMaxCompressedSize(base.buffer.size());
			if (bound == 0) {
				return nullptr;
			}

			compressed.resize(bound);
			size_t actualSize = bound;

			if (BrotliEncoderCompress(
				BROTLI_DEFAULT_QUALITY,
				BROTLI_DEFAULT_WINDOW,
				BROTLI_DEFAULT_MODE,
				base.buffer.size(),
				reinterpret_cast<const uint8_t*>(base.buffer.data()),
				&actualSize,
				reinterpret_cast<uint8_t*>(compressed.data())
			) != BROTLI_TRUE) {
				return nullptr;
			}
			compressed.resize(actualSize);
			#endif

		} else if (variant == CompressionVariant::DEFLATE) {
			struct libdeflate_compressor *compressor = libdeflate_alloc_compressor(6);
			if (!compressor) {
				return nullptr;
			}

			size_t bound = libdeflate_deflate_compress_bound(compressor, base.buffer.size());
			compressed.resize(bound);
			
			size_t actualSize = libdeflate_deflate_compress(
				compressor,
				base.buffer.data(),
				base.buffer.size(),
				compressed.data(),
				compressed.size()
			);

			libdeflate_free_compressor(compressor);

			if (actualSize == 0) {
				return nullptr;
			}
			compressed.resize(actualSize);

		} else {
			return nullptr;
		}

		// Create the compressed variant
		CacheEntry &compressedEntry = entry.variants[variant];
		compressedEntry.buffer = std::move(compressed);
		compressedEntry.variant = variant;
		compressedEntry.extension = base.extension;
		compressedEntry.mimeType = base.mimeType;
		compressedEntry.lastAccessed = std::chrono::steady_clock::now();
		compressedEntry.headers = base.headers;
		compressedEntry.shared = entry.shared;

		// Set the appropriate Content-Encoding header
		if (variant == CompressionVariant::GZIP) {
			compressedEntry.setHeader("Content-Encoding", "gzip");
		} else if (variant == CompressionVariant::BROTLI) {
			compressedEntry.setHeader("Content-Encoding", "br");
		} else if (variant == CompressionVariant::DEFLATE) {
			compressedEntry.setHeader("Content-Encoding", "deflate");
		}

		if (compressedEntry.hasHeader(std::string("Content-Length"))) {
			compressedEntry.setHeader("Content-Length", std::to_string(compressedEntry.buffer.size()));
		}

		compressedEntry.precomputeHeaders();

		return &compressedEntry;
	}

	void remove(std::string_view key) {
		auto it = entries.find(std::string(key));
		if (it != entries.end()) {
			if (it->second.shared) {
				detachWatchers(*it->second.shared);
			}
			entries.erase(it);
		}
	}

	void remove(std::string_view key, uint8_t variant) {
		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			return;
		}
		it->second.variants.erase(variant);
		if (it->second.variants.empty()) {
			if (it->second.shared) {
				detachWatchers(*it->second.shared);
			}
			entries.erase(it);
		}
	}

	void resetVariants(std::string_view key) {
		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			return;
		}
		for (auto vIt = it->second.variants.begin(); vIt != it->second.variants.end();) {
			if (vIt->first != 0) {
				vIt = it->second.variants.erase(vIt);
			} else {
				++vIt;
			}
		}
	}

	bool hasChanged(std::string_view key, bool force = false) {
		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			return true;
		}

		KeyEntry &entry = it->second;
		if (!entry.shared) {
			return true;
		}

#ifdef __linux__
		if (inotifyFd >= 0 && !entry.shared->watchDescriptors.empty()) {
			pollWatchEvents();
			if (!force && !entry.shared->watchDirty) {
				return false;
			}
		}
#endif

		auto now = std::chrono::steady_clock::now();
		if (!force && entry.shared->lastChecked.time_since_epoch().count() != 0) {
			if (now - entry.shared->lastChecked < checkInterval) {
				return false;
			}
		}

		bool changed = false;
		std::vector<PathInfo> updatedPaths;
		updatedPaths.reserve(entry.shared->paths.size());

		for (const auto &info : entry.shared->paths) {
			if (!std::filesystem::exists(info.path)) {
				changed = true;
				continue;
			}

			auto current = std::filesystem::last_write_time(info.path);
			if (current != info.mtime) {
				changed = true;
			}
			updatedPaths.push_back({info.path, current});
		}

		bool templateExists = false;
		std::filesystem::file_time_type currentTemplateMtime{};
		if (!entry.shared->templatePath.empty()) {
			if (std::filesystem::exists(entry.shared->templatePath)) {
				templateExists = true;
				currentTemplateMtime = std::filesystem::last_write_time(entry.shared->templatePath);
				if (currentTemplateMtime != entry.shared->templateMtime) {
					changed = true;
				}
			} else {
				changed = true;
			}
		}

		if (changed) {
			entry.shared->paths = std::move(updatedPaths);
			entry.shared->lastModified = computeLastModified(entry.shared->paths);
			if (templateExists && currentTemplateMtime > entry.shared->lastModified) {
				entry.shared->lastModified = currentTemplateMtime;
			}
#ifdef __linux__
			if (inotifyFd >= 0) {
				detachWatchers(*entry.shared);
				attachWatchers(*entry.shared, entry.shared->paths);
			}
#endif
		}

		if (!entry.shared->templatePath.empty()) {
			entry.shared->templateMtime = templateExists ? currentTemplateMtime : std::filesystem::file_time_type{};
		}

		entry.shared->lastChecked = now;
		entry.shared->watchDirty = false;
		return changed;
	}

	void cleanScope(std::string_view pathPrefix) {
		for (auto it = entries.begin(); it != entries.end();) {
			if (startsWith(it->first, pathPrefix)) {
				if (it->second.shared) {
					detachWatchers(*it->second.shared);
				}
				it = entries.erase(it);
			} else {
				++it;
			}
		}
	}

	void assignPaths(SharedMeta &shared, const std::vector<std::string> &paths) {
		detachWatchers(shared);
		shared.paths.clear();
		shared.paths.reserve(paths.size());

		for (const auto &path : paths) {
			if (!std::filesystem::exists(path)) {
				continue;
			}
			shared.paths.push_back({path, std::filesystem::last_write_time(path)});
		}

		shared.lastModified = computeLastModified(shared.paths);
		if (!shared.templatePath.empty() && std::filesystem::exists(shared.templatePath)) {
			shared.templateMtime = std::filesystem::last_write_time(shared.templatePath);
			if (shared.templateMtime > shared.lastModified) {
				shared.lastModified = shared.templateMtime;
			}
		}
		attachWatchers(shared, shared.paths);
	}

private:
    ankerl::unordered_dense::map<std::string, KeyEntry> entries;
	std::chrono::milliseconds checkInterval;

	static bool startsWith(const std::string &value, std::string_view prefix) {
		if (prefix.size() > value.size()) {
			return false;
		}
		return std::equal(prefix.begin(), prefix.end(), value.begin());
	}

	static std::string extractExtension(std::string_view key) {
		size_t lastSlash = key.find_last_of('/');
		size_t lastDot = key.find_last_of('.');
		if (lastDot == std::string_view::npos) {
			return {};
		}
		if (lastSlash != std::string_view::npos && lastDot < lastSlash) {
			return {};
		}
		return std::string(key.substr(lastDot + 1));
	}

	static std::filesystem::file_time_type computeLastModified(const std::vector<PathInfo> &paths) {
		if (paths.empty()) {
			return std::filesystem::file_time_type{};
		}
		auto latest = paths.front().mtime;
		for (const auto &path : paths) {
			if (path.mtime > latest) {
				latest = path.mtime;
			}
		}
		return latest;
	}

    /**
     * Merges the given paths into the shared metadata, updating the last modified time accordingly.
     * This is used when updating the cache entry with new content that may be associated with different file paths.
     */
	void mergePaths(SharedMeta &shared, const std::vector<std::string> &paths) {
		ankerl::unordered_dense::map<std::string, std::filesystem::file_time_type> merged;
		merged.reserve(shared.paths.size() + paths.size());

		for (const auto &info : shared.paths) {
			if (!std::filesystem::exists(info.path)) {
				continue;
			}
			merged[info.path] = std::filesystem::last_write_time(info.path);
		}

		for (const auto &path : paths) {
			if (!std::filesystem::exists(path)) {
				continue;
			}
			merged[path] = std::filesystem::last_write_time(path);
		}

		shared.paths.clear();
		shared.paths.reserve(merged.size());
		for (const auto &item : merged) {
			shared.paths.push_back({item.first, item.second});
		}

		shared.lastModified = computeLastModified(shared.paths);
		if (!shared.templatePath.empty() && std::filesystem::exists(shared.templatePath)) {
			shared.templateMtime = std::filesystem::last_write_time(shared.templatePath);
			if (shared.templateMtime > shared.lastModified) {
				shared.lastModified = shared.templateMtime;
			}
		}
		detachWatchers(shared);
		attachWatchers(shared, shared.paths);
	}

	void setInternal(std::string_view key, std::string buffer, uint8_t variant, const std::vector<std::string> *paths) {
		auto it = entries.find(std::string(key));
		if (it == entries.end()) {
			auto inserted = entries.emplace(std::string(key), KeyEntry{});
			it = inserted.first;
		}
		KeyEntry &entry = it->second;

		if (!entry.shared) {
			entry.shared = std::make_shared<SharedMeta>();
		}

		if (paths) {
			mergePaths(*entry.shared, *paths);
		}

		CacheEntry &cacheEntry = entry.variants[variant];
		cacheEntry.buffer = std::move(buffer);
		cacheEntry.variant = variant;
		cacheEntry.extension = extractExtension(key);
		cacheEntry.lastAccessed = std::chrono::steady_clock::now();
		cacheEntry.shared = entry.shared;
        cacheEntry.enableCompression = buffer.size() >= MIN_COMPRESSION_SIZE;

        entry.shared->lastModified = computeLastModified(entry.shared->paths);
        
        if (entry.shared->lastModified.time_since_epoch().count() == 0) {
            entry.shared->lastModified = std::filesystem::file_time_type::clock::now();
        }

        auto ms = entry.shared->lastModified.time_since_epoch().count();
        entry.shared->setHeader("ETag", std::to_string(ms) + std::string(variantToString(variant)));

        // Update all variants precomputed headers
        for(auto &[idx, variantEntry] : entry.variants) {
             variantEntry.precomputeHeaders();
        }
	}

#ifdef __linux__
	struct WatchSlot {
		int wd = -1;
		std::string path;
		std::vector<SharedMeta *> subscribers;
	};

	int inotifyFd = -1;
	ankerl::unordered_dense::map<int, WatchSlot> watchSlots;
	ankerl::unordered_dense::map<std::string, int> pathToWatch;

	void pollWatchEvents() {
		if (inotifyFd < 0 || watchSlots.empty()) {
			return;
		}
		alignas(inotify_event) char buffer[4096];
		for (;;) {
			ssize_t bytes = read(inotifyFd, buffer, sizeof(buffer));
			if (bytes <= 0) {
				if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
					break;
				}
				break;
			}
			size_t offset = 0;
			while (offset < static_cast<size_t>(bytes)) {
				auto *event = reinterpret_cast<inotify_event *>(buffer + offset);
				offset += sizeof(inotify_event) + event->len;

				auto slotIt = watchSlots.find(event->wd);
				if (slotIt == watchSlots.end()) {
					continue;
				}
				if (event->mask & IN_IGNORED) {
					for (auto *shared : slotIt->second.subscribers) {
						if (shared) {
							shared->watchDirty = true;
						}
					}
					pathToWatch.erase(slotIt->second.path);
					watchSlots.erase(event->wd);
					continue;
				}

				for (auto *shared : slotIt->second.subscribers) {
					if (shared) {
						shared->watchDirty = true;
					}
				}
			}
		}
	}

	void addSubscriber(WatchSlot &slot, SharedMeta *shared) {
		if (!shared) {
			return;
		}
		auto it = std::find(slot.subscribers.begin(), slot.subscribers.end(), shared);
		if (it == slot.subscribers.end()) {
			slot.subscribers.push_back(shared);
		}
	}

	void detachWatchers(SharedMeta &shared) {
		if (inotifyFd < 0 || shared.watchDescriptors.empty()) {
			shared.watchDescriptors.clear();
			shared.watchDirty = false;
			return;
		}
		for (int wd : shared.watchDescriptors) {
			auto slotIt = watchSlots.find(wd);
			if (slotIt == watchSlots.end()) {
				continue;
			}
			auto &subs = slotIt->second.subscribers;
			subs.erase(std::remove(subs.begin(), subs.end(), &shared), subs.end());
			if (subs.empty()) {
				inotify_rm_watch(inotifyFd, wd);
				pathToWatch.erase(slotIt->second.path);
				watchSlots.erase(wd);
			}
		}
		shared.watchDescriptors.clear();
		shared.watchDirty = false;
	}

	void attachWatchers(SharedMeta &shared, const std::vector<PathInfo> &paths) {
		if (inotifyFd < 0 || paths.empty()) {
			shared.watchDescriptors.clear();
			shared.watchDirty = false;
			return;
		}

		shared.watchDescriptors.clear();
		shared.watchDescriptors.reserve(paths.size());
		ankerl::unordered_dense::map<int, bool> added;
		added.reserve(paths.size());
		constexpr uint32_t watchMask = IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO;

		for (const auto &info : paths) {
			int wd = -1;
			auto pathIt = pathToWatch.find(info.path);
			if (pathIt != pathToWatch.end()) {
				wd = pathIt->second;
			} else {
				wd = inotify_add_watch(inotifyFd, info.path.c_str(), watchMask);
				if (wd < 0) {
					continue;
				}
				WatchSlot slot;
				slot.wd = wd;
				slot.path = info.path;
				watchSlots.emplace(wd, std::move(slot));
				pathToWatch.emplace(info.path, wd);
			}

			auto slotIt = watchSlots.find(wd);
			if (slotIt == watchSlots.end()) {
				continue;
			}
			addSubscriber(slotIt->second, &shared);
			if (added.emplace(wd, true).second) {
				shared.watchDescriptors.push_back(wd);
			}
		}
		shared.watchDirty = false;
	}
#else
	void detachWatchers(SharedMeta &) {}
	void attachWatchers(SharedMeta &, const std::vector<PathInfo> &) {}
#endif
};

} // namespace Akeno