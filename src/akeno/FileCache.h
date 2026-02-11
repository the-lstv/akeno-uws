/*
	Author: Lukas (thelstv)
	Copyright: (c) https://lstv.space

	Last modified: 2026
	License: GPL-3.0
	Version: 2.0.0-cpp
	Description: A performance optimized web application framework for Akeno.
*/

#ifndef AKENO_FILE_CACHE_H
#define AKENO_FILE_CACHE_H

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <memory>

namespace Akeno {

class FileCache {
public:
	struct PathInfo {
		std::string path;
		std::filesystem::file_time_type mtime;
	};

	struct TransparentHash {
		using is_transparent = void;
		size_t operator()(std::string_view value) const noexcept {
			return std::hash<std::string_view>{}(value);
		}
		size_t operator()(const std::string &value) const noexcept {
			return std::hash<std::string_view>{}(value);
		}
	};

	struct TransparentEq {
		using is_transparent = void;
		bool operator()(std::string_view a, std::string_view b) const noexcept {
			return a == b;
		}
		bool operator()(const std::string &a, std::string_view b) const noexcept {
			return a == b;
		}
		bool operator()(std::string_view a, const std::string &b) const noexcept {
			return a == b;
		}
	};

	struct SharedMeta {
		std::vector<PathInfo> paths;
		std::filesystem::file_time_type lastModified{};
		std::chrono::steady_clock::time_point lastChecked{};
	};

	struct CacheEntry {
		std::string buffer;
		uint8_t variant = 0;
		std::string extension;
		std::string mimeType;
		std::chrono::steady_clock::time_point lastAccessed{};
		std::unordered_map<std::string, std::string, TransparentHash, TransparentEq> headers;
		std::shared_ptr<SharedMeta> shared;

		void setHeader(std::string name, std::string value) {
			headers[std::move(name)] = std::move(value);
		}

		void reserveHeaders(size_t count) {
			headers.reserve(count);
		}

		bool hasHeader(std::string_view name) const {
			return headers.find(name) != headers.end();
		}

		std::string_view getHeader(std::string_view name) const {
			auto it = headers.find(name);
			if (it == headers.end()) {
				return {};
			}
			return it->second;
		}

		void removeHeader(std::string_view name) {
			auto it = headers.find(name);
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
	};

	struct KeyEntry {
		std::unordered_map<uint8_t, CacheEntry> variants;
		std::shared_ptr<SharedMeta> shared = std::make_shared<SharedMeta>();
	};

	explicit FileCache(std::chrono::milliseconds checkInterval = std::chrono::milliseconds(1000))
		: checkInterval(checkInterval) {}

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

	void update(std::string_view key, std::string buffer) {
		auto it = entries.find(key);
		if (it == entries.end()) {
			set(key, std::move(buffer), 0);
			return;
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
	}

	bool hasVariant(std::string_view key, uint8_t variant) const {
		auto it = entries.find(key);
		if (it == entries.end()) {
			return false;
		}
		return it->second.variants.find(variant) != it->second.variants.end();
	}

	CacheEntry *get(std::string_view key, uint8_t variant = 0) {
		auto it = entries.find(key);
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
		auto it = entries.find(key);
		if (it == entries.end()) {
			return nullptr;
		}
		auto vIt = it->second.variants.find(variant);
		if (vIt == it->second.variants.end()) {
			return nullptr;
		}
		return &vIt->second;
	}

	void remove(std::string_view key) {
		auto it = entries.find(key);
		if (it != entries.end()) {
			entries.erase(it);
		}
	}

	void remove(std::string_view key, uint8_t variant) {
		auto it = entries.find(key);
		if (it == entries.end()) {
			return;
		}
		it->second.variants.erase(variant);
		if (it->second.variants.empty()) {
			entries.erase(it);
		}
	}

	void resetVariants(std::string_view key) {
		auto it = entries.find(key);
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
		auto it = entries.find(key);
		if (it == entries.end()) {
			return true;
		}

		KeyEntry &entry = it->second;
		if (!entry.shared) {
			return true;
		}

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

		if (changed) {
			entry.shared->paths = std::move(updatedPaths);
			entry.shared->lastModified = computeLastModified(entry.shared->paths);
		}

		entry.shared->lastChecked = now;
		return changed;
	}

	void cleanScope(std::string_view pathPrefix) {
		for (auto it = entries.begin(); it != entries.end();) {
			if (startsWith(it->first, pathPrefix)) {
				it = entries.erase(it);
			} else {
				++it;
			}
		}
	}

private:
	std::unordered_map<std::string, KeyEntry, TransparentHash, TransparentEq> entries;
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

	void mergePaths(SharedMeta &shared, const std::vector<std::string> &paths) {
		std::unordered_map<std::string, std::filesystem::file_time_type, TransparentHash, TransparentEq> merged;
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
	}

	void setInternal(std::string_view key, std::string buffer, uint8_t variant, const std::vector<std::string> *paths) {
		auto it = entries.find(key);
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
	}
};

} // namespace Akeno

#endif // AKENO_FILE_CACHE_H
