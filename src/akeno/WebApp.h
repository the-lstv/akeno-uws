/*
    Author: Lukas (thelstv)
    Copyright: (c) https://lstv.space

    Last modified: 2026
    License: GPL-3.0
    Version: 2.0.0-cpp
    Description: A performance optimized web application framework for Akeno.
    Rewritten from JavaScript to C++
*/

#pragma once

#include <string>
#include <string_view>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <vector>
#include <functional>
#include <unordered_map>

#include "akeno/App.h"
#include "akeno/FileCache.h"
// #include "akeno/RateLimiter.h"
#include "akeno/MimeType.h"
#include "akeno/Router.h"

#include "akeno/parser/x-parser.h"

using namespace std::literals;

namespace Akeno
{
    struct ResolvePathResult {
        bool useRootPath;
        std::string full;
        std::string relative;
    };

    struct WebAppOptions {
        bool redirectToHttps = true;
        std::tuple<int, int, bool> browserCompatibility = {0, 0, false}; // Chrome version, Firefox version, whether to check compatibility
        // Placeholder for future options
    };

    struct PathAttributes {
        bool deny = false; // If true, this path will be deniedv

        uint8_t transformType = 0; // 0 = none, 1 = alias, 2 = redirect, 3 = reroute
        std::string transformTarget; // Target path for an alias or redirect

        bool operator==(const PathAttributes &other) const {
            return deny == other.deny &&
                   transformType == other.transformType &&
                   transformTarget == other.transformTarget;
        }

        void operator|=(const PathAttributes &other) {
            std::cout << "Before merging: deny=" << deny << ", transformType=" << (int)transformType << ", transformTarget=\"" << transformTarget << "\"" << std::endl;
            deny = deny || other.deny;
            if (other.transformType != 0) {
                transformType = other.transformType;
                transformTarget = other.transformTarget;
            }
            std::cout << "Merged path attributes: deny=" << deny << ", transformType=" << (int)transformType << ", transformTarget=\"" << transformTarget << "\"" << std::endl;
        }
    };

    // struct ErrorPages {
    //     // Could be benchmarked against an unordered_map but for ~two values it's mostly pointless and a vector may be faster
    // };

    class WebApp {
    public:
        bool _rootPathAllowed = true;
        bool enabled = true;
        WebAppOptions options;
        FileCache fileCache;
        std::string path; // Location of the app
        std::string root; // Optional separate content root; by default the same as path; is where files are served from. If set, referencing /~/ will by default use the app path ("home").
        Akeno::PathMatcher<PathAttributes> pathAttributes;
        std::vector<std::pair<int, std::string>> errorPages;

        std::function<bool(uWS::HttpResponse<false> *res, uWS::HttpRequest *req, std::string_view url,
                           std::string_view fullPath, std::string_view mimeType, int variant, std::string_view status)>
        fileProcessorHttp;
        std::function<bool(uWS::HttpResponse<true> *res, uWS::HttpRequest *req, std::string_view url,
                           std::string_view fullPath, std::string_view mimeType, int variant, std::string_view status)>
        fileProcessorHttps;

        WebApp(std::string path, WebAppOptions options) : path(path), root(path), options(options), pathAttributes({
            .mergeHandlers = true,
            .mergeFn = [](const PathAttributes &a, const PathAttributes &b) {
                PathAttributes result = a;
                result |= b;
                return result;
            }
        }) {}

        void applyAttributes(std::string pathPattern, PathAttributes attributes) {
            pathAttributes.add(pathPattern, attributes);
        }

        void applyAttributes(std::string_view pathPattern, PathAttributes attributes) {
            applyAttributes(std::string(pathPattern), attributes);
        }

        void removeAttributes(std::string pathPattern) {
            pathAttributes.remove(pathPattern);
        }

        void removeAttributes(std::string_view pathPattern) {
            removeAttributes(std::string(pathPattern));
        }

        void clearAttributes() {
            pathAttributes.clear();
        }

        // Resolve + validate. Stores resolved filesystem path. Returns false if the resolved file doesn't exist.
        bool setErrorPage(int code, std::string page) {
            ResolvePathResult resolved = resolvePath(false, page);

            std::error_code ec;
            const bool ok = std::filesystem::exists(resolved.full, ec) && std::filesystem::is_regular_file(resolved.full, ec);
            if (!ok) {
                return false;
            }

            auto it = std::find_if(errorPages.begin(), errorPages.end(),
                [code](const auto& p) { return p.first == code; });

            if (it != errorPages.end())
                it->second = std::move(resolved.full);
            else
                errorPages.emplace_back(code, std::move(resolved.full));

            return true;
        }

        const std::string* getErrorPage(int code) const {
            auto it = std::find_if(errorPages.begin(), errorPages.end(),
                [code](const auto& p) { return p.first == code; });

            return it != errorPages.end() ? &it->second : nullptr;
        }

        /**
         * Resolve a relative, absolute, or root path to a full path while safely avoiding directory traversal attacks.
         * TODO: Optimize
         * @param path - The path to resolve
         * @param current - The current path context (optional)
         * @param useRootPath - Indicates whether to use the root path
         * @returns ResolvePathResult containing full path, relative path, and useRootPath flag
         */
        ResolvePathResult resolvePath(bool useRootPath, std::string_view path, const std::string* current = nullptr) {
            bool isRelative = false;
            std::string_view processedPath = path;

            // Check for tilde prefix patterns
            if (!path.empty() && path[0] == '~') { // '~'
                processedPath = path.substr(1);
                useRootPath = true;
            } else if (path.empty() || path[0] != '/') { // not starting with '/'
                isRelative = true;
            } else if (path.length() >= 3 && path[1] == '~' && path[2] == '/') { // '/~/'
                processedPath = path.substr(2);
                useRootPath = true;
            }

            if (!this->_rootPathAllowed) {
                useRootPath = false;
            }

            const std::string& rootPath = useRootPath ? this->path : (this->root.empty() ? this->path : this->root);

            // Build the full filesystem path
            std::filesystem::path full(rootPath);

            if (isRelative) {
                if (current && !current->empty()) {
                    full /= *current;
                }
                full /= processedPath;
            } else {
                // Absolute path - strip leading slash before appending
                if (!processedPath.empty() && processedPath[0] == '/') {
                    processedPath = processedPath.substr(1);
                }
                full /= processedPath;
            }

            full = full.lexically_normal();
            
            // Safety: prevent traversal outside of root
            std::filesystem::path normalizedRootPath(rootPath);
            normalizedRootPath = normalizedRootPath.lexically_normal();
            
            const std::string& normalizedRoot = normalizedRootPath.native();
            const std::string& fullStr = full.native();
            
            if (fullStr.find(normalizedRoot) != 0 || 
                (fullStr.length() > normalizedRoot.length() &&
                 fullStr[normalizedRoot.length()] != '/' &&
                 !normalizedRoot.empty())) {
                return { true, std::string(fullStr), std::string(1, std::filesystem::path::preferred_separator) };
            }

            // For client links, compute relative path efficiently
            std::string relativeForLink;
            if (isRelative) {
                relativeForLink.assign(path.data(), path.size());
            } else {
                // Extract relative portion after root
                if (fullStr.length() > normalizedRoot.length()) {
                    size_t start = normalizedRoot.length();
                    if (start < fullStr.length() && fullStr[start] == '/') {
                        ++start;
                    }
                    if (start < fullStr.length()) {
                        relativeForLink = "/" + fullStr.substr(start);
                    } else {
                        relativeForLink = "/";
                    }
                } else {
                    relativeForLink = "/";
                }
            }

            return { useRootPath, std::string(fullStr), std::move(relativeForLink) };
        }
    };

    bool checkCompatibility(std::string_view userAgent, const std::tuple<int, int, bool>& browserCompatibility) {
        int minChrome = std::get<0>(browserCompatibility);
        int minFirefox = std::get<1>(browserCompatibility);
        bool shouldCheck = std::get<2>(browserCompatibility);

        if (!shouldCheck) {
            return true;
        }

        if (userAgent.find("msie") != std::string_view::npos || userAgent.find("trident/") != std::string_view::npos) {
            return false; // Internet Explorer is never supported
        }

        auto parseVersionAfter = [](std::string_view haystack, size_t start) -> int {
            if (start >= haystack.size()) {
                return -1;
            }
            int value = 0;
            bool any = false;
            for (size_t i = start; i < haystack.size(); ++i) {
                char c = haystack[i];
                if (c < '0' || c > '9') {
                    break;
                }
                any = true;
                value = value * 10 + (c - '0');
            }
            return any ? value : -1;
        };

        // Simple user agent parsing
        if (minChrome > 0) {
            size_t chromePos = userAgent.find("Chrome/");
            if (chromePos != std::string_view::npos) {
                int chromeVersion = parseVersionAfter(userAgent, chromePos + 7);
                if (chromeVersion != -1 && chromeVersion < minChrome) {
                    return false;
                }
            }
        }

        if (minFirefox > 0) {
            size_t firefoxPos = userAgent.find("Firefox/");
            if (firefoxPos != std::string_view::npos) {
                int firefoxVersion = parseVersionAfter(userAgent, firefoxPos + 8);
                if (firefoxVersion != -1 && firefoxVersion < minFirefox) {
                    return false;
                }
            }
        }

        return true;
    }

    namespace WebServer {
        template <bool SSL>
        void onRequest(uWS::HttpResponse<SSL> *res, uWS::HttpRequest *req, Akeno::WebApp *app) {
            if(!app) {
                Akeno::sendErrorPage(res, "404");
                return;
            }

            // HTTPS redirect
            // TODO: Decide based on mode (dev/prod) and app config
            // HTTP should be redirected by default in production
            if constexpr (!SSL) {
                if (app->options.redirectToHttps) {
                    res->redirectToHTTPS(req->getHeader("host"), req->getUrl());
                    return;
                }
            }

            // Check if app is enabled or disabled
            if(!app->enabled) {
                Akeno::sendErrorPage(res, "422", "This website is currently disabled.");
                return;
            }

            // TODO: Configurable path attributes & other handlers

            // TODO: Direct streaming only for large files (above the cache threshold)

            // There's a lot left to implement

            std::string_view url = req->getUrl();
            std::string_view status = "200 OK"sv;

            PathAttributes* attributes = app->pathAttributes.match(url);
            if(attributes != nullptr) {
                // Handle deny
                if (attributes->deny) {
                    Akeno::sendErrorPage(res, "403");
                    return;
                }

                // Handle redirect
                if (attributes->transformType == 2) { // Redirect
                    res->redirect(attributes->transformTarget);
                    return;
                }

                // Handle reroute
                if (attributes->transformType == 3) { // Reroute
                    std::string host = attributes->transformTarget.substr(0, attributes->transformTarget.find('/'));
                    std::string path = attributes->transformTarget.substr(attributes->transformTarget.find('/'));

                    // TODO: This is hacky. Path is also not properly rerouted
                    res->reroute(req, host, path);
                    return;
                }

                // Handle alias
                if (attributes->transformType == 1) { // Alias
                    url = attributes->transformTarget;
                }
            }

            // Temporary
            if(req->getCaseSensitiveMethod() != "GET" && req->getCaseSensitiveMethod() != "HEAD") {
                res->writeStatus("405 Method Not Allowed")->end();
                return;
            }

            // Check browser compatibility
            if(std::get<2>(app->options.browserCompatibility)) {
                std::string_view userAgent = req->getHeader("user-agent");
                if(!checkCompatibility(userAgent, app->options.browserCompatibility)) {
                    // TODO: Reimplement the templated string
                    // std::string_view messageStr = "Your browser version is not supported - please update your web browser!<br>Minimum requirement to access this website: Chrome ${app._browserRequirements.chrome && app._browserRequirements.chrome} and up, Firefox ${app._browserRequirements.firefox && app._browserRequirements.firefox} and up.<br><br><strong><a href=\"https://browser-update.org/update-browser.html\" target=\"_blank\">Learn more</a></strong>";
                    std::string_view messageStr = "Your browser version is not supported - please update your web browser!<br><strong><a href=\"https://browser-update.org/update-browser.html\" target=\"_blank\">Learn more</a></strong>";
                    Akeno::sendErrorPage(res, "403", messageStr, "Outdated Browser");
                    return;
                }
            }

            ResolvePathResult pathResult = app->resolvePath(false, url);
            std::string file = pathResult.full;
            // std::cout << "Resolved path: " << file << " (relative: " << pathResult.relative << ", useRootPath: " << pathResult.useRootPath << ")" << std::endl;

            std::string_view mimeType = getMimeType(file);
            std::string_view acceptEncoding = req->getHeader("accept-encoding");

            int variant = Akeno::getUsedCompression(acceptEncoding, mimeType);

            // File not found
            // TODO: This shouldn't be here (cache should take priority & there should be a better/more efficient way to resolve aliases)
            // For now this is "good enough"
            bool exists = std::filesystem::exists(file);
            if(!exists) {
                // Try aliasing
                std::filesystem::path aliasPath = file;
                aliasPath += ".html";
                if (std::filesystem::exists(aliasPath)) {
                    file = aliasPath;
                    mimeType = "text/html";
                    exists = true;
                    // We will check if it is a reular file later
                }
            } else if(exists && std::filesystem::is_directory(file)) {
                // Try to resolve *.html, /index.html
                std::filesystem::path indexPath = std::filesystem::path(file) / "index.html";
                if (std::filesystem::exists(indexPath)) {
                    file = indexPath.native();
                    mimeType = "text/html";
                    // We will check if it is a reular file later
                } else {
                    exists = false;
                }
            }

            if(!exists || !std::filesystem::is_regular_file(file)) {
                // Remove from cache if it exists, since it's no longer valid
                app->fileCache.remove(file);

                if(mimeType == "text/css" || mimeType == "application/javascript" || mimeType.starts_with("image/") || mimeType.starts_with("font/")) {
                    // For missing images/css/js, end the response without body rather than a 404 page
                    res->writeStatus("404 Not Found")->writeHeader("Content-Type", mimeType)->end();
                    return;
                }

                const std::string* customPage = app->getErrorPage(404);
                if (customPage == nullptr) {
                    // Default 404 page
                    Akeno::sendErrorPage(res, "404");
                    return;
                }

                // Alias to the custom page
                file = *customPage;
                mimeType = "text/html";
                status = "404 Not Found";

                if(!std::filesystem::exists(file)) {
                    // If the custom 404 page doesn't exist, send a default 404 response
                    res->writeStatus("404 Not Found")->end();
                    return;
                }
            }

            // If not changed and is cached, we serve from cache:
            const Akeno::FileCache::CacheEntry* baseEntry = app->fileCache.get(file, 0);

            if(baseEntry) {
                std::cout << "Connected paths to key \"" << file << "\":" << std::endl;
                for (const auto &item : baseEntry->shared->paths) {
                    std::cout << "  " << item.path << std::endl;
                }
            }

            if(baseEntry && !app->fileCache.hasChanged(file)) {
                // Check ETag
                // std::string_view clientETags = req->getHeader("if-none-match");
                // if(!clientETags.empty() && baseEntry->shared->hasHeader("ETag")) {
                //     std::string_view serverETag = baseEntry->shared->getHeader("ETag");
                //     if (clientETags == "*" || clientETags.find(serverETag) != std::string_view::npos) {
                //         res->writeStatus("304 Not Modified")->writeHeader("ETag", serverETag)->endWithoutBody();
                //         return;
                //     }
                // }

                if(app->fileCache.tryServeWithCompression(file, variant, res, status)) {
                    // File served successfully
                    // We must not touch req/res now (we're done with this request)
                    return;
                }

                // Unsure how to handle this case yet (failed sending anything); could just be an empty buffer, etc.
                // For now just send an empty response (we must respond somehow)
                // Later we could distinguish what happened
                res->endWithoutBody();
                return;
            }

            // std::cout << "File \"" << file << "\" is not cached or has changed, updating cache..." << std::endl;

            if constexpr (SSL) {
                if (app->fileProcessorHttps && app->fileProcessorHttps(res, req, url, file, mimeType, variant, status)) {
                    return;
                }
            } else {
                if (app->fileProcessorHttp && app->fileProcessorHttp(res, req, url, file, mimeType, variant, status)) {
                    return;
                }
            }

            std::string content;
            try {
                std::filesystem::path filePath{file};
                content = std::string(std::filesystem::file_size(filePath), '\0');
                std::ifstream ifs(filePath, std::ios::binary);
                ifs.read(content.data(), content.size());
            } catch (const std::exception& e) {
                std::cerr << "Error reading file \"" << file << "\": " << e.what() << std::endl;
                Akeno::sendErrorPage(res, "500");
                return;
            }

            // Save content to cache
            std::vector<std::string> paths{std::string(file)};
            app->fileCache.update(file, content, paths);

            // Now send the response
            if(app->fileCache.tryServeWithCompression(file, variant, res, status)) {
                // File served successfully
                return;
            }

            // Failed to serve file for some reason, send an empty response for now
            res->endWithoutBody();
        }
    }
} // namespace Akeno
