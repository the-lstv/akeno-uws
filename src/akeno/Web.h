/*
    Author: Lukas (thelstv)
    Copyright: (c) https://lstv.space

    Last modified: 2026
    License: GPL-3.0
    Version: 2.0.0-cpp
    Description: A performance optimized web application framework for Akeno.
    Rewritten from JavaScript to C++
*/

#include <string>
#include <string_view>
#include <filesystem>
#include <algorithm>
#include "akeno/App.h"


namespace Akeno
{
    struct ResolvePathResult {
        std::string full;
        std::string relative;
        bool useRootPath;
    };

    struct WebAppOptions {
        // Placeholder for future options
    };

    namespace WebServer {
        template <bool SSL>
        void onRequest(uWS::HttpResponse<SSL> *res, uWS::HttpRequest *req, WebApp *app) {
            HttpContextData<SSL> *httpContextData = HttpContext<SSL>::getSocketContextDataS((us_socket_t *) res);

            if(!app) {
                Akeno::sendErrorPage(res, "404");
                return;
            }

            // HTTPS redirect
            // TODO: Decide based on mode (dev/prod) and app config
            // HTTP should be redirected by default in production
            if constexpr (!SSL) {
                if (app->options.redirectToHttps) {
                    std::string_view host = req->getHeader("host");
                    std::string_view url = req->getUrl();
                    std::string redirectUrl = "https://" + std::string(host) + std::string(url);
                    res->writeStatus("301 Moved Permanently")->writeHeader("Location", redirectUrl)->end();
                    return;
                }
            }

            // TODO: Ratelimit

            // TODO: Check if app is enabled or disabled

            // TODO: Check browser compatibility

            // TODO: Configurable path attributes

            // There's a lot left to re-implement from JS, I am for now just going to implement the basic file serving logic

            std::string_view url = req->getUrl();
            
            ResolvePathResult pathResult = app->resolvePath(std::string(url));
        }
    }

    class WebApp {
    public:
        std::string path;
        std::string root;
        WebAppOptions options;
        bool _rootPathAllowed = true;

        WebApp(std::string path, WebAppOptions options) : path(path), root(path), options(options) {
            
        }

        /**
         * Resolve a relative, absolute, or root path to a full path while safely avoiding directory traversal attacks.
         * @param path - The path to resolve
         * @param current - The current path context (optional)
         * @param useRootPath - Indicates whether to use the root path
         * @returns ResolvePathResult containing full path, relative path, and useRootPath flag
         */
        ResolvePathResult resolvePath(const std::string& path, const std::string* current = nullptr, bool useRootPath = false) {
            // Preserve original input for URL construction
            const std::string original = path;
            bool isRelative = false;
            std::string processedPath = path;

            if (!path.empty() && static_cast<unsigned char>(path[0]) == 126) { // '~'
                processedPath = path.substr(1);
                useRootPath = true;
            } else if (path.empty() || static_cast<unsigned char>(path[0]) != 47) { // not starting with '/'
                isRelative = true;
            } else if (path.length() >= 3 && 
                       static_cast<unsigned char>(path[1]) == 126 && 
                       static_cast<unsigned char>(path[2]) == 47) { // '/~/'
                processedPath = path.substr(2);
                useRootPath = true;
            }

            if (!this->_rootPathAllowed) {
                useRootPath = false;
            }

            const std::string& rootPath = useRootPath ? this->path : (this->root.empty() ? this->path : this->root);

            // Resolve to an absolute filesystem path for the server
            std::filesystem::path base = isRelative ? (current ? *current : "/") : "/";
            std::filesystem::path resolvedFsRelative = (base / processedPath).lexically_normal();
            
            // Make it absolute if not already
            if (!resolvedFsRelative.is_absolute()) {
                resolvedFsRelative = std::filesystem::path("/") / resolvedFsRelative.relative_path();
            }
            resolvedFsRelative = resolvedFsRelative.lexically_normal();

            // Join root with resolved path
            std::filesystem::path full = std::filesystem::path(rootPath);
            std::string resolvedStr = resolvedFsRelative.string();
            // Strip leading slash for joining
            if (!resolvedStr.empty() && resolvedStr[0] == '/') {
                resolvedStr = resolvedStr.substr(1);
            }
            full /= resolvedStr;
            full = full.lexically_normal();

            std::string fullStr = full.string();
            
            // Safety: prevent traversal outside of root
            // Ensure both paths end without trailing separator for comparison
            std::string normalizedRoot = std::filesystem::path(rootPath).lexically_normal().string();
            if (fullStr.find(normalizedRoot) != 0 || 
                (fullStr.length() > normalizedRoot.length() && 
                 fullStr[normalizedRoot.length()] != '/' && 
                 normalizedRoot.length() > 0)) {
                return { fullStr, std::string(1, std::filesystem::path::preferred_separator), true };
            }

            // For client links, keep relative input as-is (e.g., "./assets/main.js")
            std::string relativeForLink = isRelative ? original : resolvedFsRelative.string();

            return { fullStr, relativeForLink, useRootPath };
        }
    };
} // namespace Akeno
