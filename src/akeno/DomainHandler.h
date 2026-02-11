#ifndef AKENO_DOMAIN_HANDLER_H
#define AKENO_DOMAIN_HANDLER_H

#include <v8.h>
#include "akeno/Router.h"
#include <memory>
#include <functional>
#include <string>
#include "MoveOnlyFunction.h"

namespace uWS {
    template <bool> struct HttpResponse;
    struct HttpRequest;
}

using namespace v8;

struct DomainHandler {
    enum class Kind : uint8_t {
        None,
        PathMatcher,
        JsObject,
        Callback,
        StaticBuffer,
        Custom
    } kind = Kind::None;

    // This thing is a bit clumsy but sadly there is no simpler way to have both HTTP and HTTPS via one route in C++
    // Don't get me started on H3

    // Store both HTTP and HTTPS callbacks for protocol-agnostic routing
    uWS::MoveOnlyFunction<void(uWS::HttpResponse<false> *, uWS::HttpRequest *)> callbackHttp;
    uWS::MoveOnlyFunction<void(uWS::HttpResponse<true> *, uWS::HttpRequest *)> callbackHttps;
    
    std::shared_ptr<Akeno::PathMatcher<DomainHandler>> pathMatcher;
    std::shared_ptr<std::string> staticBuffer;
    std::shared_ptr<v8::Global<v8::Object>> jsObject;
    std::shared_ptr<void> customData;

    // TODO: Add request type filtering

    /**
     * Invoke the appropriate callback based on SSL template parameter.
     */
    template <bool SSL>
    void invokeCallback(uWS::HttpResponse<SSL> *res, uWS::HttpRequest *req) {
        if constexpr (SSL) {
            if (callbackHttps) {
                callbackHttps(res, req);
            }
        } else {
            if (callbackHttp) {
                callbackHttp(res, req);
            }
        }
    }

    /**
     * Check if a callback exists for the given protocol.
     */
    template <bool SSL>
    bool hasCallback() {
        if constexpr (SSL) {
            return (bool)callbackHttps;
        } else {
            return (bool)callbackHttp;
        }
    }

    /**
     * Note; both Callback and any other type (can) be registered, callback is always first.
     * Whether it should depends on you
     */
    template <bool SSL>
    static DomainHandler onRequest(uWS::MoveOnlyFunction<void(uWS::HttpResponse<SSL> *, uWS::HttpRequest *)> &&handler) {
        DomainHandler h;
        h.kind = Kind::Callback;
        if constexpr (SSL) {
            h.callbackHttps = std::move(handler);
        } else {
            h.callbackHttp = std::move(handler);
        }
        return h;
    }

    /**
     * Create a handler that works with both HTTP and HTTPS by providing both callbacks.
     */
    static DomainHandler onRequestBoth(
        uWS::MoveOnlyFunction<void(uWS::HttpResponse<false> *, uWS::HttpRequest *)> &&httpHandler,
        uWS::MoveOnlyFunction<void(uWS::HttpResponse<true> *, uWS::HttpRequest *)> &&httpsHandler
    ) {
        DomainHandler h;
        h.kind = Kind::Callback;
        h.callbackHttp = std::move(httpHandler);
        h.callbackHttps = std::move(httpsHandler);
        return h;
    }

    /**
     * Create a unified handler from a template function (preferred for protocol-agnostic handlers).
     * Usage: DomainHandler::onRequestUnified<MyHandler>()
     */
    template <auto HandlerFunc>
    static DomainHandler onRequestUnified() {
        DomainHandler h;
        h.kind = Kind::Callback;
        h.callbackHttp = [](uWS::HttpResponse<false> *res, uWS::HttpRequest *req) {
            HandlerFunc(res, req);
        };
        h.callbackHttps = [](uWS::HttpResponse<true> *res, uWS::HttpRequest *req) {
            HandlerFunc(res, req);
        };
        return h;
    }

    static DomainHandler fromPathMatcher(std::shared_ptr<Akeno::PathMatcher<DomainHandler>> matcher) {
        DomainHandler h;
        h.kind = Kind::PathMatcher;
        h.pathMatcher = std::move(matcher);
        return h;
    }

    static DomainHandler fromPathMatcher(Akeno::PathMatcher<DomainHandler> *matcher) {
        return fromPathMatcher(std::shared_ptr<Akeno::PathMatcher<DomainHandler>>(matcher, [](auto *) {}));
    }

    static DomainHandler fromJsObject(Isolate *isolate, Local<Object> obj) {
        DomainHandler h;
        h.kind = Kind::JsObject;
        h.jsObject = std::make_shared<v8::Global<v8::Object>>();
        h.jsObject->Reset(isolate, obj);
        return h;
    }

    static DomainHandler fromStaticBuffer(std::string buffer) {
        DomainHandler h;
        h.kind = Kind::StaticBuffer;
        h.staticBuffer = std::make_shared<std::string>(std::move(buffer));
        return h;
    }

    static DomainHandler fromCustom(std::shared_ptr<void> data) {
        DomainHandler h;
        h.kind = Kind::Custom;
        h.customData = std::move(data);
        return h;
    }

    bool operator==(const DomainHandler &other) const noexcept {
        if (kind != other.kind)
            return false;
        switch (kind) {
            case Kind::None:
                return true;
            case Kind::PathMatcher:
                return pathMatcher == other.pathMatcher;
            case Kind::JsObject:
                return jsObject == other.jsObject;
            case Kind::Callback:
                return false; // MoveOnlyFunction cannot be compared (TODO: Idk probably)
            case Kind::StaticBuffer:
                return staticBuffer == other.staticBuffer;
            case Kind::Custom:
                return customData == other.customData;
        }
        return false;
    }
};

/* Resolve a domain handler through nested PathMatcher chains.
 * Used by both HttpContext (C++) and AppWrapper (JS bridge). */
inline DomainHandler *resolveDomainHandler(DomainHandler *handler, std::string_view path) {
    DomainHandler *current = handler;
    size_t depth = 0;
    constexpr size_t kMaxResolveDepth = 8;
    while (current && current->kind == DomainHandler::Kind::PathMatcher) {
        if (!current->pathMatcher) {
            return nullptr;
        }
        current = current->pathMatcher->match(path);
        if (!current) {
            return nullptr;
        }
        if (++depth > kMaxResolveDepth) {
            return nullptr;
        }
    }
    return current;
}

inline const DomainHandler *resolveDomainHandler(const DomainHandler *handler, std::string_view path) {
    return resolveDomainHandler(const_cast<DomainHandler *>(handler), path);
}

#endif // AKENO_DOMAIN_HANDLER_H
