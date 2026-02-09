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

    uWS::MoveOnlyFunction<void(uWS::HttpResponse<false> *, uWS::HttpRequest *)> callback;
    std::shared_ptr<Akeno::PathMatcher<DomainHandler>> pathMatcher;
    std::shared_ptr<std::string> staticBuffer;
    std::shared_ptr<v8::Global<v8::Object>> jsObject;
    std::shared_ptr<void> customData;

    // TODO: Add request type filtering

    /**
     * Note; both Callback and any other type (can) be registered, callback is always first.
     * Whether it should depends on you
     */
    static DomainHandler onRequest(uWS::MoveOnlyFunction<void(uWS::HttpResponse<false> *, uWS::HttpRequest *)> &&handler) { // TODO: Handle SSL cases (will need to do it differently as routers are now protocol agnostic)
        DomainHandler h;
        h.kind = Kind::Callback;
        h.callback = std::move(handler);
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
