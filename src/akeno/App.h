/*
 * Authored by Alex Hultman, 2018-2026.
 * Intellectual property of third-party.
 *
 * Modified for Akeno: copyright (c) 2026 Lukas Zloch (https://lstv.space)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UWS_APP_H
#define UWS_APP_H

// Important TODO: keep version in sync with package.json
#define AKENO_VERSION "1.6.9-beta"

#define _CRT_SECURE_NO_WARNINGS

#include <string>
#include <charconv>
#include <string_view>
#include <unordered_set>
#include <algorithm>

namespace uWS {
    /* Safari 15.0 - 15.3 broken compression detection */
    inline bool hasBrokenCompression(std::string_view userAgent) {
        size_t posStart = userAgent.find(" Version/15.");
        if (posStart == std::string_view::npos) return false;
        posStart += 12;
        size_t posEnd = userAgent.find(' ', posStart);
        if (posEnd == std::string_view::npos) return false;
        unsigned int minorVersion = 0;
        auto result = std::from_chars(userAgent.data() + posStart, userAgent.data() + posEnd, minorVersion);
        if (result.ec != std::errc()) return false;
        if (result.ptr != userAgent.data() + posEnd) return false;
        if (minorVersion > 3) return false;
        if (userAgent.find(" Safari/", posEnd) == std::string_view::npos) return false;
        return true;
    }
}

#include "akeno/HttpContext.h"
#include "HttpResponse.h"
#include "WebSocketContext.h"
#include "WebSocket.h"
#include "PerMessageDeflate.h"

#include "akeno/Router.h"

namespace uWS {

    /* This one matches us_socket_context_options_t but has default values */
    struct SocketContextOptions {
        const char *key_file_name = nullptr;
        const char *cert_file_name = nullptr;
        const char *passphrase = nullptr;
        const char *dh_params_file_name = nullptr;
        const char *ca_file_name = nullptr;
        const char *ssl_ciphers = nullptr;
        int ssl_prefer_low_memory_usage = 0;

        operator struct us_socket_context_options_t() const {
            struct us_socket_context_options_t socket_context_options;
            memcpy(&socket_context_options, this, sizeof(SocketContextOptions));
            return socket_context_options;
        }
    };

    static_assert(sizeof(struct us_socket_context_options_t) == sizeof(SocketContextOptions), "Mismatching uSockets/uWebSockets ABI");

using DomainHandler = ::DomainHandler;

/* Forward declaration */
template <bool SSL> struct TemplatedProtocol;

/* WebSocket behavior — used by Protocol */
template <bool SSL, typename UserData>
struct WebSocketBehavior {
    /* Disabled compression by default - probably a bad default */
    CompressOptions compression = DISABLED;
    /* Maximum message size we can receive */
    unsigned int maxPayloadLength = 16 * 1024;
    /* 2 minutes timeout is good */
    unsigned short idleTimeout = 120;
    /* 64kb backpressure is probably good */
    unsigned int maxBackpressure = 64 * 1024;
    bool closeOnBackpressureLimit = false;
    /* This one depends on kernel timeouts and is a bad default */
    bool resetIdleTimeoutOnSend = false;
    /* A good default, esp. for newcomers */
    bool sendPingsAutomatically = true;
    /* Maximum socket lifetime in minutes before forced closure (defaults to disabled) */
    unsigned short maxLifetime = 0;
    MoveOnlyFunction<void(HttpResponse<SSL> *, HttpRequest *, struct us_socket_context_t *)> upgrade = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *)> open = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *, std::string_view, OpCode)> message = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *, std::string_view, OpCode)> dropped = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *)> drain = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *, std::string_view)> ping = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *, std::string_view)> pong = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *, std::string_view, int, int)> subscription = nullptr;
    MoveOnlyFunction<void(WebSocket<SSL, true, UserData> *, int, std::string_view)> close = nullptr;
};


/*
 * App is now a protocol-agnostic routing context.
 */
struct App {
private:
    Akeno::DomainRouter<DomainHandler> *domainRouter = nullptr;
    bool ownsDomainRouter = false;

public:
    TopicTree<TopicTreeMessage, TopicTreeBigMessage> *topicTree = nullptr;

    /* --- Domain Router --- */

    void setDomainRouter(Akeno::DomainRouter<DomainHandler> *router) {
        domainRouter = router;
        ownsDomainRouter = false;
    }

    Akeno::DomainRouter<DomainHandler> *getDomainRouter() {
        return domainRouter;
    }

    /* --- Domain routing API --- */

    /* Add a domain route: app.route("example.{com,net}", handler) */
    App &&route(std::string pattern, DomainHandler handler) {
        if (!domainRouter) return std::move(*this);
        domainRouter->add(pattern, std::move(handler));
        return std::move(*this);
    }

    /* Remove a domain route. */
    App &&unroute(std::string pattern) {
        if (!domainRouter) return std::move(*this);
        domainRouter->remove(pattern);
        return std::move(*this);
    }

    /* --- Pub/Sub --- */

    /* Publish to a topic — requires topicTree to have been initialized by a protocol */
    bool publish(std::string_view topic, std::string_view message, OpCode opCode, bool compress = false) {
        if (!topicTree) return false;
        if (message.length() >= LoopData::CORK_BUFFER_SIZE) {
            return topicTree->publishBig(nullptr, topic, {message, opCode, compress}, [](Subscriber *s, TopicTreeBigMessage &msg) {
                /* The actual WebSocket send is protocol-specific but the subscriber's user pointer
                 * was set by the protocol, so this cast works regardless of SSL. We use SSL=false
                 * here as the send() method is identical in both templates at the binary level. */
                auto *ws = (WebSocket<false, true, int> *) s->user;
                ws->send(msg.message, (OpCode)msg.opCode, msg.compress);
            });
        } else {
            return topicTree->publish(nullptr, topic, {std::string(message), opCode, compress});
        }
    }

    unsigned int numSubscribers(std::string_view topic) {
        if (!topicTree) return 0;
        Topic *t = topicTree->lookupTopic(topic);
        if (t) {
            return (unsigned int) t->size();
        }
        return 0;
    }

    /* --- Lifecycle --- */

    ~App() {
        /* Delete TopicTree */
        if (topicTree) {
            Loop::get()->removePostHandler(topicTree);
            Loop::get()->removePreHandler(topicTree);
            delete topicTree;
        }

        /* Free domain router if we own it */
        if (ownsDomainRouter && domainRouter) {
            delete domainRouter;
        }
    }

    App(const App &other) = delete;

    App(App &&other) {
        domainRouter = other.domainRouter;
        other.domainRouter = nullptr;
        ownsDomainRouter = other.ownsDomainRouter;
        other.ownsDomainRouter = false;

        topicTree = other.topicTree;
        other.topicTree = nullptr;
    }

    App() {
        /* No protocol-specific initialization */
    }

    bool constructorFailed() {
        return false;
    }
};


/*
 * TemplatedProtocol
 *
 * Owns an httpContext (socket context) that listens on an address.
 * Owns WebSocket contexts, manages SNI, etc.
 * Can bind to an App to use its domain router for request routing.
 * Can be created, bound, and destroyed independently of the App.
 */
template <bool SSL>
struct TemplatedProtocol {
private:
    HttpContext<SSL> *httpContext;
    App *app = nullptr;

    /* Track which SNI server names we registered (for cleanup) */
    std::unordered_set<std::string> sniServerNames;

public:
    /* WebSocket contexts owned by this protocol */
    std::vector<MoveOnlyFunction<void()>> webSocketContextDeleters;
    std::vector<void *> webSocketContexts;

    /* Register an exact domain as SNI server name */
    void syncSniForExact(const std::string &domain, DomainHandler *handler) {
        if constexpr (SSL) {
            if (sniServerNames.find(domain) == sniServerNames.end()) {
                us_socket_context_add_server_name(SSL,
                    (struct us_socket_context_t *) httpContext,
                    domain.c_str(), {}, (void *) handler);
                sniServerNames.insert(domain);
            }
        }
    }

    /* Remove SNI entries for a pattern */
    void removeSniForPattern(const std::string &pattern) {
        if constexpr (SSL) {
            std::vector<std::string> expanded;
            Akeno::Internal::expandPattern(pattern, expanded);

            for (const auto &p : expanded) {
                auto it = sniServerNames.find(p);
                if (it != sniServerNames.end()) {
                    us_socket_context_remove_server_name(SSL,
                        (struct us_socket_context_t *) httpContext, p.c_str());
                    sniServerNames.erase(it);
                }
            }
        }
    }

    /* SNI management */
    TemplatedProtocol &&addServerName(std::string hostname_pattern, SocketContextOptions options = {}) {
        if constexpr (SSL) {
            us_socket_context_add_server_name(SSL,
                (struct us_socket_context_t *) httpContext,
                hostname_pattern.c_str(), options, nullptr);
        }

        return std::move(*this);
    }

    TemplatedProtocol &&removeServerName(std::string hostname_pattern) {
        if constexpr (SSL) {
            us_socket_context_remove_server_name(SSL,
                (struct us_socket_context_t *) httpContext,
                hostname_pattern.c_str());
        }

        return std::move(*this);
    }

    TemplatedProtocol &&missingServerName(MoveOnlyFunction<void(const char *hostname)> handler) {
        if (!constructorFailed()) {
            httpContext->getSocketContextData()->missingServerNameHandler = std::move(handler);

            us_socket_context_on_server_name(SSL, (struct us_socket_context_t *) httpContext,
                [](struct us_socket_context_t *context, const char *hostname) {
                    HttpContext<SSL> *httpContext = (HttpContext<SSL> *) context;
                    httpContext->getSocketContextData()->missingServerNameHandler(hostname);
                });
        }

        return std::move(*this);
    }

    void *getNativeHandle() {
        return us_socket_context_get_native_handle(SSL, (struct us_socket_context_t *) httpContext);
    }

    TemplatedProtocol &&filter(MoveOnlyFunction<void(HttpResponse<SSL> *, int)> &&filterHandler) {
        httpContext->filter(std::move(filterHandler));
        return std::move(*this);
    }

    /* --- App binding --- */

    /* Bind this protocol to an app. The app's domain router will be used for request routing. */
    TemplatedProtocol &&bind(App *newApp) {
        /* Detach from current app if any */
        if (app) {
            unbind();
        }

        app = newApp;
        if (app) {
            /* Store domain router pointer in httpContext for use by the request handler */
            httpContext->getSocketContextData()->domainRouter = (void *) app->getDomainRouter();
        }

        return std::move(*this);
    }

    /* Detach this protocol from its current app. */
    TemplatedProtocol &&unbind() {
        if (app) {
            /* Clear domain router reference in httpContext */
            if (httpContext) {
                httpContext->getSocketContextData()->domainRouter = nullptr;
            }

            app = nullptr;
        }
        return std::move(*this);
    }

    App *getApp() {
        return app;
    }

    HttpContext<SSL> *getHttpContext() {
        return httpContext;
    }

    /* Closes all sockets including listen sockets. */
    TemplatedProtocol &&close() {
        us_socket_context_close(SSL, (struct us_socket_context_t *) httpContext);
        /* Also close WebSocket contexts */
        for (void *webSocketContext : webSocketContexts) {
            us_socket_context_close(SSL, (struct us_socket_context_t *) webSocketContext);
        }
        return std::move(*this);
    }

    /* --- Listen --- */

    /* Host, port, callback */
    TemplatedProtocol &&listen(std::string host, int port, MoveOnlyFunction<void(us_listen_socket_t *)> &&handler) {
        if (!host.length()) {
            return listen(port, std::move(handler));
        }
        handler(httpContext ? httpContext->listen(host.c_str(), port, 0) : nullptr);
        return std::move(*this);
    }

    /* Host, port, options, callback */
    TemplatedProtocol &&listen(std::string host, int port, int options, MoveOnlyFunction<void(us_listen_socket_t *)> &&handler) {
        if (!host.length()) {
            return listen(port, options, std::move(handler));
        }
        handler(httpContext ? httpContext->listen(host.c_str(), port, options) : nullptr);
        return std::move(*this);
    }

    /* Port, callback */
    TemplatedProtocol &&listen(int port, MoveOnlyFunction<void(us_listen_socket_t *)> &&handler) {
        handler(httpContext ? httpContext->listen(nullptr, port, 0) : nullptr);
        return std::move(*this);
    }

    /* Port, options, callback */
    TemplatedProtocol &&listen(int port, int options, MoveOnlyFunction<void(us_listen_socket_t *)> &&handler) {
        handler(httpContext ? httpContext->listen(nullptr, port, options) : nullptr);
        return std::move(*this);
    }

    /* options, callback, path to unix domain socket */
    TemplatedProtocol &&listen(int options, MoveOnlyFunction<void(us_listen_socket_t *)> &&handler, std::string path) {
        handler(httpContext ? httpContext->listen(path.c_str(), options) : nullptr);
        return std::move(*this);
    }

    /* callback, path to unix domain socket */
    TemplatedProtocol &&listen(MoveOnlyFunction<void(us_listen_socket_t *)> &&handler, std::string path) {
        handler(httpContext ? httpContext->listen(path.c_str(), 0) : nullptr);
        return std::move(*this);
    }

    /* --- WebSocket --- */

    /* Register a WebSocket handler on this protocol. */
    template <typename UserData>
    struct us_socket_context_t *ws(std::string pattern, WebSocketBehavior<SSL, UserData> &&behavior) {
        static_assert(alignof(UserData) <= LIBUS_EXT_ALIGNMENT,
        "µWebSockets cannot satisfy UserData alignment requirements. You need to recompile µSockets with LIBUS_EXT_ALIGNMENT adjusted accordingly.");

        if (!httpContext) {
            return nullptr;
        }

        if (behavior.idleTimeout && behavior.idleTimeout < 8) {
            std::cerr << "Error: idleTimeout must be either 0 or greater than 8!" << std::endl;
            std::terminate();
        }

        if (behavior.idleTimeout > 240 * 4) {
            std::cerr << "Error: idleTimeout must not be greater than 960 seconds!" << std::endl;
            std::terminate();
        }

        if (behavior.maxLifetime > 240) {
            std::cerr << "Error: maxLifetime must not be greater than 240 minutes!" << std::endl;
            std::terminate();
        }

        /* Ensure topicTree exists (on the bound app if we have one, or stand-alone) */
        TopicTree<TopicTreeMessage, TopicTreeBigMessage> *topicTree = app ? app->topicTree : nullptr;
        if (!topicTree) {
            bool needsUncork = false;
            topicTree = new TopicTree<TopicTreeMessage, TopicTreeBigMessage>([needsUncork](Subscriber *s, TopicTreeMessage &message, TopicTree<TopicTreeMessage, TopicTreeBigMessage>::IteratorFlags flags) mutable {
                auto *ws = (WebSocket<SSL, true, int> *) s->user;

                if (flags & TopicTree<TopicTreeMessage, TopicTreeBigMessage>::IteratorFlags::FIRST) {
                    if (ws->canCork() && !ws->isCorked()) {
                        ((AsyncSocket<SSL> *)ws)->cork();
                        needsUncork = true;
                    }
                }

                if (WebSocket<SSL, true, int>::SendStatus::DROPPED == ws->send(message.message, (OpCode)message.opCode, message.compress)) {
                    if (needsUncork) {
                        ((AsyncSocket<SSL> *)ws)->uncork();
                        needsUncork = false;
                    }
                    return true;
                }

                if (flags & TopicTree<TopicTreeMessage, TopicTreeBigMessage>::IteratorFlags::LAST) {
                    if (needsUncork) {
                        ((AsyncSocket<SSL> *)ws)->uncork();
                    }
                }

                return false;
            });

            Loop::get()->addPostHandler(topicTree, [topicTree](Loop *) {
                topicTree->drain();
            });

            Loop::get()->addPreHandler(topicTree, [topicTree](Loop *) {
                topicTree->drain();
            });

            if (app) {
                app->topicTree = topicTree;
            }
        }

        auto *webSocketContext = WebSocketContext<SSL, true, UserData>::create(Loop::get(), (us_socket_context_t *) httpContext, topicTree);

        webSocketContextDeleters.push_back([webSocketContext]() {
            webSocketContext->free();
        });

        webSocketContexts.push_back((void *)webSocketContext);

#ifdef UWS_NO_ZLIB
        behavior.compression = DISABLED;
#endif

        if (behavior.compression) {
            LoopData *loopData = (LoopData *) us_loop_ext(us_socket_context_loop(SSL, webSocketContext->getSocketContext()));
            if (!loopData->zlibContext) {
                loopData->zlibContext = new ZlibContext;
                loopData->inflationStream = new InflationStream(CompressOptions::DEDICATED_DECOMPRESSOR);
                loopData->deflationStream = new DeflationStream(CompressOptions::DEDICATED_COMPRESSOR);
            }
        }

        /* Copy all handlers */
        webSocketContext->getExt()->openHandler = std::move(behavior.open);
        webSocketContext->getExt()->messageHandler = std::move(behavior.message);
        webSocketContext->getExt()->droppedHandler = std::move(behavior.dropped);
        webSocketContext->getExt()->drainHandler = std::move(behavior.drain);
        webSocketContext->getExt()->subscriptionHandler = std::move(behavior.subscription);
        webSocketContext->getExt()->closeHandler = std::move(behavior.close);
        webSocketContext->getExt()->pingHandler = std::move(behavior.ping);
        webSocketContext->getExt()->pongHandler = std::move(behavior.pong);

        /* Copy settings */
        webSocketContext->getExt()->maxPayloadLength = behavior.maxPayloadLength;
        webSocketContext->getExt()->maxBackpressure = behavior.maxBackpressure;
        webSocketContext->getExt()->closeOnBackpressureLimit = behavior.closeOnBackpressureLimit;
        webSocketContext->getExt()->resetIdleTimeoutOnSend = behavior.resetIdleTimeoutOnSend;
        webSocketContext->getExt()->sendPingsAutomatically = behavior.sendPingsAutomatically;
        webSocketContext->getExt()->maxLifetime = behavior.maxLifetime;
        webSocketContext->getExt()->compression = behavior.compression;

        /* Calculate idleTimeoutCompnents */
        webSocketContext->getExt()->calculateIdleTimeoutCompnents(behavior.idleTimeout);

        return (struct us_socket_context_t *) webSocketContext;
    }

    /* --- Misc --- */

    /* Register event handler for accepted FD. Can be used together with adoptSocket. */
    TemplatedProtocol &&preOpen(LIBUS_SOCKET_DESCRIPTOR (*handler)(struct us_socket_context_t *, LIBUS_SOCKET_DESCRIPTOR)) {
        httpContext->onPreOpen(handler);
        return std::move(*this);
    }

    TemplatedProtocol &&removeChildProtocol(TemplatedProtocol *proto) {
        auto &childApps = httpContext->getSocketContextData()->childApps;
        childApps.erase(
            std::remove(childApps.begin(), childApps.end(), (void *) proto),
            childApps.end()
        );
        httpContext->getSocketContextData()->roundRobin = 0;
        
        return std::move(*this);
    }

    TemplatedProtocol &&addChildProtocol(TemplatedProtocol *proto) {
        httpContext->getSocketContextData()->childApps.push_back((void *) proto);
        
        httpContext->onPreOpen([](struct us_socket_context_t *context, LIBUS_SOCKET_DESCRIPTOR fd) -> LIBUS_SOCKET_DESCRIPTOR {
            
            HttpContext<SSL> *httpContext = (HttpContext<SSL> *) context;

            if (httpContext->getSocketContextData()->childApps.empty()) {
                return fd;
            }

            unsigned int *roundRobin = &httpContext->getSocketContextData()->roundRobin;

            TemplatedProtocol *receivingProto = (TemplatedProtocol *) httpContext->getSocketContextData()->childApps[*roundRobin];

            receivingProto->getLoop()->defer([fd, receivingProto]() {
                receivingProto->adoptSocket(fd);
            });

            if (++(*roundRobin) == httpContext->getSocketContextData()->childApps.size()) {
                *roundRobin = 0;
            }

            return fd + 1;
        });
        return std::move(*this);
    }

    /* adopt an externally accepted socket */
    TemplatedProtocol &&adoptSocket(LIBUS_SOCKET_DESCRIPTOR accepted_fd) {
        httpContext->adoptAcceptedSocket(accepted_fd);
        return std::move(*this);
    }

    TemplatedProtocol &&run() {
        uWS::run();
        return std::move(*this);
    }

    Loop *getLoop() {
        return (Loop *) httpContext->getLoop();
    }

    /* --- Lifecycle --- */

    ~TemplatedProtocol() {
        /* Unbind from app */
        unbind();

        /* Free all our webSocketContexts */
        for (auto &webSocketContextDeleter : webSocketContextDeleters) {
            webSocketContextDeleter();
        }

        /* Free httpContext */
        if (httpContext) {
            httpContext->free();
        }
    }

    TemplatedProtocol(const TemplatedProtocol &other) = delete;

    TemplatedProtocol(TemplatedProtocol &&other) {
        httpContext = other.httpContext;
        other.httpContext = nullptr;

        app = other.app;
        other.app = nullptr;

        sniServerNames = std::move(other.sniServerNames);
        webSocketContextDeleters = std::move(other.webSocketContextDeleters);
        webSocketContexts = std::move(other.webSocketContexts);
    }

    TemplatedProtocol(SocketContextOptions options = {}) {
        httpContext = HttpContext<SSL>::create(Loop::get(), options);
    }

    bool constructorFailed() {
        return !httpContext;
    }

    /* For backward compat: inner WebSocketBehavior type */
    template <typename UserData>
    using WebSocketBehavior = uWS::WebSocketBehavior<SSL, UserData>;
};

}

namespace uWS {
    typedef uWS::TemplatedProtocol<false> HTTPProtocol;
    typedef uWS::TemplatedProtocol<true> SSLProtocol;
}

#endif // UWS_APP_H
