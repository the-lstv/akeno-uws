/*
 * Authored by Alex Hultman, 2018-2026.
 * Intellectual property of third-party.
 *
 * Modified for Akeno: integrated domain routing with SNI fast-path.
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

#ifndef UWS_HTTPCONTEXT_AKENO_H
#define UWS_HTTPCONTEXT_AKENO_H

/* HTTP context with integrated Akeno domain routing and SNI fast-path.
 *
 * Uses HttpContextData<SSL> as socket context ext so that HttpResponse::upgrade()
 * can access isParsingHttp / upgradedWebSocket without modification.
 * The built-in HttpRouter inside HttpContextData is left unused — all routing
 * is handled through the requestHandler callback set via onRequest().
 */

#include "Loop.h"
#include "HttpContextData.h"
#include "HttpResponseData.h"
#include "AsyncSocket.h"
#include "WebSocketData.h"

#include "akeno/DomainHandler.h"

#include <string_view>
#include <iostream>
#include "MoveOnlyFunction.h"

// Akeno domain router
#include "akeno/Router.h"

namespace uWS {
template<bool> struct HttpResponse;
struct App;
template<bool> struct TemplatedProtocol;

template <bool SSL>
struct HttpContext {
    friend struct App;
    template<bool> friend struct TemplatedProtocol;
    template<bool> friend struct HttpResponse;
private:
    HttpContext() = delete;

    static const int HTTP_IDLE_TIMEOUT_S = 10;
    static const int HTTP_RECEIVE_THROUGHPUT_BYTES = 16 * 1024;

    us_loop_t *getLoop() {
        return us_socket_context_loop(SSL, getSocketContext());
    }

    us_socket_context_t *getSocketContext() {
        return (us_socket_context_t *) this;
    }

    static us_socket_context_t *getSocketContext(us_socket_t *s) {
        return (us_socket_context_t *) us_socket_context(SSL, s);
    }

    HttpContextData<SSL> *getSocketContextData() {
        return (HttpContextData<SSL> *) us_socket_context_ext(SSL, getSocketContext());
    }

    static HttpContextData<SSL> *getSocketContextDataS(us_socket_t *s) {
        return (HttpContextData<SSL> *) us_socket_context_ext(SSL, getSocketContext(s));
    }

    HttpContext<SSL> *init() {
        /* Handle socket connections */
        us_socket_context_on_open(SSL, getSocketContext(), [](us_socket_t *s, int, char *, int) {
            us_socket_timeout(SSL, s, HTTP_IDLE_TIMEOUT_S);
            new (us_socket_ext(SSL, s)) HttpResponseData<SSL>;

            HttpContextData<SSL> *httpContextData = getSocketContextDataS(s);
            for (auto &f : httpContextData->filterHandlers) {
                f((HttpResponse<SSL> *) s, 1);
            }
            return s;
        });

        /* Handle socket disconnections */
        us_socket_context_on_close(SSL, getSocketContext(), [](us_socket_t *s, int, void *) {
            HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) us_socket_ext(SSL, s);

            HttpContextData<SSL> *httpContextData = getSocketContextDataS(s);
            for (auto &f : httpContextData->filterHandlers) {
                f((HttpResponse<SSL> *) s, -1);
            }

            if (httpResponseData->onAborted) {
                httpResponseData->onAborted();
            }

            httpResponseData->~HttpResponseData<SSL>();
            return s;
        });

        /* Handle HTTP data streams */
        us_socket_context_on_data(SSL, getSocketContext(), [](us_socket_t *s, char *data, int length) -> us_socket_t * {

            HttpContextData<SSL> *httpContextData = getSocketContextDataS(s);

            if (us_socket_is_shut_down(SSL, (us_socket_t *) s)) {
                return s;
            }

            HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) us_socket_ext(SSL, s);

            ((AsyncSocket<SSL> *) s)->cork();
            httpContextData->isParsingHttp = true;

            void *proxyParser = nullptr;
#ifdef UWS_WITH_PROXY
            proxyParser = &httpResponseData->proxyParser;
#endif

            /* The return value is entirely up to us to interpret. The HttpParser only care for whether the returned value is DIFFERENT or not from passed user */
            auto [err, returnedSocket] = httpResponseData->consumePostPadded(data, (unsigned int) length, s, proxyParser, [httpContextData](void *s, HttpRequest *httpRequest) -> void * {
                /* For every request we reset the timeout and hang until user makes action */
                /* Warning: if we are in shutdown state, resetting the timer is a security issue! */
                us_socket_timeout(SSL, (us_socket_t *) s, 0);

                /* Reset httpResponse */
                HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) us_socket_ext(SSL, (us_socket_t *) s);
                httpResponseData->offset = 0;

                /* Are we not ready for another request yet? Terminate the connection.
                 * Important for denying async pipelining until, if ever, we want to suppot it.
                 * Otherwise requests can get mixed up on the same connection. We still support sync pipelining. */
                if (httpResponseData->state & HttpResponseData<SSL>::HTTP_RESPONSE_PENDING) {
                    us_socket_close(SSL, (us_socket_t *) s, 0, nullptr);
                    return nullptr;
                }

                /* Mark pending request and emit it */
                httpResponseData->state = HttpResponseData<SSL>::HTTP_RESPONSE_PENDING;

                /* Mark this response as connectionClose if ancient or connection: close */
                if (httpRequest->isAncient() || httpRequest->getHeader("connection").length() == 5) {
                    httpResponseData->state |= HttpResponseData<SSL>::HTTP_CONNECTION_CLOSE;
                }

                // I am going to assume this is fine??
                auto *res = (HttpResponse<SSL>*)s;

                std::string_view method = httpRequest->getCaseSensitiveMethod();

                // OPTIONS fast-path
                // IMPORTANT TODO: More flexible CORS handling, though I don't know how to approach this yet.
                if (method == "OPTIONS") {
                    res->writeHeader("Access-Control-Allow-Origin", "*");
                    res->writeHeader("Access-Control-Allow-Methods",
                                    "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD");
                    res->writeHeader("Access-Control-Allow-Headers",
                                    "Content-Type, Authorization");
                    res->writeHeader("Cache-Control", "max-age=1382400");
                    res->writeHeader("Access-Control-Max-Age", "1382400");
                    res->end();
                    return nullptr;
                }

                /* SNI fast-path for SSL: try exact-match us_socket_server_name_userdata first */
                /* This way we can possibly skip standard domain routing */
                /* TODO: Not working yet */
                DomainHandler *sniHandler = nullptr;
                if constexpr (SSL) {
                    void *sniUserdata = us_socket_server_name_userdata(1, (struct us_socket_t *) s);
                    if (sniUserdata) {
                        sniHandler = (DomainHandler *) sniUserdata;
                    }
                }

                // TODO: h3 handling (:authority)
                // It's separated in Http3Context, so ill decide how to handle both later
                std::string_view host = httpRequest->getHeader("host");
                std::string_view domain = host;
                std::string_view url = httpRequest->getUrl();

                /* Extract domain from host (strip port) */
                if (!host.empty()) {
                    if (host.front() == '[') { // IPv6 literal
                        auto end = host.find(']');
                        if (end != std::string_view::npos)
                            domain = host.substr(1, end - 1);
                    } else {
                        // www redirect fast-path
                        // TODO: Set from config
                        if (host.length() > 4 && host.starts_with("www.")) { // If it's exactly "www.", we let it pass
                            res->writeStatus("301 Moved Permanently");

                            std::string location;
                            location.reserve(8 + host.size() + url.size());
                            location += SSL ? "https://" : "http://";
                            location.append(host.data() + 4, host.size() - 4);
                            location += url;

                            res->writeHeader("Location", location);
                            res->end();
                            return nullptr;
                        }

                        auto first = host.find(':');
                        if (first != std::string_view::npos && first == host.rfind(':')) {
                            domain = host.substr(0, first);
                        }
                    }
                }

                // std::cout << "Received request for domain: " << domain << " with path: " << url << std::endl;

                /* Route via domain router (fallback from SNI or for non-SSL) */
                /* This is always the case for wildcards */
                DomainHandler *domainMatch = sniHandler;

                if (!domainMatch && httpContextData->domainRouter) {
                    domainMatch = ((Akeno::DomainRouter<DomainHandler> *) httpContextData->domainRouter)->match(domain);
                }

                if (!domainMatch) {
                    // No route found for domain
                    Akeno::sendErrorPage(res, "404");
                    return nullptr;
                }

                // Recursively resolve path matchers
                DomainHandler *resolved = domainMatch->kind == DomainHandler::Kind::PathMatcher? resolveDomainHandler(domainMatch, url): domainMatch;
                if (!resolved) {
                    // TODO: Helper for an user-provided 404 within an App context
                    // Though this is low priority as users can just define it themselves
                    Akeno::sendErrorPage(res, "404");
                    return nullptr;
                }

                if (resolved->kind == DomainHandler::Kind::Callback && resolved->hasCallback<SSL>()) {
                    resolved->invokeCallback<SSL>((HttpResponse<SSL> *) res, httpRequest);
                } else {
                    if (resolved->kind == DomainHandler::Kind::StaticBuffer && resolved->staticBuffer) {
                        res->end(std::string_view(resolved->staticBuffer->data(), resolved->staticBuffer->size()));
                        return nullptr;
                    }                    
                }

                if (httpContextData->upgradedWebSocket || us_socket_is_closed(SSL, (struct us_socket_t *) s) || us_socket_is_shut_down(SSL, (us_socket_t *) s)) {
                    return nullptr;
                }
                
                if (!((HttpResponse<SSL> *) s)->hasResponded() && !httpResponseData->onAborted) {
                    std::cerr << "Error: Returning from a request handler without responding or attaching an abort handler is forbidden!"
                              << std::endl
                              << "\tMethod: \"" << httpRequest->getCaseSensitiveMethod() << "\"" << std::endl
                              << "\tURL: \"" << httpRequest->getUrl() << "\"" << std::endl;
                    std::terminate();
                }

                if (!((HttpResponse<SSL> *) s)->hasResponded() && httpResponseData->inStream) {
                    us_socket_timeout(SSL, (us_socket_t *) s, HTTP_IDLE_TIMEOUT_S);
                }

                return s;

            }, [httpResponseData](void *user, std::string_view data, bool fin) -> void * {
                if (httpResponseData->inStream) {
                    if (fin) {
                        us_socket_timeout(SSL, (struct us_socket_t *) user, 0);
                    } else {
                        httpResponseData->received_bytes_per_timeout += (unsigned int) data.length();
                        if (httpResponseData->received_bytes_per_timeout >= HTTP_RECEIVE_THROUGHPUT_BYTES * HTTP_IDLE_TIMEOUT_S) {
                            us_socket_timeout(SSL, (struct us_socket_t *) user, HTTP_IDLE_TIMEOUT_S);
                            httpResponseData->received_bytes_per_timeout = 0;
                        }
                    }

                    httpResponseData->inStream(data, fin);

                    if (us_socket_is_closed(SSL, (struct us_socket_t *) user)) {
                        return nullptr;
                    }

                    if (us_socket_is_shut_down(SSL, (us_socket_t *) user)) {
                        return nullptr;
                    }

                    if (fin) {
                        httpResponseData->inStream = nullptr;
                    }
                }
                return user;
            });

            httpContextData->isParsingHttp = false;

            if (returnedSocket == FULLPTR) {
                us_socket_write(SSL, s, httpErrorResponses[err].data(), (int) httpErrorResponses[err].length(), false);
                us_socket_shutdown(SSL, s);
                us_socket_close(SSL, s, 0, nullptr);
                returnedSocket = nullptr;
            }

            if (returnedSocket != nullptr) {
                auto [written, failed] = ((AsyncSocket<SSL> *) returnedSocket)->uncork();
                if (failed) {
                    ((AsyncSocket<SSL> *) s)->timeout(HTTP_IDLE_TIMEOUT_S);
                }

                if (httpResponseData->state & HttpResponseData<SSL>::HTTP_CONNECTION_CLOSE) {
                    if ((httpResponseData->state & HttpResponseData<SSL>::HTTP_RESPONSE_PENDING) == 0) {
                        if (((AsyncSocket<SSL> *) s)->getBufferedAmount() == 0) {
                            ((AsyncSocket<SSL> *) s)->shutdown();
                            ((AsyncSocket<SSL> *) s)->close();
                        }
                    }
                }

                return (us_socket_t *) returnedSocket;
            }

            if (httpContextData->upgradedWebSocket) {
                AsyncSocket<SSL> *asyncSocket = (AsyncSocket<SSL> *) httpContextData->upgradedWebSocket;
                auto [written, failed] = asyncSocket->uncork();

                if (!failed) {
                    WebSocketData *webSocketData = (WebSocketData *) asyncSocket->getAsyncSocketData();
                    if (webSocketData->isShuttingDown) {
                        asyncSocket->shutdown();
                    }
                }

                httpContextData->upgradedWebSocket = nullptr;
                return (us_socket_t *) asyncSocket;
            }

            ((AsyncSocket<SSL> *) s)->uncork();
            return s;
        });

        /* Handle HTTP write out */
        us_socket_context_on_writable(SSL, getSocketContext(), [](us_socket_t *s) {

            AsyncSocket<SSL> *asyncSocket = (AsyncSocket<SSL> *) s;
            HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) asyncSocket->getAsyncSocketData();

            if (httpResponseData->onWritable) {
                us_socket_timeout(SSL, s, 0);
                bool success = httpResponseData->callOnWritable(httpResponseData->offset);
                if (!success) {
                    return s;
                }
                return s;
            }

            asyncSocket->write(nullptr, 0, true, 0);

            if (httpResponseData->state & HttpResponseData<SSL>::HTTP_CONNECTION_CLOSE) {
                if ((httpResponseData->state & HttpResponseData<SSL>::HTTP_RESPONSE_PENDING) == 0) {
                    if (asyncSocket->getBufferedAmount() == 0) {
                        asyncSocket->shutdown();
                        asyncSocket->close();
                    }
                }
            }

            asyncSocket->timeout(HTTP_IDLE_TIMEOUT_S);
            return s;
        });

        /* Handle FIN */
        us_socket_context_on_end(SSL, getSocketContext(), [](us_socket_t *s) {
            AsyncSocket<SSL> *asyncSocket = (AsyncSocket<SSL> *) s;
            return asyncSocket->close();
        });

        /* Handle socket timeouts */
        us_socket_context_on_timeout(SSL, getSocketContext(), [](us_socket_t *s) {
            AsyncSocket<SSL> *asyncSocket = (AsyncSocket<SSL> *) s;
            return asyncSocket->close();
        });

        return this;
    }

public:
    /* Construct a new HttpContext using specified loop */
    static HttpContext *create(Loop *loop, us_socket_context_options_t options = {}) {
        HttpContext *httpContext;

        httpContext = (HttpContext *) us_create_socket_context(SSL, (us_loop_t *) loop, sizeof(HttpContextData<SSL>), options);

        if (!httpContext) {
            return nullptr;
        }

        new ((HttpContextData<SSL> *) us_socket_context_ext(SSL, (us_socket_context_t *) httpContext)) HttpContextData<SSL>();
        return httpContext->init();
    }

    void free() {
        HttpContextData<SSL> *httpContextData = getSocketContextData();
        httpContextData->~HttpContextData<SSL>();
        us_socket_context_free(SSL, getSocketContext());
    }

    void filter(MoveOnlyFunction<void(HttpResponse<SSL> *, int)> &&filterHandler) {
        getSocketContextData()->filterHandlers.emplace_back(std::move(filterHandler));
    }

    /* Set the request handler — called for every incoming HTTP request.
     * Return true if handled, false to close the connection. */
    void onRequest(MoveOnlyFunction<bool(HttpResponse<SSL> *, HttpRequest *)> &&handler) {
        getSocketContextData()->requestHandler = std::move(handler);
    }

    us_listen_socket_t *listen(const char *host, int port, int options) {
        return us_socket_context_listen(SSL, getSocketContext(), host, port, options, sizeof(HttpResponseData<SSL>));
    }

    us_listen_socket_t *listen(const char *path, int options) {
        return us_socket_context_listen_unix(SSL, getSocketContext(), path, options, sizeof(HttpResponseData<SSL>));
    }

    void onPreOpen(LIBUS_SOCKET_DESCRIPTOR (*handler)(struct us_socket_context_t *, LIBUS_SOCKET_DESCRIPTOR)) {
        us_socket_context_on_pre_open(SSL, getSocketContext(), handler);
    }

    us_socket_t *adoptAcceptedSocket(LIBUS_SOCKET_DESCRIPTOR accepted_fd) {
        return us_adopt_accepted_socket(SSL, getSocketContext(), accepted_fd, sizeof(HttpResponseData<SSL>), 0, 0);
    }
};

}

#endif // UWS_HTTPCONTEXT_AKENO_H
