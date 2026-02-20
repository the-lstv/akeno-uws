#pragma once

#include "akeno/App.h"
#include <string>
#include <string_view>

namespace Akeno {
    std::string escapeString(std::string_view input) {
        std::string output;
        output.reserve(input.size() + 20); // Reserve some extra space to minimize reallocations

        for (char c : input) {
            switch (c) {
                case '"': output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        // Control characters are escaped as \uXXXX
                        char buffer[7];
                        snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                        output += buffer;
                    } else {
                        output += c;
                    }
            }
        }

        return output;
    }

    template <bool SSL>
    void sendJSONError(uWS::HttpResponse<SSL> *res, std::string_view message, int code = 400, std::string_view status = uWS::HTTP_400_BAD_REQUEST) {
        res->writeStatus(status);
        res->writeRaw(
            "Content-Type: application/json\r\n"
            // TODO: Move CORS headers to a better place
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Headers: Authorization,*\r\n"
            "Access-Control-Allow-Methods: GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS\r\n"
        );
        res->end(std::string("{\"error\":\"").append(escapeString(message)).append("\",\"code\":").append(std::to_string(code)).append(",\"success\":false}"));
    }

    // For HTTP/3, we have to use writeHeader instead of writeRaw (because HTTP/3 uses packed headers magic)
    void sendJSONError(uWS::Http3Response *res, std::string_view message, int code = 400, std::string_view status = uWS::HTTP_400_BAD_REQUEST) {
        res->writeStatus(status);
        // TODO: Move CORS headers to a better place
        res->writeHeader("Content-Type", "application/json");
        res->writeHeader("Access-Control-Allow-Origin", "*");
        res->writeHeader("Access-Control-Allow-Headers", "Authorization,*");
        res->writeHeader("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");
        res->end(std::string("{\"error\":\"").append(escapeString(message)).append("\",\"code\":").append(std::to_string(code)).append(",\"success\":false}"));
    }

    template <bool SSL>
    void sendJSON(uWS::HttpResponse<SSL> *res, std::string_view json) {
        res->writeStatus(uWS::HTTP_200_OK);
        res->writeRaw(
            "Content-Type: application/json\r\n"
            // TODO: Move CORS headers to a better place
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Headers: Authorization,*\r\n"
            "Access-Control-Allow-Methods: GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS\r\n"
        );
        res->end(json);
    }

    // For HTTP/3, we have to use writeHeader instead of writeRaw
    void sendJSON(uWS::Http3Response *res, std::string_view json) {
        res->writeStatus(uWS::HTTP_200_OK);
        // TODO: Move CORS headers to a better place
        res->writeHeader("Content-Type", "application/json");
        res->writeHeader("Access-Control-Allow-Origin", "*");
        res->writeHeader("Access-Control-Allow-Headers", "Authorization,*");
        res->writeHeader("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");
        res->end(json);
    }
}