/*
    Author: Lukas (thelstv)
    Copyright: (c) https://lstv.space

    Last modified: 2026
    License: GPL-3.0
    Version: 2.0.0-cpp
    Description: A routing/matching module for Akeno, allowing to match domains and paths with wildcards and groups.
    Translated from the original JavaScript implementation.

    Warning: this is a prototype implementation and not production-ready code.
*/

#ifndef AKENO_ROUTER_H
#define AKENO_ROUTER_H

#include <algorithm>
#include <cctype>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <limits>

namespace Akeno {

    /* Sentinel value for an empty/invalid handler slot */
    static constexpr uint32_t INVALID_SLOT = std::numeric_limits<uint32_t>::max();

    namespace Internal {
        inline std::string trim_copy(std::string s) {
            auto is_ws = [](unsigned char c) { return std::isspace(c) != 0; };
            while (!s.empty() && is_ws(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
            while (!s.empty() && is_ws(static_cast<unsigned char>(s.back()))) s.pop_back();
            return s;
        }

        inline std::vector<std::string> split(const std::string& input, char delimiter) {
            std::vector<std::string> parts;
            size_t start = 0;
            size_t end = input.find(delimiter);
            while (end != std::string::npos) {
                parts.push_back(input.substr(start, end - start));
                start = end + 1;
                end = input.find(delimiter, start);
            }
            parts.push_back(input.substr(start));
            return parts;
        }

        inline void expandPattern(std::string pattern, std::vector<std::string>& out) {
            size_t searchFrom = 0;
            while (true) {
                size_t group = pattern.find('{', searchFrom);
                if (group == std::string::npos) break;

                const char prevChar = (group > 0? pattern[group - 1]: '\0');
                if (prevChar != '!') {
                    size_t endGroup = pattern.find('}', group);
                    if (endGroup == std::string::npos) {
                        // throw std::runtime_error("Unmatched group in pattern: " + pattern);
                        return;
                    }

                    std::string groupValues = pattern.substr(group + 1, endGroup - group - 1);
                    std::string patternStart = pattern.substr(0, group);
                    std::string patternEnd = pattern.substr(endGroup + 1);

                    for (std::string value : split(groupValues, ',')) {
                        value = trim_copy(std::move(value));
                        std::string nextEnd = patternEnd;

                        if (value.empty() && !patternEnd.empty() && patternEnd.front() == '.') {
                            nextEnd = patternEnd.substr(1);
                        }

                        expandPattern(patternStart + value + nextEnd, out);
                    }
                    return;
                }

                searchFrom = group + 1;
            }

            if (!pattern.empty() && pattern.back() == '/') {
                pattern.pop_back();
            }
            out.push_back(std::move(pattern));
        }

        inline std::vector<std::string_view> splitSegments(std::string_view s, char segmentChar) {
            if (s.empty()) return {std::string_view{}};

            bool hasLeadingSep = (!s.empty() && s.front() == segmentChar);

            std::vector<std::string_view> parts;
            if (!hasLeadingSep) {
                parts.push_back(std::string_view{});
            }

            size_t start = 0;
            while (start <= s.size()) {
                size_t pos = s.find(segmentChar, start);
                if (pos == std::string_view::npos) {
                    parts.push_back(s.substr(start));
                    break;
                }
                parts.push_back(s.substr(start, pos - start));
                start = pos + 1;
                if (start == s.size()) {
                    parts.push_back(std::string_view{});
                    break;
                }
            }
            return parts;
        }

        inline bool containsWildcardOrNegSet(std::string_view p) {
            return (p.find('*') != std::string_view::npos) || (p.find("!{") != std::string_view::npos);
        }
    }

    /* Indexed storage with free-list recycling */
    template <class Handler>
    class HandlerStore {
    public:
        /* Allocate a slot, moving the handler in. Returns the slot index. */
        uint32_t allocate(Handler handler) {
            uint32_t slot;
            if (!freeSlots_.empty()) {
                slot = freeSlots_.back();
                freeSlots_.pop_back();
                handlers_[slot].emplace(std::move(handler));
            } else {
                slot = static_cast<uint32_t>(handlers_.size());
                handlers_.push_back(std::move(handler));
            }
            refCounts_.resize(handlers_.size(), 0);
            refCounts_[slot]++;
            return slot;
        }

        /* Increment reference count for a slot (e.g. when a pattern expands to multiple entries). */
        void addRef(uint32_t slot) {
            if (slot < refCounts_.size()) {
                refCounts_[slot]++;
            }
        }

        /* Decrement reference count; when it reaches zero the handler is destroyed. */
        void release(uint32_t slot) {
            if (slot >= refCounts_.size()) return;
            if (refCounts_[slot] == 0) return;
            if (--refCounts_[slot] == 0) {
                handlers_[slot].reset();
                freeSlots_.push_back(slot);
            }
        }

        const Handler *get(uint32_t slot) const {
            if (slot < handlers_.size() && handlers_[slot].has_value()) {
                return &*handlers_[slot];
            }
            return nullptr;
        }

        Handler *get(uint32_t slot) {
            if (slot < handlers_.size() && handlers_[slot].has_value()) {
                return &*handlers_[slot];
            }
            return nullptr;
        }

        bool compareEqual(uint32_t slotA, uint32_t slotB) const {
            const Handler *a = get(slotA);
            const Handler *b = get(slotB);
            if (!a || !b) return false;
            return *a == *b;
        }

        void clear() {
            handlers_.clear();
            refCounts_.clear();
            freeSlots_.clear();
        }

        size_t size() const { return handlers_.size(); }

    private:
        std::vector<std::optional<Handler>> handlers_;
        std::vector<uint32_t> refCounts_;
        std::vector<uint32_t> freeSlots_;
    };

    template <class Handler>
    struct MatcherOptions {
        bool simpleMatcher = false;
        bool mergeHandlers = false;

        std::function<Handler(const Handler &existing, const Handler &incoming)> mergeFn;
    };

    class WildcardMatcher {
    public:
        explicit WildcardMatcher(char segmentChar = '/')
            : segmentChar_(segmentChar ? segmentChar : '/') {}

        struct Part {
            enum class Type { Literal, Star, DoubleStar, NegSet, Set } type = Type::Literal;
            std::string literal;
            std::unordered_set<std::string> set;

            static Part literalPart(std::string s) {
                Part p;
                p.type = Type::Literal;
                p.literal = std::move(s);
                return p;
            }
            static Part star() {
                Part p;
                p.type = Type::Star;
                return p;
            }
            static Part doubleStar() {
                Part p;
                p.type = Type::DoubleStar;
                return p;
            }
            static Part negSet(std::unordered_set<std::string> s) {
                Part p;
                p.type = Type::NegSet;
                p.set = std::move(s);
                return p;
            }
            static Part posSet(std::unordered_set<std::string> s) {
                Part p;
                p.type = Type::Set;
                p.set = std::move(s);
                return p;
            }
        };

        struct Route {
            std::vector<Part> parts;
            uint32_t handlerSlot = INVALID_SLOT;
            std::string pattern;
            bool hasDoubleStar = false;
        };

        void add(const std::string &pattern, uint32_t handlerSlot) {

            auto raw = Internal::splitSegments(pattern, segmentChar_);
            std::vector<Part> parts;
            parts.reserve(raw.size());

            for (auto sv : raw) {
                std::string seg(sv);
                if (seg == "**") {
                    parts.push_back(Part::doubleStar());
                } else if (seg == "*") {
                    parts.push_back(Part::star());
                } else if (seg.size() > 3 && seg.rfind("!{", 0) == 0 && seg.back() == '}') {
                    std::string inner = seg.substr(2, seg.size() - 3);
                    auto values = Internal::split(inner, ',');
                    std::unordered_set<std::string> set;
                    for (auto &v : values) {
                        v = Internal::trim_copy(std::move(v));
                        if (!v.empty())
                            set.insert(std::move(v));
                    }
                    parts.push_back(Part::negSet(std::move(set)));
                } else {
                    parts.push_back(Part::literalPart(std::move(seg)));
                }
            }

            /* Try to merge into an existing route with the same handler slot */
            for (auto &existing : patterns_) {
                if (existing.handlerSlot != handlerSlot)
                    continue;
                if (existing.parts.size() != parts.size())
                    continue;

                int diffIndex = -1;
                bool canMerge = true;

                for (size_t i = 0; i < parts.size(); i++) {
                    const auto &ep = existing.parts[i];
                    const auto &np = parts[i];

                    auto equalPart = [&](const Part &a, const Part &b) -> bool {
                        if (a.type != b.type)
                            return false;
                        if (a.type == Part::Type::Literal)
                            return a.literal == b.literal;
                        if (a.type == Part::Type::NegSet || a.type == Part::Type::Set)
                            return a.set == b.set;
                        return true;
                    };

                    if (equalPart(ep, np))
                        continue;

                    if (ep.type == Part::Type::Set && np.type == Part::Type::Literal) {
                        if (diffIndex != -1) { canMerge = false; break; }
                        diffIndex = static_cast<int>(i);
                        continue;
                    }

                    if (ep.type == Part::Type::Literal && np.type == Part::Type::Literal) {
                        if (diffIndex != -1) { canMerge = false; break; }
                        diffIndex = static_cast<int>(i);
                        continue;
                    }

                    canMerge = false;
                    break;
                }

                if (canMerge && diffIndex != -1) {
                    auto &ep = existing.parts[static_cast<size_t>(diffIndex)];
                    const auto &np = parts[static_cast<size_t>(diffIndex)];

                    if (ep.type == Part::Type::Set && np.type == Part::Type::Literal) {
                        ep.set.insert(np.literal);
                    } else if (ep.type == Part::Type::Literal && np.type == Part::Type::Literal) {
                        std::unordered_set<std::string> s;
                        s.insert(ep.literal);
                        s.insert(np.literal);
                        ep = Part::posSet(std::move(s));
                    }
                    return;
                }
            }

            bool hasDoubleStar = false;
            for (const auto &p : parts) {
                if (p.type == Part::Type::DoubleStar) {
                    hasDoubleStar = true;
                    break;
                }
            }

            patterns_.push_back(Route{std::move(parts), handlerSlot, pattern, hasDoubleStar});

            std::sort(patterns_.begin(), patterns_.end(),
                      [](const Route &a, const Route &b) { return a.parts.size() > b.parts.size(); });

            indexDirty_ = true;
        }

        /* Remove routes matching a pattern string; returns the set of handler slots that were removed */
        std::vector<uint32_t> removeByPattern(const std::string &pattern) {
            std::vector<uint32_t> removed;
            std::vector<Route> kept;
            kept.reserve(patterns_.size());
            for (auto &r : patterns_) {
                if (r.pattern == pattern) {
                    removed.push_back(r.handlerSlot);
                } else {
                    kept.push_back(std::move(r));
                }
            }
            patterns_ = std::move(kept);
            if (!removed.empty()) indexDirty_ = true;
            return removed;
        }

        uint32_t matchSlot(std::string_view input) const {
            auto path = Internal::splitSegments(input, segmentChar_);

            rebuildIndexIfNeeded();

            for (const auto &group : sizeGroups_) {
                if (group.size > path.size() && !group.hasAnyDoubleStar) {
                    continue;
                }

                const std::string_view firstSeg = path.empty() ? std::string_view{} : path[0];
                auto literalIt = group.literalFirst.find(std::string(firstSeg));
                if (literalIt != group.literalFirst.end()) {
                    for (const Route *routePtr : literalIt->second) {
                        const Route &route = *routePtr;
                        if (route.parts.size() > path.size() && !route.hasDoubleStar)
                            continue;
                        if (matchRoute(route, path))
                            return route.handlerSlot;
                    }
                }

                for (const Route *routePtr : group.nonLiteral) {
                    const Route &route = *routePtr;
                    if (route.parts.size() > path.size() && !route.hasDoubleStar)
                        continue;
                    if (matchRoute(route, path))
                        return route.handlerSlot;
                }
            }

            return INVALID_SLOT;
        }

        bool matchRoute(const Route &route, const std::vector<std::string_view> &path) const {
            const auto &parts = route.parts;

            if (parts.size() == 1) {
                const auto &only = parts[0];
                if (only.type == Part::Type::DoubleStar)
                    return true;
                if (only.type == Part::Type::Star) {
                    if (path.size() == 1 && path[0] != std::string_view{})
                        return true;
                } else if (only.type == Part::Type::Literal) {
                    if (path.size() == 1 && path[0] == only.literal)
                        return true;
                } else if (only.type == Part::Type::NegSet) {
                    if (path.size() == 1 && path[0] != std::string_view{} &&
                        only.set.find(std::string(path[0])) == only.set.end()) {
                        return true;
                    }
                } else if (only.type == Part::Type::Set) {
                    if (path.size() == 1 && only.set.find(std::string(path[0])) != only.set.end()) {
                        return true;
                    }
                }
                return false;
            }

            size_t pi = 0, si = 0;
            int starPi = -1, starSi = -1;

            while (si < path.size()) {
                const Part *part = (pi < parts.size() ? &parts[pi] : nullptr);

                if (pi < parts.size() && part->type == Part::Type::DoubleStar) {
                    starPi = static_cast<int>(pi);
                    starSi = static_cast<int>(si);
                    pi++;
                } else if (pi < parts.size() && part->type == Part::Type::Star) {
                    if (path[si] == std::string_view{})
                        break;
                    pi++;
                    si++;
                } else if (pi < parts.size() &&
                           (part->type == Part::Type::NegSet || part->type == Part::Type::Set)) {
                    if (path[si] == std::string_view{})
                        break;

                    std::string seg(path[si]);
                    if (part->type == Part::Type::NegSet) {
                        if (part->set.find(seg) != part->set.end())
                            break;
                    } else {
                        if (part->set.find(seg) == part->set.end())
                            break;
                    }
                    pi++;
                    si++;
                } else if (pi < parts.size() && part->type == Part::Type::Literal &&
                           path[si] == part->literal) {
                    pi++;
                    si++;
                } else if (starPi != -1) {
                    pi = static_cast<size_t>(starPi + 1);
                    starSi++;
                    si = static_cast<size_t>(starSi);
                } else {
                    break;
                }
            }

            while (pi < parts.size() && parts[pi].type == Part::Type::DoubleStar)
                pi++;

            return (pi == parts.size() && si == path.size());
        }

        void clear() {
            patterns_.clear();
            sizeGroups_.clear();
            indexDirty_ = true;
        }

        const std::vector<Route> &patterns() const { return patterns_; }

    private:
        char segmentChar_;
        std::vector<Route> patterns_;

        struct SizeGroup {
            size_t size = 0;
            bool hasAnyDoubleStar = false;
            std::unordered_map<std::string, std::vector<const Route *>> literalFirst;
            std::vector<const Route *> nonLiteral;
        };

        mutable bool indexDirty_ = true;
        mutable std::vector<SizeGroup> sizeGroups_;

        void rebuildIndexIfNeeded() const {
            if (!indexDirty_)
                return;

            sizeGroups_.clear();
            std::unordered_map<size_t, size_t> sizeToIndex;

            for (const auto &route : patterns_) {
                size_t sz = route.parts.size();
                auto it = sizeToIndex.find(sz);
                if (it == sizeToIndex.end()) {
                    sizeGroups_.push_back(SizeGroup{});
                    sizeGroups_.back().size = sz;
                    sizeToIndex.emplace(sz, sizeGroups_.size() - 1);
                    it = sizeToIndex.find(sz);
                }

                SizeGroup &group = sizeGroups_[it->second];
                if (route.hasDoubleStar)
                    group.hasAnyDoubleStar = true;

                if (!route.parts.empty() && route.parts.front().type == Part::Type::Literal) {
                    group.literalFirst[route.parts.front().literal].push_back(&route);
                } else {
                    group.nonLiteral.push_back(&route);
                }
            }

            std::sort(sizeGroups_.begin(), sizeGroups_.end(),
                      [](const SizeGroup &a, const SizeGroup &b) { return a.size > b.size; });

            indexDirty_ = false;
        }
    };

    class SimpleWildcardMatcher {
    public:
        struct Compiled {
            std::vector<std::string> parts;
            uint32_t handlerSlot = INVALID_SLOT;
            std::string pattern;
            bool hasPrefix = false;
            bool hasSuffix = false;
            std::vector<std::string> nonEmptyParts;
        };

        void add(const std::string &pattern, uint32_t handlerSlot) {

            std::vector<std::string> parts;
            {
                size_t start = 0;
                while (true) {
                    size_t pos = pattern.find('*', start);
                    if (pos == std::string::npos) {
                        parts.push_back(pattern.substr(start));
                        break;
                    }
                    parts.push_back(pattern.substr(start, pos - start));
                    start = pos + 1;
                }
            }

            Compiled c;
            c.parts = std::move(parts);
            c.handlerSlot = handlerSlot;
            c.pattern = pattern;
            c.hasPrefix = !c.parts.empty() && !c.parts.front().empty();
            c.hasSuffix = !c.parts.empty() && !c.parts.back().empty();
            for (const auto &p : c.parts)
                if (!p.empty())
                    c.nonEmptyParts.push_back(p);

            compiled_.push_back(std::move(c));
        }

        /* Remove entries matching a pattern string; returns the set of handler slots that were removed */
        std::vector<uint32_t> removeByPattern(const std::string &pattern) {
            std::vector<uint32_t> removed;
            std::vector<Compiled> kept;
            kept.reserve(compiled_.size());
            for (auto &c : compiled_) {
                if (c.pattern == pattern) {
                    removed.push_back(c.handlerSlot);
                } else {
                    kept.push_back(std::move(c));
                }
            }
            compiled_ = std::move(kept);
            return removed;
        }

        uint32_t matchSlot(std::string_view input) const {

            for (const auto &c : compiled_) {
                if (c.hasPrefix) {
                    if (input.size() < c.parts.front().size())
                        continue;
                    if (input.substr(0, c.parts.front().size()) != c.parts.front())
                        continue;
                }
                if (c.hasSuffix) {
                    if (input.size() < c.parts.back().size())
                        continue;
                    if (input.substr(input.size() - c.parts.back().size()) != c.parts.back())
                        continue;
                }

                if (c.nonEmptyParts.size() <= 2) {
                    return c.handlerSlot;
                }

                size_t pos = c.hasPrefix ? c.parts.front().size() : 0;
                bool failed = false;

                for (size_t i = 1; i + 1 < c.parts.size(); ++i) {
                    if (c.parts[i].empty())
                        continue;
                    auto found = input.find(c.parts[i], pos);
                    if (found == std::string_view::npos) {
                        failed = true;
                        break;
                    }
                    pos = found + c.parts[i].size();
                }

                if (!failed)
                    return c.handlerSlot;
            }

            return INVALID_SLOT;
        }

        void clear() { compiled_.clear(); }

    private:
        std::vector<Compiled> compiled_;
    };

    template <class Handler>
    class Matcher {
    public:
        explicit Matcher(MatcherOptions<Handler> options = {}, char segmentChar = '/')
            : options_(std::move(options)),
              segmentChar_(segmentChar ? segmentChar : '/'),
              wildcards_(segmentChar_) {}

        void add(const std::vector<std::string> &patterns, Handler handler) {
            /* Allocate once, share the slot across all patterns */
            uint32_t slot = store_.allocate(std::move(handler));
            for (size_t i = 0; i < patterns.size(); i++) {
                if (i > 0) store_.addRef(slot);
                addWithSlot(patterns[i], slot);
            }
        }

        void add(std::string pattern, Handler handler) {

            if (!pattern.empty() && pattern.back() == '.') {
                pattern.pop_back();
            }

            if (pattern == "*" || pattern == "**") {
                if (fallbackSlot_ != INVALID_SLOT) {
                    store_.release(fallbackSlot_);
                }
                fallbackSlot_ = store_.allocate(std::move(handler));
                return;
            }

            if (pattern.empty()) {
                return;
            }

            std::vector<std::string> expanded;
            Internal::expandPattern(pattern, expanded);

            if (expanded.empty()) return;

            /* Allocate one slot; add a ref for each additional expanded pattern */
            uint32_t slot = store_.allocate(std::move(handler));
            for (size_t i = 0; i < expanded.size(); i++) {
                if (i > 0) store_.addRef(slot);
                addWithSlot(expanded[i], slot);
            }
        }

        void clear() {
            /* Release all exact-match slots */
            for (auto &[key, slot] : exactSlots_) {
                store_.release(slot);
            }
            exactSlots_.clear();

            /* Wildcard/simple matchers hold slot indices; release them */
            for (const auto &r : wildcards_.patterns()) {
                store_.release(r.handlerSlot);
            }
            wildcards_.clear();

            /* Simple wildcards don't expose patterns(), so we clear and rely on the store */
            simpleWildcards_.clear();

            if (fallbackSlot_ != INVALID_SLOT) {
                store_.release(fallbackSlot_);
                fallbackSlot_ = INVALID_SLOT;
            }

            store_.clear();
        }

        void remove(const std::string &pattern) {
            std::vector<std::string> expanded;
            Internal::expandPattern(pattern, expanded);

            for (const auto &expandedPattern : expanded) {
                /* Remove from exact matches */
                auto it = exactSlots_.find(expandedPattern);
                if (it != exactSlots_.end()) {
                    store_.release(it->second);
                    exactSlots_.erase(it);
                }

                /* Remove from wildcard matchers and release slots */
                if (options_.simpleMatcher) {
                    for (uint32_t slot : simpleWildcards_.removeByPattern(expandedPattern)) {
                        store_.release(slot);
                    }
                } else {
                    for (uint32_t slot : wildcards_.removeByPattern(expandedPattern)) {
                        store_.release(slot);
                    }
                }
            }
        }

        const Handler *match(std::string_view input) const {
            /* 1. Exact match (fast path) */
            if (auto it = exactSlots_.find(input); it != exactSlots_.end()) {
                return store_.get(it->second);
            }

            /* 2. Wildcard match */
            uint32_t slot = INVALID_SLOT;
            if (options_.simpleMatcher) {
                slot = simpleWildcards_.matchSlot(input);
            } else {
                slot = wildcards_.matchSlot(input);
            }
            if (slot != INVALID_SLOT) {
                return store_.get(slot);
            }

            /* 3. Fallback */
            if (fallbackSlot_ != INVALID_SLOT) {
                return store_.get(fallbackSlot_);
            }
            return nullptr;
        }

        Handler *match(std::string_view input) {
            return const_cast<Handler *>(const_cast<const Matcher *>(this)->match(input));
        }

    protected:
        MatcherOptions<Handler> options_;
        char segmentChar_;

        HandlerStore<Handler> store_;
        std::map<std::string, uint32_t, std::less<>> exactSlots_;

        WildcardMatcher wildcards_;
        SimpleWildcardMatcher simpleWildcards_;

        uint32_t fallbackSlot_ = INVALID_SLOT;

    private:
        /* Internal: register an already-allocated slot under a single expanded pattern */
        void addWithSlot(const std::string &expandedPattern, uint32_t slot) {
            if (Internal::containsWildcardOrNegSet(expandedPattern)) {
                if (options_.simpleMatcher) {
                    simpleWildcards_.add(expandedPattern, slot);
                } else {
                    wildcards_.add(expandedPattern, slot);
                }
                return;
            }

            auto it = exactSlots_.find(expandedPattern);
            if (it != exactSlots_.end()) {
                const Handler *existing = store_.get(it->second);
                const Handler *incoming = store_.get(slot);
                if (existing && incoming && !(*existing == *incoming)) {
                    if (options_.mergeHandlers && options_.mergeFn) {
                        Handler merged = options_.mergeFn(*existing, *incoming);
                        store_.release(it->second);
                        store_.release(slot);
                        it->second = store_.allocate(std::move(merged));
                        return;
                    }
                }
                /* Replace: release old slot */
                store_.release(it->second);
            }

            exactSlots_[expandedPattern] = slot;
        }
    };

    template <class Handler>
    class DomainRouter : public Matcher<Handler> {
    public:
        explicit DomainRouter(MatcherOptions<Handler> options = {})
            : Matcher<Handler>(std::move(options), '.') {}
    };

    template <class Handler>
    class PathMatcher : public Matcher<Handler> {
    public:
        explicit PathMatcher(MatcherOptions<Handler> options = {})
            : Matcher<Handler>(std::move(options), '/') {}
    };

    /* Global error page logic, moved from HttpResponseWrapper.h */
    
    static inline constexpr std::string_view kDefaultErrorPageHead =
        "<!DOCTYPE html><html><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><style>"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:2rem;box-sizing:border-box;"
        "background:#fff4f7;color:#90435b;--dark-color:#be7b90;min-height:100vh;min-height:100dvh;display:flex;flex-direction:column;"
        "justify-content:center;align-items:center;text-align:center}"
        "h2{margin:0 0 2rem;font-size:64px;font-weight:600;background:#ffdbe6;padding:8px 30px;border-radius:100px;font-family:monospace}"
        "@media(prefers-color-scheme: dark){body{background:#1b1617;color:#ddb6c2;--dark-color:#726468}h2{background:#292122}}"
        "p{margin:0;color:var(--dark-color)}"
        "hr{border:none;height:1px;background:currentColor;opacity:.2;width:100%;max-width:300px;margin:2rem 0 1rem}"
        "footer{font-size:.9rem;color:var(--dark-color)}a{color:inherit}"
        "</style>";

    static inline constexpr std::string_view kDefaultErrorPageTail =
        "<hr><footer>Powered by <a href=\"https://github.com/the-lstv/akeno\" target=\"_blank\">Akeno/1.6.9-beta</a></footer></html>";

    inline std::string errorPageHead = std::string(kDefaultErrorPageHead);
    inline std::string errorPageTail = std::string(kDefaultErrorPageTail);

    inline std::string defaultErrorMessageForStatus(std::string_view status) {
        if (status.rfind("404", 0) == 0) {
            return "The requested page could not be found on this server.";
        }

        if (status.rfind("200", 0) == 0) {
            return "Wait, what?";
        }

        if (status.rfind("401", 0) == 0) {
            return "You are not authorized to access this page.";
        }

        if (status.rfind("403", 0) == 0) {
            return "You do not have permission to access this page.";
        }

        if (status.rfind("418", 0) == 0) {
            return "The server is a teapot.";
        }

        return "Internal Server Error";
    }

    inline void setDefaultErrorPage(std::string_view html) {
        constexpr std::string_view placeholder = "{{message}}";
        size_t pos = html.find(placeholder);

        std::string_view head = html;
        std::string_view tail = std::string_view();
        if (pos != std::string_view::npos) {
            head = html.substr(0, pos);
            tail = html.substr(pos + placeholder.size());
        }

        errorPageHead.assign(head.data(), head.size());
        errorPageTail.assign(tail.data(), tail.size());
    }

    // If VSCode complains about the concept keyword here, we are compiling with C++20 so it's fine
    // Annoying though
    template <typename Res>
    concept HasCork = requires(Res *res) {
        res->cork([]() {});
    };

    /**
     * Helper logic used by HttpResponseWrapper and HttpContext
     */
    template <typename Res>
    inline void sendErrorPage(Res *res, std::string_view status, std::string_view message = {}, std::string_view title = {}) {
        if (!res) {
            return;
        }

        std::string statusStr(status.empty() ? "500" : std::string(status));
        if (statusStr.empty()) {
            statusStr = "500";
        }

        std::string messageStr;
        if (!message.empty()) {
            messageStr.assign(message.data(), message.size());
        } else {
            messageStr = defaultErrorMessageForStatus(statusStr);
        }

        std::string titleStr;
        if (!title.empty()) {
            titleStr.assign(title.data(), title.size());
        } else {
            titleStr = statusStr.empty() ? "Internal Server Error" : statusStr;
        }

        std::string messageData;
        messageData.reserve(titleStr.size() + messageStr.size() + 20);
        messageData.append("<h2>");
        messageData.append(titleStr);
        messageData.append("</h2><p>");
        messageData.append(messageStr);
        messageData.append("</p>");

        std::string_view headView = errorPageHead;
        std::string_view tailView = errorPageTail;

        if constexpr (!HasCork<Res>) {
            res->writeStatus(statusStr);
            res->writeHeader("Content-Type", "text/html");
            res->write(headView);
            res->write(messageData);
            res->end(tailView);
        } else {
            res->cork([&]() {
                 res->writeStatus(statusStr);
                 res->writeHeader("Content-Type", "text/html");
                 res->write(headView);
                 res->write(messageData);
                 res->end(tailView);
            });
        }
    }
}

#endif