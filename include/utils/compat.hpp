#pragma once
#include <cstdint>
#include <cstddef>
#include <limits>
#include <string_view>
#include <type_traits>
#include <vector>
//---------------------------------------------------------------------------
// AnyBlob - Universal Cloud Object Storage Library
// SingleStore compatibility shim for C++17
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//---------------------------------------------------------------------------

#if __cplusplus >= 202002L || (defined(__has_cpp_attribute) && __has_cpp_attribute(likely))
#define ANYBLOB_LIKELY [[likely]]
#define ANYBLOB_UNLIKELY [[unlikely]]
#else
#define ANYBLOB_LIKELY
#define ANYBLOB_UNLIKELY
#endif

namespace anyblob::compat {
// polyfill for std::span
//
template <typename T>
class Span {
    T* _data;
    std::size_t _size;

    public:
    constexpr Span() : _data(nullptr), _size(0) {}
    constexpr Span(T* data, std::size_t size) : _data(data), _size(size) {}
    template <std::size_t N>
    constexpr Span(T (&arr)[N]) : _data(arr), _size(N) {}
    template <typename Alloc>
    Span(std::vector<T, Alloc>& v) : _data(v.data()), _size(v.size()) {}
    constexpr T* data() const { return _data; }
    constexpr std::size_t size() const { return _size; }
    constexpr bool empty() const { return _size == 0; }
    constexpr T* begin() const { return _data; }
    constexpr T* end() const { return _data + _size; }
    constexpr T& operator[](std::size_t i) const { return _data[i]; }
};

// Polyfill for std::string_view::starts_with 
//
inline bool startsWith(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

// Polyfill for std::in_range<T> 
//
template <typename T, typename U>
constexpr bool inRange(U value) {
    static_assert(std::is_integral_v<T> && std::is_integral_v<U>, "inRange requires integral types");
    if constexpr (std::is_signed_v<T> == std::is_signed_v<U>) {
        return static_cast<U>(std::numeric_limits<T>::min()) <= value &&
               value <= static_cast<U>(std::numeric_limits<T>::max());
    } else if constexpr (std::is_signed_v<T>) {
        // T is signed, U is unsigned
        return value <= static_cast<std::make_unsigned_t<T>>(std::numeric_limits<T>::max());
    } else {
        // T is unsigned, U is signed
        return value >= 0 &&
               static_cast<std::make_unsigned_t<U>>(value) <= std::numeric_limits<T>::max();
    }
}

} // namespace anyblob::compat
