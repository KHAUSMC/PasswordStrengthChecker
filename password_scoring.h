#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint>

namespace pwcheck
{

    enum class Bucket : uint8_t
    {
        Weak = 0,
        Fair = 1,
        Strong = 2,
        VeryStrong = 3
    };

    struct ScoreConfig
    {
        int min_length = 8;
        int max_length_allowed = 512; // accept long passphrases
        int length_cap_points = 60;   // max points contributed by length
        int variety_points = 10;      // max points for character variety
        int pattern_points = 10;      // deducted when patterns are found
        int passphrase_points = 10;   // bonus for uncommon multi-word passphrases
        // Thresholds
        int weak_max = 24;
        int fair_max = 59;
        int strong_max = 79; // 80+ = VeryStrong
    };

    struct ScoreDetail
    {
        int score = 0;
        Bucket bucket = Bucket::Weak;
        std::vector<std::string> reasons; // explanatory messages for users
        bool blocklist_hit = false;
        bool dictionary_hit = false;
    };

    // Primary scoring function. Provide blocklist & dictionary word sets (lowercased).
    ScoreDetail score_password(const std::string &password,
                               const std::unordered_set<std::string> &blocklist,
                               const std::unordered_set<std::string> &dictionary,
                               const ScoreConfig &cfg = ScoreConfig());

    // Utility to convert a numeric score to a bucket using cfg thresholds.
    Bucket bucket_from_score(int score, const ScoreConfig &cfg = ScoreConfig());

    // Optional: minimal heuristics helpers you might expose for testing
    bool looks_like_sequence(const std::string &s);       // "123456", "abcdef"
    bool looks_like_keyboard_walk(const std::string &s);  // "qwerty", "asdf"
    bool looks_like_repeated_chunk(const std::string &s); // "abcabc", "aaaaaa"
    bool contains_year_suffix(const std::string &s);      // "2024", "2025"

} // namespace pwcheck
