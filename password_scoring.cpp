#include "password_scoring.h"
#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace pwcheck
{

    static std::string to_lower(const std::string &s)
    {
        std::string t = s;
        std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c)
                       { return std::tolower(c); });
        return t;
    }

    static bool is_ascii_print(char c)
    {
        return c >= 32 && c <= 126;
    }

    static int char_class_count(const std::string &s)
    {
        // setting boolean = for testing
        bool has_lower = false;
        bool has_upper = false;
        bool has_digit = false;
        bool has_symbol = false;
        bool has_space = false;

        for (unsigned char c : s)
        {
            // checking to see if the it's lower
            if (std::islower(c))
                has_lower = true;
            else if (std::isupper(c))
                has_upper = true;
            else if (std::isdigit(c))
                has_digit = true;
            else if (std::isspace(c))
                has_space = true;
            else if (is_ascii_print(c))
                has_symbol = true;
        }
        int n = 0;
        n += has_lower;
        n += has_upper;
        n += has_digit;
        n += (has_symbol || has_space);
        return n;
    }

    Bucket bucket_from_score(int score, const ScoreConfig &cfg)
    {
        if (score <= cfg.weak_max)
            return Bucket::Weak;
        if (score <= cfg.fair_max)
            return Bucket::Fair;
        if (score <= cfg.strong_max)
            return Bucket::Strong;
        return Bucket::VeryStrong;
    }

    bool looks_like_sequence(const std::string &s)
    {
        if (s.size() < 4)
            return false;
        int deltas[] = {1, -1};
        for (int d : deltas)
        {
            int run = 1;
            for (size_t i = 1; i < s.size(); ++i)
            {
                if ((int)s[i] - (int)s[i - 1] == d)
                {
                    run++;
                    if (run >= 4)
                        return true;
                }
                else
                {
                    run = 1;
                }
            }
        }
        return false;
    }

    bool looks_like_repeated_chunk(const std::string &s)
    {
        const size_t n = s.size();
        for (size_t len = 1; len <= n / 2; ++len)
        {
            if (n % len != 0)
                continue;
            bool ok = true;
            for (size_t i = len; i < n; i += len)
            {
                if (s.compare(0, len, s, i, len) != 0)
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
                return true;
        }
        return false;
    }

    bool looks_like_keyboard_walk(const std::string &s)
    {
        static const std::vector<std::string> rows = {
            "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "1234567890"};
        std::string low = to_lower(s);
        for (const auto &r : rows)
        {
            if (r.find(low) != std::string::npos)
                return true;
            std::string rev = std::string(r.rbegin(), r.rend());
            if (rev.find(low) != std::string::npos)
                return true;
        }
        for (const auto &r : rows)
        {
            int run = 0;
            for (char c : low)
            {
                if (r.find(c) != std::string::npos)
                {
                    run++;
                    if (run >= 4)
                        return true;
                }
                else
                    run = 0;
            }
        }
        return false;
    }

    bool contains_year_suffix(const std::string &s)
    {
        for (size_t i = 0; i + 3 < s.size(); ++i)
        {
            if (std::isdigit(s[i]) && std::isdigit(s[i + 1]) && std::isdigit(s[i + 2]) && std::isdigit(s[i + 3]))
            {
                int y = (s[i] - '0') * 1000 + (s[i + 1] - '0') * 100 + (s[i + 2] - '0') * 10 + (s[i + 3] - '0');
                if (y >= 1990 && y <= 2099)
                    return true;
            }
        }
        return false;
    }

    ScoreDetail score_password(const std::string &password,
                               const std::unordered_set<std::string> &blocklist,
                               const std::unordered_set<std::string> &dictionary,
                               const ScoreConfig &cfg)
    {
        ScoreDetail out;
        const std::string pw = password;
        const std::string low = to_lower(pw);
        const int n = (int)pw.size();

        if (n == 0)
        {
            out.reasons.push_back("Password is empty.");
            out.score = 0;
            out.bucket = Bucket::Weak;
            return out;
        }
        if (n > cfg.max_length_allowed)
        {
            out.reasons.push_back("Password exceeds maximum allowed length.");
        }

        if (blocklist.find(low) != blocklist.end())
        {
            out.blocklist_hit = true;
            out.reasons.push_back("Found in common-passwords list.");
        }
        if (dictionary.find(low) != dictionary.end() && n <= 10)
        {
            out.dictionary_hit = true;
            out.reasons.push_back("Is a common dictionary word.");
        }

        int score = std::min(cfg.length_cap_points, n * 3);

        int classes = char_class_count(pw);
        score += (int)((cfg.variety_points) * (std::max(0, classes - 1)) / 3.0);

        int pattern_deductions = 0;
        if (looks_like_sequence(low))
        {
            out.reasons.push_back("Contains an increasing/decreasing sequence.");
            pattern_deductions += 5;
        }
        if (looks_like_keyboard_walk(low))
        {
            out.reasons.push_back("Contains a keyboard pattern.");
            pattern_deductions += 5;
        }
        if (looks_like_repeated_chunk(low))
        {
            out.reasons.push_back("Contains repeated chunks.");
            pattern_deductions += 5;
        }
        if (contains_year_suffix(pw))
        {
            out.reasons.push_back("Contains a year (predictable).");
            pattern_deductions += 3;
        }
        score -= std::min(cfg.pattern_points, pattern_deductions);

        int wordish = 1;
        for (char c : pw)
            if (c == ' ' || c == '-' || c == '_')
                wordish++;
        if (wordish >= 3 && n >= 16)
        {
            score += cfg.passphrase_points;
            out.reasons.push_back("Looks like a multi-word passphrase (good).");
        }

        if (n < cfg.min_length)
        {
            out.reasons.push_back("Shorter than recommended minimum length.");
            score = std::min(score, cfg.weak_max);
        }

        if (out.blocklist_hit || out.dictionary_hit)
        {
            score = std::min(score, 10);
        }

        score = std::max(0, std::min(100, score));
        out.score = score;
        out.bucket = bucket_from_score(score, cfg);

        if (out.bucket == Bucket::Weak || out.bucket == Bucket::Fair)
        {
            out.reasons.push_back("Try 3–4 uncommon words, avoid years/keyboard runs, and steer clear of known common passwords.");
        }

        return out;
    }

} // namespace pwcheck
