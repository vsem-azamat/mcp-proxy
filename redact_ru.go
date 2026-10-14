package main

import (
	"regexp"
	"strings"
	"unicode"
)

// Russian-language credential labels, for chats in Russian. Kept out of
// redact.go so the upstream file stays unchanged.

// russianLabelSeparators are the characters that make "label X" an explicit
// "label: X".
const russianLabelSeparators = ":=：—–-"

// russianTechValue matches values that follow "ключ"/"токен" in ordinary talk
// about crypto and keys ("токен ERC-20", "ключ: ED25519", "ключ - 12:30",
// "секрет: 50%") rather than a credential.
var russianTechValue = regexp.MustCompile(`^(?:[A-Z0-9][A-Z0-9-]{1,11}|\d{1,2}:\d{2}|\d{1,5}%?|ssh-[a-z0-9-]+)$`)

func init() {
	// "логин/пароль: admin / Qwerty123" covers the rest of the line. It runs
	// before every other rule, so another finding on the same line cannot
	// split it and leave the password visible.
	pair := &redactionRule{
		kind:      "password",
		re:        regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}_])(логин\s*(?:/|и)\s*пароль)` + zeroWidth + `\s*(?:[:=：]|[—–-])\s*([^\r\n]+)`),
		groups:    []int{2},
		prefilter: []string{"пароль"},
		accept:    russianPairAccept,
	}
	label := &redactionRule{
		// "пароль: X", "пароль от почты: X", "токен — X", "ключ = X",
		// "Пароль:\nX", "пароль Qwerty-123".
		kind: "password",
		re: regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}_])(пароль|пароля|паролем|пароли|токен|токена|ключ|ключа|апи[\s\-]*ключ|секрет|код\s+доступа)` +
			`((?:[ \t]+(?:от|к|для|на|доступа)(?:[ \t]+[^\s:=：—–\-]{1,30}){0,2})?)` + zeroWidth +
			`([ \t]*(?:[:=：]|--?|[—–])(?:[ \t]*\r?\n)?[ \t]*|[ \t]+)` +
			"(?:\"([^\"\\r\\n]+)\"|«([^»\\r\\n]+)»|'([^'\\r\\n]+)'|`([^`\\r\\n]+)`|([^\\s\"«»'`]+))"),
		groups:    []int{4, 5, 6, 7, 8},
		prefilter: []string{"пароль", "парол", "токен", "ключ", "секрет", "код"},
		accept:    russianLabelAccept,
	}
	builtinRedactionRules = append([]*redactionRule{pair}, builtinRedactionRules...)
	builtinRedactionRules = append(builtinRedactionRules, label)
}

func russianPairAccept(text string, _ []int, start, end int) (int, int, string, bool) {
	end = start + len(strings.TrimRight(text[start:end], " \t"))
	value := text[start:end]
	if isPlaceholderValue(value) || onlyCyrillicLetters(value) {
		return 0, 0, "", false
	}
	return start, end, "password", true
}

// russianLabelAccept validates a value after a Russian label. With an explicit
// separator, anything but a placeholder or plain Cyrillic words counts ("токен:
// истёк" is prose). Without one ("пароль Qwerty123"), the value must look like
// a password: no Cyrillic, at least 6 characters, mixed case or letters with
// digits and symbols.
func russianLabelAccept(text string, match []int, start, end int) (int, int, string, bool) {
	label := strings.ToLower(text[match[2]:match[3]])
	qualified := match[5] > match[4]
	separator := text[match[6]:match[7]]
	explicit := strings.ContainsAny(separator, russianLabelSeparators)
	if qualified && !explicit {
		return 0, 0, "", false // "пароль от почты сменили"
	}
	unquoted := match[16] >= 0 && match[16] == start
	if unquoted {
		end = trimTrailingPunctuation(text, start, end)
	}
	value := text[start:end]
	if isPlaceholderValue(value) || onlyCyrillicLetters(value) {
		return 0, 0, "", false
	}
	isPassword := strings.HasPrefix(label, "парол") || strings.HasPrefix(label, "код")
	// A token or key is never a plain word ("токен — Telegram выдаёт").
	if !isPassword && (russianTechValue.MatchString(value) || strings.IndexFunc(value, func(r rune) bool { return !unicode.IsLetter(r) }) < 0) {
		return 0, 0, "", false
	}
	if !explicit && !passwordShaped(value) {
		return 0, 0, "", false
	}
	kind := "secret"
	if isPassword {
		kind = "password"
	}
	return start, end, kind, true
}

func onlyCyrillicLetters(value string) bool {
	for _, r := range value {
		if !unicode.Is(unicode.Cyrillic, r) && r != '-' && r != ' ' && r != ',' && r != '.' {
			return false
		}
	}
	return true
}

func passwordShaped(value string) bool {
	if len([]rune(value)) < 6 {
		return false
	}
	var upper, lower, digit, symbol bool
	for _, r := range value {
		switch {
		case unicode.Is(unicode.Cyrillic, r):
			return false
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbol = true
		}
	}
	return (upper && lower && (digit || symbol)) || (lower && digit && symbol)
}
