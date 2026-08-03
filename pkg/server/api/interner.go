package api

import "strings"

// StringInterner collapses repeated strings onto a single shared copy.
//
// It exists for bulk conversions, where the same trust domain and parent path
// repeat across every entry, and where the converted entries are retained for
// the lifetime of a cache. Interning drops the duplicate copies and releases
// the datastore rows they were sliced from.
//
// Interning is only worth its map lookups for strings whose bytes dominate
// what is retained. Selector types, for instance, measured as pure overhead:
// the per-selector cost is the string header, which interning cannot remove.
//
// A StringInterner is not safe for concurrent use. Give each worker its own.
type StringInterner struct {
	strings map[string]string
}

func NewStringInterner() *StringInterner {
	return &StringInterner{strings: make(map[string]string)}
}

// Intern returns a copy of s that is shared with every previous and future
// Intern of an equal string. A nil interner returns s untouched, so callers
// can treat interning as optional.
func (i *StringInterner) Intern(s string) string {
	if i == nil || s == "" {
		return s
	}
	if interned, ok := i.strings[s]; ok {
		return interned
	}
	// s may be a substring of a much larger string, which it would otherwise
	// keep alive for as long as the interner holds it.
	interned := strings.Clone(s)
	i.strings[interned] = interned
	return interned
}
