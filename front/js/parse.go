package js

import (
	"strings"
	"unicode/utf8"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

type escapedIdentifier struct{}

// node owns a normalized, position-preserving syntax tree.
// Punctuation preserves operators, holes, and declaration kinds.
type node struct {
	kind, text, field string
	line, col         int
	named             bool
	children          []*node
}

func (n *node) get(field string) *node {
	if n == nil {
		return nil
	}
	for _, c := range n.children {
		if c.field == field {
			return c
		}
	}
	return nil
}

func (n *node) namedChildren() []*node {
	if n == nil {
		return nil
	}
	var out []*node
	for _, c := range n.children {
		if c.named && c.kind != "comment" {
			out = append(out, c)
		}
	}
	return out
}

func (n *node) first() *node {
	for _, c := range n.children {
		if c.named && c.kind != "comment" {
			return c
		}
	}
	return nil
}

func (n *node) operator() string {
	if op := n.get("operator"); op != nil {
		return op.text
	}
	return ""
}

func parse(src string) (root *node, reason string) {
	defer func() {
		if p := recover(); p != nil {
			root = nil
			reason = "JavaScript parser or normalization limit reached"
			if _, ok := p.(escapedIdentifier); ok {
				reason = "escaped JavaScript identifiers are unsupported"
			}
		}
	}()
	if len(src) > maxSourceBytes {
		return nil, "JavaScript source size limit exceeded"
	}
	if !utf8.ValidString(src) {
		return nil, "JavaScript source is not valid UTF-8"
	}
	lang := grammars.JavascriptLanguage()
	if lang == nil {
		return nil, "JavaScript grammar unavailable"
	}
	p := gotreesitter.NewParser(lang)
	// No wall-clock parse deadline: a timed budget would make the result
	// depend on host load rather than on the source (ADR-0012's rationale,
	// applied to every build). Parsing stays bounded by the deterministic
	// source/node/depth limits below plus the parser's own deterministic caps.
	p.SetTimeoutMicros(0)
	tree, err := p.Parse([]byte(src))
	if err != nil {
		return nil, "JavaScript parse failed"
	}
	if tree == nil {
		return nil, "JavaScript parser returned no tree"
	}
	defer tree.Release()
	if tree.ParseStoppedEarly() {
		return nil, "JavaScript parse stopped early"
	}
	r := tree.RootNode()
	if r == nil || r.HasErrorOrMissing() {
		return nil, "JavaScript syntax error or missing syntax"
	}
	remaining := defaultBudget
	var copyNode func(*gotreesitter.Node, int, string) *node
	copyNode = func(n *gotreesitter.Node, depth int, field string) *node {
		remaining--
		if remaining < 0 || depth > maxDepth {
			panic(budgetExhausted{})
		}
		point := n.StartPoint()
		out := &node{
			kind: n.Type(lang), text: src[n.StartByte():n.EndByte()], field: field,
			named: n.IsNamed(), line: int(point.Row) + 1, col: int(point.Column) + 1,
		}
		if strings.Contains(out.kind, "identifier") && strings.Contains(out.text, `\u`) {
			panic(escapedIdentifier{})
		}
		for i := range n.ChildCount() {
			if c := n.Child(i); c != nil {
				out.children = append(out.children, copyNode(c, depth+1, n.FieldNameForChild(i, lang)))
			}
		}
		return out
	}
	return copyNode(r, 0, ""), ""
}
