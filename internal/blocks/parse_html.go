package blocks

import (
	"strings"

	"golang.org/x/net/html"
)

// ParseHTML accepts a fragment or full HTML document and returns a block
// tree. The parser walks the HTML node graph and maps recognised tags onto
// canonical blocks. Unrecognised tags become raw_html blocks (which are
// passed through bluemonday-equivalent sanitation rules in the caller; the
// parser itself is structural, not security-bearing).
func ParseHTML(src string) *Tree {
	t := MustEmptyTree()
	if strings.TrimSpace(src) == "" {
		return t
	}

	// Wrap in a body so html.Parse always has a root.
	wrapped := "<html><body>" + src + "</body></html>"
	doc, err := html.Parse(strings.NewReader(wrapped))
	if err != nil {
		return t
	}

	body := findFirst(doc, "body")
	if body == nil {
		return t
	}

	for c := body.FirstChild; c != nil; c = c.NextSibling {
		if blk := nodeToBlock(c); blk != nil {
			t.Blocks = append(t.Blocks, *blk)
		}
	}
	return t
}

func nodeToBlock(n *html.Node) *Block {
	if n.Type == html.TextNode {
		text := strings.TrimSpace(n.Data)
		if text == "" {
			return nil
		}
		return &Block{ID: generateBlockID(), Type: TypeParagraph, Text: text}
	}
	if n.Type != html.ElementNode {
		return nil
	}

	switch strings.ToLower(n.Data) {
	case "h1", "h2", "h3", "h4", "h5", "h6":
		lvl := int(n.Data[1] - '0')
		return &Block{
			ID:    generateBlockID(),
			Type:  TypeHeading,
			Attrs: map[string]any{"level": float64(lvl)},
			Text:  textContent(n),
		}
	case "p":
		text := textContent(n)
		if text == "" {
			return nil
		}
		return &Block{ID: generateBlockID(), Type: TypeParagraph, Text: text}
	case "ul":
		items := listItems(n)
		if len(items) == 0 {
			return nil
		}
		return &Block{ID: generateBlockID(), Type: TypeBulletList, Content: items}
	case "ol":
		items := listItems(n)
		if len(items) == 0 {
			return nil
		}
		return &Block{ID: generateBlockID(), Type: TypeOrderedList, Content: items}
	case "table":
		return tableBlock(n)
	case "hr":
		return &Block{ID: generateBlockID(), Type: TypeDivider}
	case "blockquote":
		return &Block{ID: generateBlockID(), Type: TypeQuote, Text: textContent(n)}
	case "pre":
		// Look for inner <code language="x">; otherwise plain code block.
		lang := ""
		if codeEl := findFirst(n, "code"); codeEl != nil {
			for _, a := range codeEl.Attr {
				if a.Key == "class" && strings.HasPrefix(a.Val, "language-") {
					lang = strings.TrimPrefix(a.Val, "language-")
				}
			}
		}
		return &Block{
			ID:    generateBlockID(),
			Type:  TypeCode,
			Attrs: map[string]any{"language": lang},
			Text:  textContent(n),
		}
	case "img":
		var src, alt string
		for _, a := range n.Attr {
			if a.Key == "src" {
				src = a.Val
			}
			if a.Key == "alt" {
				alt = a.Val
			}
		}
		return &Block{
			ID:    generateBlockID(),
			Type:  TypeImage,
			Attrs: map[string]any{"storage_key": src, "alt": alt},
		}
	case "div":
		// Recognise our own page-break marker.
		for _, a := range n.Attr {
			if a.Key == "style" && strings.Contains(a.Val, "page-break-after") {
				return &Block{ID: generateBlockID(), Type: TypePageBreak}
			}
		}
		// Otherwise: walk children; emit each as its own block. If nothing
		// inside, fall through to paragraph fallback.
		text := textContent(n)
		if text == "" {
			return nil
		}
		return &Block{ID: generateBlockID(), Type: TypeParagraph, Text: text}
	}

	// Unknown element: keep its inner text as a paragraph rather than
	// silently dropping it. Authors expect content to survive a round-trip.
	text := textContent(n)
	if text == "" {
		return nil
	}
	return &Block{ID: generateBlockID(), Type: TypeParagraph, Text: text}
}

func listItems(n *html.Node) []Block {
	var out []Block
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && strings.EqualFold(c.Data, "li") {
			out = append(out, Block{
				ID:   generateBlockID(),
				Type: TypeListItem,
				Text: textContent(c),
			})
		}
	}
	return out
}

func tableBlock(n *html.Node) *Block {
	var headers []string
	var rows [][]string

	for tr := range trIter(n) {
		cells, isHeader := rowCells(tr)
		if isHeader && len(headers) == 0 {
			headers = cells
		} else {
			rows = append(rows, cells)
		}
	}
	if len(headers) == 0 && len(rows) > 0 {
		headers = rows[0]
		rows = rows[1:]
	}
	if len(headers) == 0 {
		return nil
	}
	cols := make([]any, len(headers))
	for i, h := range headers {
		cols[i] = h
	}
	return &Block{
		ID:    generateBlockID(),
		Type:  TypeTable,
		Attrs: map[string]any{"columns": cols},
		Rows:  rows,
	}
}

// trIter is a tiny generator that yields every <tr> descendant of n. Go 1.23+.
func trIter(n *html.Node) func(yield func(*html.Node) bool) {
	return func(yield func(*html.Node) bool) {
		var walk func(*html.Node) bool
		walk = func(node *html.Node) bool {
			for c := node.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && strings.EqualFold(c.Data, "tr") {
					if !yield(c) {
						return false
					}
				}
				if !walk(c) {
					return false
				}
			}
			return true
		}
		walk(n)
	}
}

func rowCells(tr *html.Node) (cells []string, isHeader bool) {
	for c := tr.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		switch strings.ToLower(c.Data) {
		case "th":
			isHeader = true
			cells = append(cells, textContent(c))
		case "td":
			cells = append(cells, textContent(c))
		}
	}
	return cells, isHeader
}

func textContent(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
			return
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(strings.Join(strings.Fields(sb.String()), " "))
}

func findFirst(n *html.Node, tag string) *html.Node {
	if n.Type == html.ElementNode && strings.EqualFold(n.Data, tag) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findFirst(c, tag); found != nil {
			return found
		}
	}
	return nil
}
