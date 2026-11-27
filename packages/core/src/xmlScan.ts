/**
 * A small, forgiving XML scanner for the dependency files the SCA engine
 * reads (MSBuild project files, `Directory.*.props`, `packages.config`).
 *
 * It is not a conforming XML parser. It builds a tree of elements with their
 * attributes and direct text, and it is built for untrusted input:
 *
 * - one left-to-right pass; every search (`indexOf`) starts after the
 *   previous position, so the work is linear in the input size;
 * - no DTD processing and no entity expansion beyond the five predefined
 *   entities and numeric character references (a DOCTYPE, including an
 *   internal subset, is skipped);
 * - bounded memory: element count, nesting depth, attributes per element and
 *   kept text per element are capped;
 * - it never throws: malformed input yields the elements read so far plus an
 *   `error` describing where reading stopped.
 */

export interface XmlElement {
  /** Element name without a namespace prefix, as written. */
  name: string;
  /** Lower-cased attribute name (prefix stripped) -> decoded value; first wins. */
  attrs: Map<string, string>;
  children: XmlElement[];
  /** Decoded direct text content (CDATA included), capped in length. */
  text: string;
  /** Offset of the `<` that opens the element. */
  offset: number;
}

export interface XmlDocument {
  /** Synthetic root; its children are the top-level elements. */
  root: XmlElement;
  /** Set when the input is malformed or a limit stopped the scan. */
  error?: string;
}

export const XML_LIMITS = {
  maxElements: 200_000,
  maxDepth: 256,
  maxAttributes: 256,
  maxTextPerElement: 4096,
  maxNameLength: 1024,
};

const ENTITY = /&(#x[0-9A-Fa-f]{1,6}|#[0-9]{1,7}|lt|gt|amp|quot|apos);/g;

/** Decode the predefined entities and numeric character references only. */
export function decodeXmlEntities(value: string): string {
  if (!value.includes("&")) return value;
  return value.replace(ENTITY, (whole, body: string) => {
    switch (body) {
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "amp":
        return "&";
      case "quot":
        return '"';
      case "apos":
        return "'";
      default: {
        const code =
          body[1] === "x" || body[1] === "X"
            ? Number.parseInt(body.slice(2), 16)
            : Number.parseInt(body.slice(1), 10);
        if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff) return whole;
        if (code >= 0xd800 && code <= 0xdfff) return whole;
        return String.fromCodePoint(code);
      }
    }
  });
}

function isSpace(code: number): boolean {
  return code === 32 || code === 9 || code === 10 || code === 13;
}

function localName(name: string): string {
  const colon = name.indexOf(":");
  return colon >= 0 ? name.slice(colon + 1) : name;
}

function newElement(name: string, offset: number): XmlElement {
  return { name, attrs: new Map(), children: [], text: "", offset };
}

/** Offset -> 1-based line number, by binary search over newline offsets. */
export function lineLookup(content: string): (offset: number) => number {
  const newlines: number[] = [];
  let index = content.indexOf("\n");
  while (index >= 0) {
    newlines.push(index);
    index = content.indexOf("\n", index + 1);
  }
  return (offset: number): number => {
    let low = 0;
    let high = newlines.length;
    while (low < high) {
      const mid = (low + high) >>> 1;
      if ((newlines[mid] as number) < offset) low = mid + 1;
      else high = mid;
    }
    return low + 1;
  };
}

export function parseXml(content: string): XmlDocument {
  const root = newElement("#document", 0);
  const stack: XmlElement[] = [root];
  // Lower-cased name -> number of open elements with that name, so a stray
  // close tag is rejected in O(1) instead of searching the stack.
  const open = new Map<string, number>();
  const n = content.length;
  let elements = 0;
  let i = content.charCodeAt(0) === 0xfeff ? 1 : 0;

  const top = (): XmlElement => stack[stack.length - 1] as XmlElement;
  const appendText = (raw: string, decode: boolean): void => {
    const element = top();
    const room = XML_LIMITS.maxTextPerElement - element.text.length;
    if (room <= 0 || element === root) return;
    const value = decode ? decodeXmlEntities(raw.slice(0, room + 16)) : raw;
    element.text += value.slice(0, room);
  };
  const fail = (message: string, at: number): XmlDocument => ({
    root,
    error: `${message} at offset ${at}`,
  });

  while (i < n) {
    const lt = content.indexOf("<", i);
    if (lt < 0) {
      appendText(content.slice(i, i + XML_LIMITS.maxTextPerElement + 16), true);
      break;
    }
    if (lt > i) appendText(content.slice(i, Math.min(lt, i + XML_LIMITS.maxTextPerElement + 16)), true);

    if (content.startsWith("<!--", lt)) {
      const end = content.indexOf("-->", lt + 4);
      if (end < 0) return fail("unterminated comment", lt);
      i = end + 3;
      continue;
    }
    if (content.startsWith("<![CDATA[", lt)) {
      const end = content.indexOf("]]>", lt + 9);
      if (end < 0) return fail("unterminated CDATA section", lt);
      appendText(content.slice(lt + 9, Math.min(end, lt + 9 + XML_LIMITS.maxTextPerElement)), false);
      i = end + 3;
      continue;
    }
    if (content.startsWith("<?", lt)) {
      const end = content.indexOf("?>", lt + 2);
      if (end < 0) return fail("unterminated processing instruction", lt);
      i = end + 2;
      continue;
    }
    if (content.startsWith("<!", lt)) {
      // DOCTYPE or another declaration: skipped, never interpreted. An
      // internal subset (`[ ... ]`) may contain `>`, so skip past `]` first.
      // Only look for `[` before that `>`: searching to the end of the input
      // for every declaration would make the scan quadratic.
      const close = content.indexOf(">", lt + 2);
      const limit = close < 0 ? n : close;
      let bracket = -1;
      for (let k = lt + 2; k < limit; k += 1) {
        if (content.charCodeAt(k) === 91 /* [ */) {
          bracket = k;
          break;
        }
      }
      let end = close;
      if (bracket >= 0) {
        const subsetEnd = content.indexOf("]", bracket + 1);
        end = subsetEnd < 0 ? -1 : content.indexOf(">", subsetEnd + 1);
      }
      if (end < 0) return fail("unterminated declaration", lt);
      i = end + 1;
      continue;
    }
    if (content.charCodeAt(lt + 1) === 47 /* / */) {
      const end = content.indexOf(">", lt + 2);
      if (end < 0) return fail("unterminated end tag", lt);
      const name = localName(content.slice(lt + 2, Math.min(end, lt + 2 + XML_LIMITS.maxNameLength)).trim()).toLowerCase();
      i = end + 1;
      if (!open.get(name)) continue; // stray end tag: ignored
      // Close every element up to and including the matching one.
      for (;;) {
        const element = stack.pop() as XmlElement;
        const key = element.name.toLowerCase();
        open.set(key, (open.get(key) ?? 1) - 1);
        if (key === name) break;
      }
      continue;
    }

    // Start tag.
    let p = lt + 1;
    const nameStart = p;
    while (p < n) {
      const code = content.charCodeAt(p);
      if (isSpace(code) || code === 47 || code === 62 || code === 60) break;
      p += 1;
    }
    if (p === nameStart || p - nameStart > XML_LIMITS.maxNameLength) {
      // `<` that does not start a tag (`a < b` in text): keep it as text.
      appendText("<", false);
      i = lt + 1;
      continue;
    }
    const element = newElement(localName(content.slice(nameStart, p)), lt);
    let selfClosing = false;
    let closed = false;
    let attributes = 0;
    while (p < n) {
      const code = content.charCodeAt(p);
      if (isSpace(code)) {
        p += 1;
        continue;
      }
      if (code === 62 /* > */) {
        p += 1;
        closed = true;
        break;
      }
      if (code === 47 /* / */) {
        if (content.charCodeAt(p + 1) === 62) {
          p += 2;
          selfClosing = true;
          closed = true;
          break;
        }
        p += 1;
        continue;
      }
      if (code === 60 /* < */) break; // a new tag starts: this one is broken
      // Attribute name.
      const attrStart = p;
      while (p < n) {
        const c = content.charCodeAt(p);
        if (isSpace(c) || c === 61 || c === 62 || c === 47 || c === 60) break;
        p += 1;
      }
      const attrName = content.slice(attrStart, Math.min(p, attrStart + XML_LIMITS.maxNameLength));
      while (p < n && isSpace(content.charCodeAt(p))) p += 1;
      let value = "";
      if (content.charCodeAt(p) === 61 /* = */) {
        p += 1;
        while (p < n && isSpace(content.charCodeAt(p))) p += 1;
        const quote = content.charCodeAt(p);
        if (quote === 34 || quote === 39) {
          const end = content.indexOf(quote === 34 ? '"' : "'", p + 1);
          if (end < 0) return fail("unterminated attribute value", p);
          value = content.slice(p + 1, end);
          p = end + 1;
        } else {
          const valueStart = p;
          while (p < n) {
            const c = content.charCodeAt(p);
            if (isSpace(c) || c === 62 || c === 60) break;
            p += 1;
          }
          value = content.slice(valueStart, p);
        }
      }
      attributes += 1;
      if (attributes <= XML_LIMITS.maxAttributes && attrName) {
        const key = localName(attrName).toLowerCase();
        if (!element.attrs.has(key)) element.attrs.set(key, decodeXmlEntities(value));
      }
    }
    if (!closed) return fail("unterminated start tag", lt);
    i = p;

    elements += 1;
    if (elements > XML_LIMITS.maxElements) {
      return fail(`more than ${XML_LIMITS.maxElements} elements; the rest was not read`, lt);
    }
    top().children.push(element);
    if (!selfClosing) {
      if (stack.length > XML_LIMITS.maxDepth) {
        return fail(`elements nested deeper than ${XML_LIMITS.maxDepth}`, lt);
      }
      stack.push(element);
      const key = element.name.toLowerCase();
      open.set(key, (open.get(key) ?? 0) + 1);
    }
  }

  if (stack.length > 1) {
    return { root, error: `unclosed element <${top().name}>` };
  }
  return { root };
}
