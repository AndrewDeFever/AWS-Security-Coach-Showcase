export type Rgb = readonly [number, number, number];

type FontName = "regular" | "bold" | "mono";
type TextOptions = { font?: FontName; size?: number; color?: Rgb; lineHeight?: number; maxWidth?: number };
type PdfLink = { x: number; top: number; width: number; height: number; url: string };
type PdfPage = { commands: string[]; links: PdfLink[] };

const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
export const MARGIN_X = 54;
const TOP = 50;
const BOTTOM = 52;
export const CONTENT_WIDTH = PAGE_WIDTH - MARGIN_X * 2;
const NAVY: Rgb = [0.04, 0.10, 0.20];
export const BLUE: Rgb = [0.10, 0.32, 0.80];
export const SLATE: Rgb = [0.26, 0.32, 0.40];
const BORDER: Rgb = [0.84, 0.88, 0.92];
const GREEN: Rgb = [0.05, 0.45, 0.24];
const RED: Rgb = [0.72, 0.12, 0.15];
const ORANGE: Rgb = [0.76, 0.34, 0.03];
const WHITE: Rgb = [1, 1, 1];
const MUTED_LIGHT: Rgb = [0.67, 0.75, 0.84];
const BLUE_TINT: Rgb = [0.95, 0.97, 1];
const GREEN_TINT: Rgb = [0.95, 0.985, 0.965];
const ORANGE_TINT: Rgb = [0.995, 0.97, 0.93];
const RED_TINT: Rgb = [1, 0.95, 0.95];
const BLOCK_GAP = 6;

export function sanitizePdfText(value: string): string {
  return value
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\u2192/g, "->")
    .replace(/\u2265/g, ">=")
    .replace(/\u2264/g, "<=")
    .replace(/\u2022/g, "-")
    .replace(/\u00A0/g, " ")
    .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "?");
}

function pdfString(value: string): string {
  return sanitizePdfText(value).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

function color(value: Rgb): string { return `${value[0]} ${value[1]} ${value[2]}`; }

function estimatedWidth(value: string, size: number, font: FontName): number {
  const factor = font === "mono" ? 0.6 : font === "bold" ? 0.54 : 0.5;
  return sanitizePdfText(value).length * size * factor;
}

function wrapText(value: string, maxWidth: number, size: number, font: FontName): string[] {
  const text = sanitizePdfText(value).trim();
  if (!text) return [""];
  const output: string[] = [];
  for (const paragraph of text.split(/\n/)) {
    if (!paragraph.trim()) {
      output.push("");
      continue;
    }
    const words = paragraph.split(/\s+/).filter(Boolean);
    let line = "";
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word;
      if (estimatedWidth(candidate, size, font) <= maxWidth) {
        line = candidate;
        continue;
      }
      if (line) output.push(line);
      if (estimatedWidth(word, size, font) <= maxWidth) {
        line = word;
        continue;
      }
      let chunk = "";
      for (const char of word) {
        const next = chunk + char;
        if (estimatedWidth(next, size, font) > maxWidth && chunk) {
          output.push(chunk);
          chunk = char;
        } else chunk = next;
      }
      line = chunk;
    }
    if (line) output.push(line);
  }
  return output.length ? output : [""];
}

export class PdfBuilder {
  private pages: PdfPage[] = [];
  private page: PdfPage;
  private y = TOP;
  private readonly title: string;
  private readonly subject: string;

  constructor(title: string, subject: string) {
    this.title = title;
    this.subject = subject;
    this.page = this.addPage();
  }

  private addPage(): PdfPage {
    const page: PdfPage = { commands: [], links: [] };
    this.pages.push(page);
    this.page = page;
    this.y = TOP;
    return page;
  }

  newPage(): void { this.addPage(); }

  private ensure(height: number): void {
    if (this.y + height > PAGE_HEIGHT - BOTTOM) this.addPage();
  }

  ensureSpace(height: number): void { this.ensure(height); }
  advance(height: number): void { this.y += height; }

  private rawText(x: number, y: number, value: string, font: FontName, size: number, textColor: Rgb): void {
    const fontKey = font === "bold" ? "F2" : font === "mono" ? "F3" : "F1";
    const baseline = PAGE_HEIGHT - y;
    this.page.commands.push(`BT /${fontKey} ${size} Tf ${color(textColor)} rg 1 0 0 1 ${x.toFixed(2)} ${baseline.toFixed(2)} Tm (${pdfString(value)}) Tj ET`);
  }

  private registerLink(x: number, top: number, width: number, height: number, url: string): void {
    this.page.links.push({ x, top, width: Math.max(width, 8), height, url });
  }

  text(value: string, x = MARGIN_X, options: TextOptions = {}): number {
    const font = options.font ?? "regular";
    const size = options.size ?? 10.25;
    const textColor = options.color ?? SLATE;
    const maxWidth = options.maxWidth ?? CONTENT_WIDTH;
    const lineHeight = options.lineHeight ?? size * 1.42;
    const lines = wrapText(value, maxWidth, size, font);
    const height = lines.length * lineHeight;
    this.ensure(height);
    for (const line of lines) {
      this.rawText(x, this.y + size, line, font, size, textColor);
      this.y += lineHeight;
    }
    return height;
  }

  linkText(value: string, url: string, x = MARGIN_X, options: TextOptions = {}): number {
    if (value === url) return 0;
    const font = options.font ?? "regular";
    const size = options.size ?? 9.4;
    const textColor = options.color ?? BLUE;
    const maxWidth = options.maxWidth ?? CONTENT_WIDTH;
    const lineHeight = options.lineHeight ?? size * 1.38;
    const lines = wrapText(value, maxWidth, size, font);
    const height = lines.length * lineHeight;
    this.ensure(height);
    for (const line of lines) {
      const top = this.y;
      this.rawText(x, this.y + size, line, font, size, textColor);
      this.registerLink(x, top, Math.min(maxWidth, estimatedWidth(line, size, font) + 3), lineHeight, url);
      this.y += lineHeight;
    }
    return height;
  }

  spacer(height: number): void { this.ensure(height); this.y += height; }

  rule(textColor: Rgb = BORDER): void {
    this.ensure(10);
    const py = PAGE_HEIGHT - this.y;
    this.page.commands.push(`${color(textColor)} RG 0.7 w ${MARGIN_X} ${py.toFixed(2)} m ${(PAGE_WIDTH - MARGIN_X).toFixed(2)} ${py.toFixed(2)} l S`);
    this.y += 10;
  }

  rect(x: number, top: number, width: number, height: number, fill: Rgb, stroke?: Rgb): void {
    const bottom = PAGE_HEIGHT - top - height;
    const strokePart = stroke ? `${color(stroke)} RG 0.7 w` : "";
    const op = stroke ? "B" : "f";
    this.page.commands.push(`q ${color(fill)} rg ${strokePart} ${x.toFixed(2)} ${bottom.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re ${op} Q`);
  }

  heading(value: string, size = 17): void {
    const lines = wrapText(value, CONTENT_WIDTH, size, "bold");
    this.ensure(lines.length * size * 1.3 + 8);
    for (const line of lines) {
      this.rawText(MARGIN_X, this.y + size, line, "bold", size, NAVY);
      this.y += size * 1.3;
    }
    this.y += 4;
  }

  kicker(value: string): void {
    this.text(value.toUpperCase(), MARGIN_X, { font: "bold", size: 7.8, color: BLUE, lineHeight: 10.5 });
  }

  labelValue(label: string, value: string, x: number, width: number): number {
    const labelLines = wrapText(label.toUpperCase(), width, 7, "bold");
    const valueLines = wrapText(value, width, 10.5, "bold");
    const height = labelLines.length * 9 + valueLines.length * 13 + 10;
    let localY = this.y;
    for (const line of labelLines) { this.rawText(x, localY + 7, line, "bold", 7, MUTED_LIGHT); localY += 9; }
    localY += 2;
    for (const line of valueLines) { this.rawText(x, localY + 10.5, line, "bold", 10.5, WHITE); localY += 13; }
    return height;
  }

  metrics(items: Array<{ label: string; value: string; tone?: "clean"|"attention"|"neutral" }>): void {
    if (!items.length) return;
    const preferredColumns = items.length === 4 ? 2 : Math.min(3, items.length);
    let offset = 0;
    while (offset < items.length) {
      const rowItems = items.slice(offset, offset + preferredColumns);
      const gap = 10;
      const width = (CONTENT_WIDTH - gap * (rowItems.length - 1)) / rowItems.length;
      const heights = rowItems.map(item => Math.max(66, wrapText(item.label.toUpperCase(), width - 22, 7, "bold").length * 9 + 34));
      const height = Math.max(...heights);
      this.ensure(height + 10);
      rowItems.forEach((item, index) => {
        const x = MARGIN_X + index * (width + gap);
        const tone = item.tone === "attention" ? RED : item.tone === "clean" ? GREEN : BLUE;
        this.rect(x, this.y, width, height, WHITE, BORDER);
        const labels = wrapText(item.label.toUpperCase(), width - 22, 7, "bold");
        let ly = this.y + 13;
        labels.forEach(line => { this.rawText(x + 11, ly + 7, line, "bold", 7, SLATE); ly += 9; });
        this.rawText(x + 11, this.y + height - 15, item.value, "bold", 20, tone);
      });
      this.y += height + 10;
      offset += preferredColumns;
    }
  }

  callout(title: string, body: string, tone: "blue"|"green"|"orange"|"red" = "blue"): void {
    const bodyLines = wrapText(body, CONTENT_WIDTH - 34, 10, "regular");
    const titleLines = wrapText(title, CONTENT_WIDTH - 34, 11, "bold");
    const height = 18 + titleLines.length * 14 + bodyLines.length * 14.5 + 13;
    this.ensure(height + BLOCK_GAP);
    const accent = tone === "green" ? GREEN : tone === "orange" ? ORANGE : tone === "red" ? RED : BLUE;
    const fill = tone === "green" ? GREEN_TINT : tone === "orange" ? ORANGE_TINT : tone === "red" ? RED_TINT : BLUE_TINT;
    this.rect(MARGIN_X, this.y, CONTENT_WIDTH, height, fill, BORDER);
    this.rect(MARGIN_X, this.y, 4, height, accent);
    let ly = this.y + 14;
    titleLines.forEach(line => { this.rawText(MARGIN_X + 16, ly + 10, line, "bold", 11, NAVY); ly += 14; });
    ly += 4;
    bodyLines.forEach(line => { this.rawText(MARGIN_X + 16, ly + 9.5, line, "regular", 10, SLATE); ly += 14.5; });
    this.y += height + BLOCK_GAP;
  }

  section(title: string, body?: string): void {
    this.ensure(32);
    this.rawText(MARGIN_X, this.y + 8.5, title.toUpperCase(), "bold", 8.5, BLUE);
    this.y += 15;
    if (body) {
      this.text(body, MARGIN_X, { size: 10.25, lineHeight: 14.5 });
      this.y += BLOCK_GAP;
    }
  }

  labeledParagraph(label: string, body: string): void {
    this.ensure(40);
    this.rawText(MARGIN_X, this.y + 9.5, label, "bold", 10.5, NAVY);
    this.y += 14;
    this.text(body, MARGIN_X, { size: 10.25, lineHeight: 14.5 });
    this.y += BLOCK_GAP;
  }

  bulletList(items: string[]): void {
    for (const item of items) {
      const size = 10;
      const lines = wrapText(item, CONTENT_WIDTH - 24, size, "regular");
      const height = lines.length * 14.5 + 5;
      this.ensure(height);
      this.rawText(MARGIN_X + 2, this.y + size, "-", "bold", size, BLUE);
      let ly = this.y;
      lines.forEach(line => { this.rawText(MARGIN_X + 20, ly + size, line, "regular", size, SLATE); ly += 14.5; });
      this.y += height;
    }
  }

  numberedList(items: string[]): void {
    items.forEach((item, index) => {
      const prefix = `${index + 1}.`;
      const size = 10;
      const lines = wrapText(item, CONTENT_WIDTH - 34, size, "regular");
      const height = lines.length * 14.5 + 6;
      this.ensure(height);
      this.rawText(MARGIN_X, this.y + size, prefix, "bold", size, BLUE);
      let ly = this.y;
      lines.forEach(line => { this.rawText(MARGIN_X + 29, ly + size, line, "regular", size, SLATE); ly += 14.5; });
      this.y += height;
    });
  }

  codeBlock(label: string, command: string): void {
    const labelLines = wrapText(label, CONTENT_WIDTH - 28, 8.5, "bold");
    const commandLines = wrapText(command, CONTENT_WIDTH - 28, 8.2, "mono");
    const height = 15 + labelLines.length * 11 + commandLines.length * 11 + 13;
    this.ensure(height + BLOCK_GAP);
    this.rect(MARGIN_X, this.y, CONTENT_WIDTH, height, NAVY);
    let ly = this.y + 12;
    labelLines.forEach(line => { this.rawText(MARGIN_X + 14, ly + 8.5, line, "bold", 8.5, [0.80, 0.84, 0.90]); ly += 11; });
    ly += 5;
    commandLines.forEach(line => { this.rawText(MARGIN_X + 14, ly + 8.2, line, "mono", 8.2, WHITE); ly += 11; });
    this.y += height + BLOCK_GAP;
  }

  reference(title: string, url: string): void {
    this.ensure(40);
    this.rawText(MARGIN_X, this.y + 8.5, "OFFICIAL AWS GUIDANCE", "bold", 8.5, BLUE);
    this.y += 15;
    this.linkText(title, url, MARGIN_X, { font: "bold", size: 10, color: BLUE, lineHeight: 13.5 });
    this.y += BLOCK_GAP;
  }

  footerPageNumbers(): void {
    const count = this.pages.length;
    this.pages.forEach((page, index) => {
      const text = `AWS Security Posture Review  |  Page ${index + 1} of ${count}`;
      const baseline = PAGE_HEIGHT - (PAGE_HEIGHT - 24);
      page.commands.push(`BT /F1 7.2 Tf ${color(SLATE)} rg 1 0 0 1 ${MARGIN_X} ${baseline.toFixed(2)} Tm (${pdfString(text)}) Tj ET`);
    });
  }

  bytes(): Uint8Array {
    this.footerPageNumbers();
    const objects: string[] = [""];
    const reserve = () => { objects.push(""); return objects.length - 1; };
    const set = (id: number, value: string) => { objects[id] = value; };
    const add = (value: string) => { objects.push(value); return objects.length - 1; };

    const catalogId = reserve();
    const pagesId = reserve();
    const fontRegularId = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    const fontBoldId = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
    const fontMonoId = add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>");
    const infoId = add(`<< /Title (${pdfString(this.title)}) /Subject (${pdfString(this.subject)}) /Creator (AWS Security Posture Review) >>`);

    const pageIds: number[] = [];
    for (const page of this.pages) {
      const stream = `${page.commands.join("\n")}\n`;
      const contentId = add(`<< /Length ${stream.length} >>\nstream\n${stream}endstream`);
      const annotationIds = page.links.map(link => {
        const x1 = link.x;
        const x2 = link.x + link.width;
        const y1 = PAGE_HEIGHT - (link.top + link.height);
        const y2 = PAGE_HEIGHT - link.top;
        return add(`<< /Type /Annot /Subtype /Link /Rect [${x1.toFixed(2)} ${y1.toFixed(2)} ${x2.toFixed(2)} ${y2.toFixed(2)}] /Border [0 0 0] /A << /S /URI /URI (${pdfString(link.url)}) >> >>`);
      });
      const annots = annotationIds.length ? ` /Annots [${annotationIds.map(id => `${id} 0 R`).join(" ")}]` : "";
      const pageId = add(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${fontRegularId} 0 R /F2 ${fontBoldId} 0 R /F3 ${fontMonoId} 0 R >> >> /Contents ${contentId} 0 R${annots} >>`);
      pageIds.push(pageId);
    }
    set(pagesId, `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(" ")}] /Count ${pageIds.length} >>`);
    set(catalogId, `<< /Type /Catalog /Pages ${pagesId} 0 R >>`);

    let output = "%PDF-1.4\n%REPORTGEN\n";
    const offsets: number[] = [0];
    const encoder = new TextEncoder();
    for (let id = 1; id < objects.length; id += 1) {
      offsets[id] = encoder.encode(output).length;
      output += `${id} 0 obj\n${objects[id]}\nendobj\n`;
    }
    const xrefOffset = encoder.encode(output).length;
    output += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
    for (let id = 1; id < objects.length; id += 1) output += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
    output += `trailer\n<< /Size ${objects.length} /Root ${catalogId} 0 R /Info ${infoId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
    return encoder.encode(output);
  }
}