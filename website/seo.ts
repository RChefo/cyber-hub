// Build-time SEO for the static pages: canonical URLs, Open Graph / Twitter URLs, sitemap.xml and
// robots.txt. Everything that needs the public domain is emitted only when SITE_URL is configured,
// so no domain is ever guessed. A Content-Security-Policy is added to production builds.
import type { Plugin } from "vite";

export interface SeoOptions {
  /** e.g. https://cyberhub.example — empty until the real domain is known */
  siteUrl: string;
  /** origin the download page reads release metadata from */
  releasesApiOrigin: string;
  pages: { path: string; file: string }[];
}

export function normalizeSiteUrl(raw: string | undefined): string {
  const v = (raw ?? "").trim().replace(/\/+$/, "");
  if (!v) return "";
  const u = new URL(v);
  if (u.protocol !== "https:") throw new Error(`VITE_SITE_URL must use https (got ${v})`);
  return u.origin + u.pathname.replace(/\/+$/, "");
}

export function seo({ siteUrl, releasesApiOrigin, pages }: SeoOptions): Plugin {
  let production = false;
  return {
    name: "cyber-hub-seo",
    configResolved(c) {
      production = c.command === "build";
    },
    transformIndexHtml(html, ctx) {
      const page = pages.find((p) => ctx.path === `/${p.file}` || ctx.path === p.file);
      const tags: string[] = [];
      if (siteUrl && page) {
        const url = `${siteUrl}${page.path}`;
        tags.push(`<link rel="canonical" href="${url}" />`, `<meta property="og:url" content="${url}" />`);
        tags.push(`<meta property="og:image" content="${siteUrl}/og.png" />`, `<meta name="twitter:image" content="${siteUrl}/og.png" />`);
      }
      if (production) {
        const csp = [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data:",
          "font-src 'self'",
          `connect-src 'self' ${releasesApiOrigin}`,
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'none'",
          // frame-ancestors only works as an HTTP header (see docs/WEBSITE.md, Deployment)
        ].join("; ");
        tags.unshift(`<meta http-equiv="Content-Security-Policy" content="${csp}" />`);
      }
      return html.replace("<!--seo-->", tags.join("\n    "));
    },
    generateBundle() {
      const robots = ["User-agent: *", "Allow: /", ...(siteUrl ? [`Sitemap: ${siteUrl}/sitemap.xml`] : [])].join("\n");
      this.emitFile({ type: "asset", fileName: "robots.txt", source: `${robots}\n` });
      if (siteUrl) {
        const urls = pages.map((p) => `  <url><loc>${siteUrl}${p.path}</loc></url>`).join("\n");
        this.emitFile({
          type: "asset",
          fileName: "sitemap.xml",
          source: `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`,
        });
      }
    },
  };
}
