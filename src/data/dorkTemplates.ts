// SPDX-License-Identifier: Apache-2.0
import type { DorkCategory, DorkTemplate } from "@/types/catalog";

export const DORK_CATEGORY_LABELS: Record<DorkCategory, string> = {
  "public-documents": "Public documents",
  "exposed-directories": "Exposed directories",
  "login-pages": "Login pages",
  "dev-docs": "Development documentation",
  "config-references": "Configuration references",
  "tech-discovery": "Technical discovery",
};

const d = (id: string, title: string, category: DorkCategory, query: string, description: string): DorkTemplate => ({
  id,
  title,
  category,
  query,
  description,
});

/**
 * Templates for reviewing what search engines have indexed about domains you own
 * or are authorized to assess. `{domain}` is replaced with the selected domain.
 */
export const DORK_TEMPLATES: DorkTemplate[] = [
  // Public documents
  d("doc-pdf", "Indexed PDF documents", "public-documents", "site:{domain} filetype:pdf", "PDFs published on your domain — check for internal reports or drafts that should not be public."),
  d("doc-office", "Office documents", "public-documents", "site:{domain} (filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx)", "Word, Excel and PowerPoint files indexed from your site."),
  d("doc-confidential", "Documents marked confidential", "public-documents", 'site:{domain} (filetype:pdf OR filetype:docx) (intext:"confidential" OR intext:"internal use only")', "Documents containing confidentiality markings that may have been published by mistake."),
  d("doc-spreadsheets", "Spreadsheets and CSV exports", "public-documents", "site:{domain} (filetype:csv OR filetype:xls OR filetype:xlsx)", "Data exports that could contain personal or business data."),
  d("doc-presentations", "Presentations", "public-documents", "site:{domain} (filetype:ppt OR filetype:pptx OR filetype:key)", "Slide decks that may reveal roadmaps or architecture."),
  d("doc-text", "Plain-text files", "public-documents", "site:{domain} filetype:txt -inurl:robots.txt", "Text files other than robots.txt, often notes or exports."),

  // Exposed directories
  d("dir-index", "Directory listings", "exposed-directories", 'site:{domain} intitle:"index of"', "Web server auto-index pages exposing folder contents."),
  d("dir-index-parent", "Listings with parent directory links", "exposed-directories", 'site:{domain} intitle:"index of" "parent directory"', "Classic Apache/Nginx directory listing pages."),
  d("dir-backup", "Backup folders", "exposed-directories", 'site:{domain} intitle:"index of" (backup OR backups OR bak)', "Listings that look like backup locations."),
  d("dir-uploads", "Upload folders", "exposed-directories", 'site:{domain} (inurl:uploads OR inurl:files) intitle:"index of"', "Publicly browsable upload directories."),
  d("dir-git", "Version control folders", "exposed-directories", 'site:{domain} (inurl:".git" OR inurl:".svn") intitle:"index of"', "Indexed repository metadata folders that should never be web-accessible."),
  d("dir-logs", "Log folders", "exposed-directories", 'site:{domain} intitle:"index of" (log OR logs)', "Browsable log directories."),

  // Login pages
  d("login-generic", "Login pages", "login-pages", "site:{domain} (inurl:login OR inurl:signin OR intitle:login)", "Authentication entry points indexed for your domain."),
  d("login-admin", "Admin panels", "login-pages", "site:{domain} (inurl:admin OR inurl:administrator OR intitle:admin)", "Administrative interfaces that should usually not be indexed."),
  d("login-portal", "Portals and dashboards", "login-pages", "site:{domain} (inurl:portal OR inurl:dashboard)", "Customer, partner or employee portals."),
  d("login-sso", "SSO and identity pages", "login-pages", "site:{domain} (inurl:sso OR inurl:oauth OR inurl:saml OR inurl:auth)", "Single sign-on and identity provider endpoints."),
  d("login-reset", "Password reset pages", "login-pages", 'site:{domain} (inurl:reset OR inurl:forgot) (password OR "reset")', "Account recovery flows."),
  d("login-wp", "WordPress login", "login-pages", "site:{domain} (inurl:wp-login.php OR inurl:wp-admin)", "WordPress authentication pages."),

  // Development documentation
  d("dev-api-docs", "API documentation", "dev-docs", "site:{domain} (inurl:api-docs OR inurl:swagger OR intitle:swagger OR inurl:redoc)", "Swagger/OpenAPI and ReDoc pages describing your APIs."),
  d("dev-openapi", "OpenAPI specifications", "dev-docs", "site:{domain} (inurl:openapi.json OR inurl:swagger.json OR inurl:openapi.yaml)", "Raw API specification files."),
  d("dev-readme", "README and changelog files", "dev-docs", "site:{domain} (inurl:readme OR inurl:changelog) (filetype:md OR filetype:txt)", "Project documentation that may reveal versions or internals."),
  d("dev-staging", "Staging and test hosts", "dev-docs", "site:*.{domain} (inurl:staging OR inurl:dev OR inurl:test OR inurl:uat) -site:www.{domain}", "Non-production environments indexed under your domain."),
  d("dev-graphql", "GraphQL endpoints", "dev-docs", "site:{domain} (inurl:graphql OR inurl:graphiql)", "GraphQL endpoints and interactive consoles."),
  d("dev-pastes", "Code snippets referencing the domain", "dev-docs", 'site:github.com OR site:gitlab.com "{domain}"', "Public repositories that mention your domain — review for leaked internal references."),

  // Configuration references
  d("cfg-env", "Environment files", "config-references", "site:{domain} (filetype:env OR inurl:.env)", "Indexed environment files, which frequently contain secrets."),
  d("cfg-config", "Configuration files", "config-references", "site:{domain} (filetype:conf OR filetype:cfg OR filetype:ini OR filetype:yml OR filetype:yaml)", "Server and application configuration files."),
  d("cfg-xml", "XML configuration", "config-references", "site:{domain} filetype:xml (inurl:config OR inurl:web.config OR inurl:settings)", "XML configuration such as web.config."),
  d("cfg-json", "JSON settings", "config-references", "site:{domain} filetype:json (inurl:config OR inurl:settings OR inurl:manifest)", "JSON configuration and manifest files."),
  d("cfg-sql", "Database dumps", "config-references", "site:{domain} (filetype:sql OR filetype:dump OR filetype:bak)", "SQL exports and backups that may have been published."),
  d("cfg-logs", "Log files", "config-references", "site:{domain} filetype:log", "Application or server logs indexed by search engines."),

  // Technical discovery
  d("tech-subdomains", "Indexed subdomains", "tech-discovery", "site:*.{domain} -site:www.{domain}", "Subdomains search engines know about."),
  d("tech-errors", "Error and debug pages", "tech-discovery", 'site:{domain} (intext:"stack trace" OR intext:"Traceback (most recent call last)" OR intext:"Warning: mysql" OR intitle:"error")', "Verbose error pages that disclose implementation details."),
  d("tech-phpinfo", "PHP info pages", "tech-discovery", 'site:{domain} (inurl:phpinfo OR intitle:"phpinfo()")', "phpinfo() output pages revealing configuration."),
  d("tech-server-status", "Server status pages", "tech-discovery", 'site:{domain} (inurl:server-status OR inurl:server-info OR intitle:"Apache Status")', "Apache/Nginx status pages."),
  d("tech-params", "URLs with query parameters", "tech-discovery", "site:{domain} inurl:? (inurl:id= OR inurl:page= OR inurl:url= OR inurl:redirect=)", "Parameterized URLs worth including in authorized testing scope reviews."),
  d("tech-third-party", "Third-party hosted content", "tech-discovery", '"{domain}" (site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com)', "Cloud storage objects that reference your domain."),
  d("tech-recent", "Recently indexed pages", "tech-discovery", "site:{domain} after:2025-01-01", "Pages indexed after a date — adjust the date to track new exposure."),
];
