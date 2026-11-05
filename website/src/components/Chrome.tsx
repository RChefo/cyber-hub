import { useEffect, useId, useRef, useState } from "react";
import { config, repoLinks } from "../lib/config";

export function Logo({ className = "size-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true">
      <rect width="64" height="64" rx="14" fill="#0E1726" />
      <rect x="0.5" y="0.5" width="63" height="63" rx="13.5" fill="none" stroke="#2B6FD6" strokeOpacity=".45" />
      <path d="M32 13 47 19v11c0 10-6.4 17.6-15 21-8.6-3.4-15-11-15-21V19z" fill="none" stroke="#5B9BFF" strokeWidth="3.2" strokeLinejoin="round" />
      <path d="M25 32h14M32 25v14" stroke="#9CC3FF" strokeWidth="3.2" strokeLinecap="round" />
    </svg>
  );
}

type Page = "home" | "download";

function navItems(page: Page) {
  const home = page === "home" ? "" : "/";
  const links = repoLinks(config.repository);
  return [
    { href: `${home}#features`, label: "Features" },
    { href: `${home}#security`, label: "Security model" },
    { href: `${home}#platforms`, label: "Platforms" },
    ...(links
      ? [
          { href: links.docs, label: "Documentation", external: true },
          { href: links.releases, label: "Changelog", external: true },
        ]
      : []),
  ];
}

export function Nav({ page }: { page: Page }) {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);
  const menuId = useId();
  const toggle = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 12);
    on();
    window.addEventListener("scroll", on, { passive: true });
    return () => window.removeEventListener("scroll", on);
  }, []);

  useEffect(() => {
    if (!open) return;
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        toggle.current?.focus();
      }
    };
    document.addEventListener("keydown", esc);
    return () => document.removeEventListener("keydown", esc);
  }, [open]);

  const items = navItems(page);
  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-[background-color,backdrop-filter,box-shadow] duration-300 ${
        scrolled || open ? "bg-base/85 shadow-[0_1px_0_rgb(255_255_255/0.06)] backdrop-blur-md" : "bg-transparent"
      }`}
    >
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:rounded-md focus:bg-raised focus:px-3 focus:py-2">
        Skip to content
      </a>
      <div className="wrap flex h-16 items-center justify-between gap-6">
        <a href="/" className="flex items-center gap-2.5 font-medium tracking-tight" aria-label="Cyber Hub home">
          <Logo />
          <span className="text-[1.05rem]">Cyber Hub</span>
        </a>
        <nav aria-label="Main" className="hidden items-center gap-1 md:flex">
          {items.map((i) => (
            <a
              key={i.label}
              href={i.href}
              {...(i.external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
              className="rounded-md px-3 py-2 text-[0.92rem] text-muted transition-colors hover:text-ink"
            >
              {i.label}
            </a>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <a href="/download/" className={`btn btn-primary h-10 px-4 text-[0.9rem] ${page === "download" ? "hidden sm:inline-flex" : ""}`} aria-current={page === "download" ? "page" : undefined}>
            Download
          </a>
          <button
            ref={toggle}
            type="button"
            className="grid size-10 place-items-center rounded-md text-ink hover:bg-white/5 md:hidden"
            aria-expanded={open}
            aria-controls={menuId}
            aria-label={open ? "Close menu" : "Open menu"}
            onClick={() => setOpen((v) => !v)}
          >
            <svg viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
              {open ? <path d="M6 6l12 12M18 6 6 18" /> : <path d="M4 7h16M4 12h16M4 17h16" />}
            </svg>
          </button>
        </div>
      </div>
      <nav id={menuId} aria-label="Main" hidden={!open} className="wrap pb-5 md:hidden">
        <ul className="flex flex-col">
          {items.map((i) => (
            <li key={i.label}>
              <a
                href={i.href}
                onClick={() => setOpen(false)}
                {...(i.external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
                className="block border-b border-white/5 py-3.5 text-[1.05rem] text-ink"
              >
                {i.label}
              </a>
            </li>
          ))}
        </ul>
      </nav>
    </header>
  );
}

export function Footer({ version }: { version?: string | null }) {
  const links = repoLinks(config.repository);
  const year = new Date().getFullYear();
  return (
    <footer className="mt-24 bg-surface/60">
      <div className="wrap grid gap-10 py-14 md:grid-cols-[1.4fr_1fr_1fr]">
        <div>
          <a href="/" className="flex items-center gap-2.5 font-medium">
            <Logo className="size-7" />
            Cyber Hub
          </a>
          <p className="mt-3 max-w-sm text-[0.92rem] leading-relaxed text-muted">A local-first desktop workspace for security work, for Windows 10/11 and Linux on x64.</p>
          <p className="mt-4 text-[0.85rem] text-faint">{version ? `Latest release: ${version}` : "No public release yet."}</p>
        </div>
        <nav aria-label="Footer">
          <h2 className="text-[0.85rem] font-medium text-muted">Product</h2>
          <ul className="mt-3 space-y-2 text-[0.92rem]">
            <li><a className="text-ink/85 hover:text-ink" href="/#features">Features</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/#security">Security model</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/#platforms">Platforms</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/download/">Download</a></li>
          </ul>
        </nav>
        <nav aria-label="Project">
          <h2 className="text-[0.85rem] font-medium text-muted">Project</h2>
          {links ? (
            <ul className="mt-3 space-y-2 text-[0.92rem]">
              <li><a className="text-ink/85 hover:text-ink" href={links.docs} target="_blank" rel="noopener noreferrer">Documentation</a></li>
              <li><a className="text-ink/85 hover:text-ink" href={links.releases} target="_blank" rel="noopener noreferrer">Releases and changelog</a></li>
              <li><a className="text-ink/85 hover:text-ink" href={links.repository} target="_blank" rel="noopener noreferrer">GitHub</a></li>
            </ul>
          ) : (
            <p className="mt-3 text-[0.9rem] leading-relaxed text-faint">Documentation, the changelog and the source repository will be linked here once the repository is public.</p>
          )}
        </nav>
      </div>
      <div className="wrap flex flex-wrap justify-between gap-3 py-6 text-[0.8rem] text-faint">
        <span>© {year} Cyber Hub contributors</span>
        <span>macOS is not supported.</span>
      </div>
    </footer>
  );
}
