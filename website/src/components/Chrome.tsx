import { useEffect, useId, useRef, useState } from "react";
import { config, repoLinks } from "../lib/config";
import { Logo } from "./brand/Logo";

type Page = "home" | "download" | "changelog";

function navItems(page: Page) {
  const home = page === "home" ? "" : "/";
  const links = repoLinks(config.repository);
  return [
    { href: "/", label: "Home", current: page === "home" },
    { href: `${home}#features`, label: "Features" },
    { href: "/changelog/", label: "Changelog", current: page === "changelog" },
    // the documentation lives in the repository: linked only once one is configured
    ...(links ? [{ href: links.docs, label: "Documentation", external: true }] : []),
  ] as { href: string; label: string; current?: boolean; external?: boolean }[];
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
        <a href="/" className="flex items-center text-ink" aria-label="ExploitX home">
          <Logo capHeight={15} />
        </a>
        <nav aria-label="Main" className="hidden items-center gap-1 md:flex">
          {items.map((i) => (
            <a
              key={i.label}
              href={i.href}
              {...(i.external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
              aria-current={i.current ? "page" : undefined}
              className={`rounded-md px-3 py-2 text-[0.92rem] transition-colors hover:text-ink ${i.current ? "text-ink" : "text-muted"}`}
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
          <a href="/" className="inline-flex text-ink" aria-label="ExploitX home">
            <Logo capHeight={15} />
          </a>
          <p className="mt-4 max-w-sm text-[0.92rem] leading-relaxed text-muted">Cybersecurity intelligence and security research platform. Local-first, for Windows 10/11 and Linux on x64.</p>
          <p className="mt-4 text-[0.85rem] text-faint">{version ? `Latest release: ${version}` : "No public release yet."}</p>
        </div>
        <nav aria-label="Footer">
          <h2 className="text-[0.85rem] font-medium text-muted">Product</h2>
          <ul className="mt-3 space-y-2 text-[0.92rem]">
            <li><a className="text-ink/85 hover:text-ink" href="/#features">Features</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/#security">Security model</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/#platforms">Platforms</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/download/">Download</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/download/archive/">Version archive</a></li>
            <li><a className="text-ink/85 hover:text-ink" href="/changelog/">Changelog</a></li>
          </ul>
        </nav>
        <nav aria-label="Project">
          <h2 className="text-[0.85rem] font-medium text-muted">Project</h2>
          {links ? (
            <ul className="mt-3 space-y-2 text-[0.92rem]">
              <li><a className="text-ink/85 hover:text-ink" href={links.docs} target="_blank" rel="noopener noreferrer">Documentation</a></li>
              <li><a className="text-ink/85 hover:text-ink" href={links.releases} target="_blank" rel="noopener noreferrer">Releases on GitHub</a></li>
              <li><a className="text-ink/85 hover:text-ink" href={links.repository} target="_blank" rel="noopener noreferrer">GitHub</a></li>
            </ul>
          ) : (
            <p className="mt-3 text-[0.9rem] leading-relaxed text-faint">Documentation and the source repository will be linked here once the repository is public.</p>
          )}
        </nav>
      </div>
      <div className="wrap flex flex-wrap justify-between gap-3 py-6 text-[0.8rem] text-faint">
        <span>© {year} ExploitX contributors</span>
        <span>macOS is not supported.</span>
      </div>
    </footer>
  );
}
