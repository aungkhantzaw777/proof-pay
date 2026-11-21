const projectLinks = [
  { label: "Watch Demo", href: "https://youtu.be/2HFyhh7Qqik" },
  { label: "DoraHacks", href: "https://dorahacks.io/build/51156" },
  {
    label: "Source Code",
    href: "https://github.com/aungkhantzaw777/proof-pay",
  },
]

export function HackathonBanner() {
  return (
    <aside
      aria-label="ProofPay hackathon project"
      className="border-b border-emerald-800 bg-[#064e3b] px-4 py-2 text-white md:px-8"
    >
      <div className="mx-auto flex max-w-[1360px] flex-wrap items-center justify-center gap-x-6 gap-y-2 lg:justify-between">
        <p className="text-center text-xs font-bold tracking-wider">
          BCH BLAZE 2026 <span aria-hidden="true">·</span> ProofPay
        </p>
        <nav
          aria-label="Project resources"
          className="flex flex-wrap items-center justify-center gap-1"
        >
          {projectLinks.map(({ label, href }) => (
            <a
              key={href}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex min-h-9 items-center rounded-md px-3 text-xs font-semibold text-emerald-50 underline-offset-4 transition-colors hover:bg-white/10 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
            >
              {label}
              <span className="sr-only"> (opens in a new tab)</span>
            </a>
          ))}
        </nav>
      </div>
    </aside>
  )
}
