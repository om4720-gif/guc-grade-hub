import { createFileRoute, Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "GradeWatch — your GUC grades, collected automatically" },
      { name: "description", content: "Link your GUC account once. We check for new grades every few hours and send them to your other apps." },
      { property: "og:title", content: "GradeWatch — your GUC grades, collected automatically" },
      { property: "og:description", content: "Automatic GUC grade checks, a personal API, and instant notifications." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const steps = [
  ["01", "Link your GUC account", "Your password is encrypted before it's stored."],
  ["02", "We check every few hours", "New or changed grades are recorded the moment they appear."],
  ["03", "Plug into anything", "A personal API link and instant notifications for your other apps."],
];

function Index() {
  return (
    <main className="mx-auto flex min-h-screen max-w-5xl flex-col px-6 py-10">
      <header className="flex items-center justify-between">
        <span className="stamp">GradeWatch · GUC</span>
        <Link to="/auth">
          <Button variant="outline" size="sm">Sign in</Button>
        </Link>
      </header>
      <section className="flex flex-1 flex-col justify-center py-20">
        <p className="stamp text-primary">Unofficial student tool</p>
        <h1 className="mt-4 max-w-3xl text-6xl leading-[0.95] md:text-8xl">
          Stop refreshing the portal. <em className="text-primary">Your grades come to you.</em>
        </h1>
        <div className="mt-10 flex gap-3">
          <Link to="/auth">
            <Button size="lg">Get started</Button>
          </Link>
        </div>
      </section>
      <section className="grid gap-6 pb-10 md:grid-cols-3">
        {steps.map(([n, t, d]) => (
          <div key={n} className="ledger-card p-6">
            <span className="stamp text-primary">{n}</span>
            <h3 className="mt-3 text-2xl">{t}</h3>
            <p className="mt-2 text-sm text-muted-foreground">{d}</p>
          </div>
        ))}
      </section>
    </main>
  );
}
