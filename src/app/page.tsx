import { Suspense } from "react";
import { Console } from "@/components/console";

// /?cve=CVE-2021-44906 opens the console with that CVE already traced.
async function ConsoleFromUrl({ searchParams }: { searchParams: Promise<{ cve?: string | string[] }> }) {
  const { cve } = await searchParams;
  return <Console initialCve={typeof cve === "string" ? cve : undefined} />;
}

export default function Home({ searchParams }: PageProps<"/">) {
  return (
    <main className="flex-1">
      <Suspense fallback={<Console />}>
        <ConsoleFromUrl searchParams={searchParams} />
      </Suspense>
    </main>
  );
}
