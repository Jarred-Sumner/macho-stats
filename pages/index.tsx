import { MachoAnalyzer } from "../components/Macho";

export default function Page() {
  return (
    <div className="max-w-5xl mx-auto p-4">
      {/** TODO: use tailwind bun plugin once that's implemented. */}
      <link
        rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/tailwindcss@latest/dist/tailwind.min.css"
      />
      {/** TODO: use metadata api once that's implemented. */}
      <title>Mach-O Binary Analyzer</title>

      <MachoAnalyzer />
    </div>
  );
}
