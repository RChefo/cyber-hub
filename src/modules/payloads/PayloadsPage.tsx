import { Tabs } from "@heroui/react";
import { useState } from "react";
import { useApp } from "@/app/store";
import { PageHeader } from "@/components/ui/Panel";
import { PAYLOADS } from "@/data/payloads";
import { PayloadsTab } from "./PayloadsTab";
import { WordlistsTab } from "./WordlistsTab";

export default function PayloadsPage() {
  const { route } = useApp();
  const params = route.params ?? {};
  const [tab, setTab] = useState<"payloads" | "wordlists">(params.tab === "wordlists" || params.wordlist ? "wordlists" : "payloads");

  return (
    <div>
      <PageHeader
        title="Payloads & Wordlists"
        description={`${PAYLOADS.length} reference test strings plus your own, and a local index of the wordlists on this machine.`}
      />
      <Tabs selectedKey={tab} onSelectionChange={(k) => setTab(k as "payloads" | "wordlists")}>
        <Tabs.ListContainer>
          <Tabs.List aria-label="Library section" className="h-9">
            <Tabs.Tab id="payloads" className="px-3 text-[13px]">Payloads<Tabs.Indicator /></Tabs.Tab>
            <Tabs.Tab id="wordlists" className="px-3 text-[13px]">Wordlists<Tabs.Indicator /></Tabs.Tab>
          </Tabs.List>
        </Tabs.ListContainer>
        <Tabs.Panel id="payloads" className="pt-4">
          <PayloadsTab preselect={params.payload} />
        </Tabs.Panel>
        <Tabs.Panel id="wordlists" className="pt-4">
          <WordlistsTab preselect={params.wordlist} />
        </Tabs.Panel>
      </Tabs>
    </div>
  );
}
