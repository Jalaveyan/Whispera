import { useEffect, useRef, useState } from "react";
import { Title, Stack, Group, Button, ScrollArea, TextInput, SegmentedControl, Code, Switch, } from "@mantine/core";
import { IconRefresh, IconSearch } from "@tabler/icons-react";
import { api } from "@/api/client";
const LEVELS = [
    { value: "all", label: "All" },
    { value: "error", label: "Error" },
    { value: "warn", label: "Warn" },
    { value: "info", label: "Info" },
    { value: "debug", label: "Debug" },
];
function levelColor(l) {
    switch ((l ?? "").toLowerCase()) {
        case "error": return "#ff6b6b";
        case "warn":
        case "warning": return "#ffd43b";
        case "info": return "#4dabf7";
        case "debug": return "#868e96";
        default: return "#adb5bd";
    }
}
export function LogsPage() {
    const [logs, setLogs] = useState<Record<string, any>[]>([]);
    const [level, setLevel] = useState("all");
    const [search, setSearch] = useState("");
    const [follow, setFollow] = useState(true);
    const viewRef = useRef(null);
    async function reload() {
        try {
            const res = await api.get("/logs");
            const arr = Array.isArray(res.data) ? res.data : res.data.logs ?? [];
            setLogs(arr);
        }
        catch {
        }
    }
    useEffect(() => {
        void reload();
        const iv = setInterval(() => void reload(), 2000);
        return () => clearInterval(iv);
    }, []);
    useEffect(() => {
        if (follow && viewRef.current) {
            viewRef.current.scrollTop = viewRef.current.scrollHeight;
        }
    }, [logs, follow]);
    const filtered = logs.filter((l) => {
        if (level !== "all" && (l.level ?? "").toLowerCase() !== level)
            return false;
        if (search && !JSON.stringify(l).toLowerCase().includes(search.toLowerCase()))
            return false;
        return true;
    });
    return (<Stack style={{ height: "calc(100vh - 110px)" }}>
      <Group justify="space-between" wrap="wrap">
        <Title order={2}>Logs</Title>
        <Group>
          <Switch label="Follow" checked={follow} onChange={(e) => setFollow(e.currentTarget.checked)}/>
          <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>
            Refresh
          </Button>
        </Group>
      </Group>

      <Group>
        <SegmentedControl data={LEVELS} value={level} onChange={setLevel}/>
        <TextInput leftSection={<IconSearch size={16}/>} placeholder="Search…" value={search} onChange={(e) => setSearch(e.currentTarget.value)} style={{ flex: 1, minWidth: 200 }}/>
      </Group>

      <ScrollArea viewportRef={viewRef} style={{ flex: 1, fontFamily: "monospace", fontSize: 12 }} offsetScrollbars>
        <Stack gap={2} p="xs">
          {filtered.length === 0 ? (<Code c="dimmed">— no matching logs —</Code>) : (filtered.map((l, i) => (<div key={i} style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                {l.ts && <span style={{ opacity: 0.5 }}>[{l.ts}] </span>}
                {l.level && (<span style={{ color: levelColor(l.level), fontWeight: 600 }}>
                    {l.level.toUpperCase()}
                  </span>)}
                {" "}
                {l.msg ?? JSON.stringify(l)}
              </div>)))}
        </Stack>
      </ScrollArea>
    </Stack>);
}
