import { useEffect, useState } from "react";
import { Title, Stack, Group, Button, Table, Skeleton, ActionIcon, Modal, TextInput, Card, Text, SimpleGrid, Switch, } from "@mantine/core";
import { IconRefresh, IconTrash, IconPlus } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
export function AdblockPage() {
    const [stats, setStats] = useState<Record<string, any>>({});
    const [rules, setRules] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    const [addOpen, setAddOpen] = useState(false);
    const [newDomain, setNewDomain] = useState("");
    async function reload() {
        setLoading(true);
        try {
            const [s, r] = await Promise.allSettled([
                api.get("/adblock/stats"),
                api.get("/adblock/rules"),
            ]);
            if (s.status === "fulfilled")
                setStats(s.value.data ?? {});
            if (r.status === "fulfilled")
                setRules(Array.isArray(r.value.data) ? r.value.data : []);
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => { void reload(); }, []);
    async function onAdd() {
        if (!newDomain.trim())
            return;
        try {
            await api.post("/adblock/rules/add", { domain: newDomain.trim() });
            setAddOpen(false);
            setNewDomain("");
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Add failed", message: newDomain });
        }
    }
    async function onDelete(r) {
        if (!confirm(`Remove ${r.domain}?`))
            return;
        try {
            await api.post("/adblock/rules/delete", { domain: r.domain, id: r.id });
            setRules((xs) => xs.filter((x) => (x.id ?? x.domain) !== (r.id ?? r.domain)));
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: r.domain });
        }
    }
    async function onToggle(enabled) {
        try {
            await api.post("/adblock/settings", { enabled });
            setStats((s) => ({ ...s, enabled }));
        }
        catch {
            notifications.show({ color: "red", title: "Toggle failed", message: "" });
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Ad-block</Title>
        <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>Refresh</Button>
      </Group>

      <Card withBorder>
        <Group justify="space-between">
          <Text fw={600}>Ad-blocking</Text>
          <Switch size="lg" checked={!!stats.enabled} onChange={(e) => void onToggle(e.currentTarget.checked)}/>
        </Group>
      </Card>

      <SimpleGrid cols={{ base: 2, sm: 4 }}>
        <StatCard label="Queries" value={stats.queries ?? "—"}/>
        <StatCard label="Blocked" value={stats.blocked ?? "—"}/>
        <StatCard label="Rules" value={stats.rules ?? rules.length}/>
        <StatCard label="Lists" value={stats.lists ?? "—"}/>
      </SimpleGrid>

      <Group justify="space-between">
        <Title order={4}>Custom rules</Title>
        <Button leftSection={<IconPlus size={16}/>} onClick={() => setAddOpen(true)}>Add domain</Button>
      </Group>

      {loading ? (<Stack>{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} h={36}/>)}</Stack>) : rules.length === 0 ? (<Text c="dimmed" ta="center" py="xl">No custom rules</Text>) : (<Table striped withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Domain</Table.Th>
              <Table.Th>Type</Table.Th>
              <Table.Th w={60}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rules.map((r, i) => (<Table.Tr key={r.id ?? i}>
                <Table.Td style={{ fontFamily: "monospace" }}>{r.domain}</Table.Td>
                <Table.Td>{r.type ?? "block"}</Table.Td>
                <Table.Td>
                  <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(r)}>
                    <IconTrash size={16}/>
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add ad-block domain">
        <Stack>
          <TextInput label="Domain" placeholder="ads.example.com" value={newDomain} onChange={(e) => setNewDomain(e.currentTarget.value)} data-autofocus/>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={() => void onAdd()}>Add</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>);
}
function StatCard({ label, value }) {
    return (<Card withBorder padding="md" radius="md">
      <Stack gap={4}>
        <Text size="xs" c="dimmed" tt="uppercase" fw={700}>{label}</Text>
        <Text size="xl" fw={700}>{value}</Text>
      </Stack>
    </Card>);
}
