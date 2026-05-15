import { useEffect, useState } from "react";
import { Title, Stack, Group, Button, Table, Skeleton, Switch, Badge, ActionIcon, Modal, TextInput, Select, Card, Text, } from "@mantine/core";
import { IconRefresh, IconTrash, IconPlus } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
const PROTOS = [
    { value: "tcp", label: "TCP" },
    { value: "udp", label: "UDP" },
    { value: "any", label: "Any" },
];
const ACTIONS = [
    { value: "ACCEPT", label: "Accept" },
    { value: "DROP", label: "Drop" },
    { value: "REJECT", label: "Reject" },
];
export function FirewallPage() {
    const [status, setStatus] = useState<Record<string, any>>({});
    const [loading, setLoading] = useState(true);
    const [addOpen, setAddOpen] = useState(false);
    const [form, setForm] = useState({ proto: "tcp", port: "", source: "", action: "ACCEPT" });
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/firewall/status");
            setStatus(res.data ?? {});
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/firewall/status" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => {
        void reload();
    }, []);
    async function onToggle(enabled) {
        try {
            await api.post("/firewall/toggle", { enabled });
            setStatus((s) => ({ ...s, enabled }));
        }
        catch {
            notifications.show({ color: "red", title: "Toggle failed", message: "" });
        }
    }
    async function onAdd() {
        try {
            await api.post("/firewall/rules", form);
            setAddOpen(false);
            setForm({ proto: "tcp", port: "", source: "", action: "ACCEPT" });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Add failed", message: "" });
        }
    }
    async function onDelete(r) {
        if (!confirm("Delete rule?"))
            return;
        try {
            await api.delete("/firewall/rules", { data: r });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: "" });
        }
    }
    const rules = status.rules ?? [];
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Firewall</Title>
        <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>
          Refresh
        </Button>
      </Group>

      <Card withBorder>
        <Group justify="space-between">
          <Stack gap={0}>
            <Text fw={600}>Firewall status</Text>
            <Text size="xs" c="dimmed">backend: {status.backend ?? "—"}</Text>
          </Stack>
          <Switch size="lg" label={status.enabled ? "Enabled" : "Disabled"} checked={!!status.enabled} onChange={(e) => void onToggle(e.currentTarget.checked)}/>
        </Group>
      </Card>

      <Group justify="space-between">
        <Title order={4}>Rules</Title>
        <Button leftSection={<IconPlus size={16}/>} onClick={() => setAddOpen(true)}>Add rule</Button>
      </Group>

      {loading ? (<Stack>
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} h={36}/>)}
        </Stack>) : rules.length === 0 ? (<Text c="dimmed" ta="center" py="xl">No rules</Text>) : (<Table striped withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Proto</Table.Th>
              <Table.Th>Port</Table.Th>
              <Table.Th>Source</Table.Th>
              <Table.Th>Action</Table.Th>
              <Table.Th w={60}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rules.map((r, i) => (<Table.Tr key={r.id ?? i}>
                <Table.Td><Badge variant="light">{r.proto ?? "—"}</Badge></Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{r.port ?? "—"}</Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{r.source ?? "any"}</Table.Td>
                <Table.Td>
                  <Badge color={r.action === "ACCEPT" ? "green" : "red"}>{r.action ?? "—"}</Badge>
                </Table.Td>
                <Table.Td>
                  <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(r)}>
                    <IconTrash size={16}/>
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add firewall rule">
        <Stack>
          <Select label="Proto" data={PROTOS} value={form.proto} onChange={(v) => setForm((f) => ({ ...f, proto: v ?? "tcp" }))}/>
          <TextInput label="Port" placeholder="8443 или 1000-2000" value={form.port} onChange={(e) => setForm((f) => ({ ...f, port: e.currentTarget.value }))}/>
          <TextInput label="Source (CIDR или IP)" placeholder="0.0.0.0/0" value={form.source} onChange={(e) => setForm((f) => ({ ...f, source: e.currentTarget.value }))}/>
          <Select label="Action" data={ACTIONS} value={form.action} onChange={(v) => setForm((f) => ({ ...f, action: v ?? "ACCEPT" }))}/>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={() => void onAdd()}>Add</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>);
}
