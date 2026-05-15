import { useEffect, useState } from "react";
import { Table, Title, Stack, Group, Button, Skeleton, Badge, ActionIcon, Modal, TextInput, Select, } from "@mantine/core";
import { IconRefresh, IconTrash, IconPlus } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
const KINDS = [
    { value: "domain", label: "Domain" },
    { value: "domain-keyword", label: "Keyword" },
    { value: "ip", label: "IP" },
    { value: "process", label: "Process" },
];
const ACTIONS = [
    { value: "DIRECT", label: "Direct" },
    { value: "PROXY", label: "Proxy" },
    { value: "REJECT", label: "Block" },
];
export function RoutingPage() {
    const [rules, setRules] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    const [addOpen, setAddOpen] = useState(false);
    const [form, setForm] = useState({ kind: "domain", value: "", action: "DIRECT" });
    const [submitting, setSubmitting] = useState(false);
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/routing/rules");
            setRules(Array.isArray(res.data) ? res.data : []);
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/routing/rules" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => {
        void reload();
    }, []);
    async function onAdd() {
        if (!form.value.trim())
            return;
        setSubmitting(true);
        try {
            await api.post("/routing/rules", form);
            setAddOpen(false);
            setForm({ kind: "domain", value: "", action: "DIRECT" });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Add failed", message: form.value });
        }
        finally {
            setSubmitting(false);
        }
    }
    async function onDelete(id) {
        if (!confirm("Delete rule?"))
            return;
        try {
            await api.delete(`/routing/rules/${id}`);
            setRules((xs) => xs.filter((r) => r.id !== id));
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: String(id) });
        }
    }
    function actionColor(a) {
        if (a === "REJECT")
            return "red";
        if (a === "PROXY")
            return "violet";
        return "gray";
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Routing rules</Title>
        <Group>
          <Button leftSection={<IconPlus size={16}/>} onClick={() => setAddOpen(true)}>
            Add rule
          </Button>
          <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>
            Refresh
          </Button>
        </Group>
      </Group>

      {loading ? (<Stack>
          {Array.from({ length: 4 }).map((_, i) => (<Skeleton key={i} h={36}/>))}
        </Stack>) : rules.length === 0 ? (<Stack align="center" py="xl">
          <Title order={5} c="dimmed">No rules</Title>
        </Stack>) : (<Table striped highlightOnHover withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={120}>Kind</Table.Th>
              <Table.Th>Value</Table.Th>
              <Table.Th w={100}>Action</Table.Th>
              <Table.Th w={60}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rules.map((r) => (<Table.Tr key={r.id}>
                <Table.Td>
                  <Badge variant="light" color="gray">{r.kind}</Badge>
                </Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{r.value}</Table.Td>
                <Table.Td>
                  <Badge color={actionColor(r.action)} variant="filled">{r.action}</Badge>
                </Table.Td>
                <Table.Td>
                  <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(r.id)}>
                    <IconTrash size={16}/>
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add routing rule">
        <Stack>
          <Select label="Kind" data={KINDS} value={form.kind} onChange={(v) => setForm((f) => ({ ...f, kind: v ?? "domain" }))}/>
          <TextInput label="Value" placeholder={form.kind === "ip" ? "1.2.3.4" : "example.com"} value={form.value} onChange={(e) => setForm((f) => ({ ...f, value: e.currentTarget.value }))} data-autofocus/>
          <Select label="Action" data={ACTIONS} value={form.action} onChange={(v) => setForm((f) => ({ ...f, action: v ?? "DIRECT" }))}/>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={() => void onAdd()} loading={submitting}>Add</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>);
}
