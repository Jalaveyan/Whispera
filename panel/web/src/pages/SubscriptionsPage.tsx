import { useEffect, useState } from "react";
import { Title, Stack, Group, Button, Table, Skeleton, ActionIcon, Modal, TextInput, } from "@mantine/core";
import { IconRefresh, IconTrash, IconPlus, IconRotate } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
export function SubscriptionsPage() {
    const [items, setItems] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    const [addOpen, setAddOpen] = useState(false);
    const [form, setForm] = useState({ name: "", url: "" });
    const [bulkUpdating, setBulkUpdating] = useState(false);
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/subscriptions");
            setItems(Array.isArray(res.data) ? res.data : []);
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/subscriptions" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => { void reload(); }, []);
    async function onAdd() {
        if (!form.name.trim() || !form.url.trim())
            return;
        try {
            await api.post("/subscriptions/add", form);
            setAddOpen(false);
            setForm({ name: "", url: "" });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Add failed", message: form.name });
        }
    }
    async function onUpdate(id) {
        try {
            await api.post("/subscriptions/update", { id });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Update failed", message: String(id) });
        }
    }
    async function onDelete(id) {
        if (!confirm("Delete subscription?"))
            return;
        try {
            await api.post("/subscriptions/delete", { id });
            setItems((xs) => xs.filter((s) => s.id !== id));
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: String(id) });
        }
    }
    async function onUpdateAll() {
        setBulkUpdating(true);
        try {
            await api.post("/subscriptions/update-all");
            await reload();
            notifications.show({ color: "green", title: "Updated", message: "All subscriptions refreshed" });
        }
        catch {
            notifications.show({ color: "red", title: "Update-all failed", message: "" });
        }
        finally {
            setBulkUpdating(false);
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Subscriptions</Title>
        <Group>
          <Button leftSection={<IconPlus size={16}/>} onClick={() => setAddOpen(true)}>Add</Button>
          <Button variant="light" leftSection={<IconRotate size={16}/>} loading={bulkUpdating} onClick={() => void onUpdateAll()}>Update all</Button>
          <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>Refresh</Button>
        </Group>
      </Group>

      {loading ? (<Stack>{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} h={36}/>)}</Stack>) : items.length === 0 ? (<Stack align="center" py="xl"><Title order={5} c="dimmed">No subscriptions</Title></Stack>) : (<Table striped withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>URL</Table.Th>
              <Table.Th>Nodes</Table.Th>
              <Table.Th>Updated</Table.Th>
              <Table.Th w={100}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((s) => (<Table.Tr key={s.id}>
                <Table.Td>{s.name ?? "—"}</Table.Td>
                <Table.Td style={{ fontFamily: "monospace", fontSize: 12, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {s.url ?? "—"}
                </Table.Td>
                <Table.Td>{s.node_count ?? "—"}</Table.Td>
                <Table.Td style={{ fontSize: 12 }}>{s.updated_at ?? "—"}</Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    <ActionIcon variant="subtle" onClick={() => void onUpdate(s.id)}>
                      <IconRotate size={16}/>
                    </ActionIcon>
                    <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(s.id)}>
                      <IconTrash size={16}/>
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add subscription">
        <Stack>
          <TextInput label="Name" placeholder="My subscription" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.currentTarget.value }))}/>
          <TextInput label="URL" placeholder="https://..." value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.currentTarget.value }))}/>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={() => void onAdd()}>Add</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>);
}
