import { useEffect, useState } from "react";
import { Title, Stack, Group, Button, Table, Skeleton, ActionIcon, Modal, TextInput, Select, Badge, } from "@mantine/core";
import { IconRefresh, IconTrash, IconPlus } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
const PROTOCOLS = [
    { value: "freedom", label: "Freedom (direct)" },
    { value: "blackhole", label: "Blackhole (reject)" },
    { value: "socks", label: "SOCKS" },
    { value: "http", label: "HTTP" },
    { value: "vless", label: "VLESS" },
    { value: "vmess", label: "VMess" },
];
export function OutboundsPage() {
    const [items, setItems] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    const [addOpen, setAddOpen] = useState(false);
    const [form, setForm] = useState({ tag: "", protocol: "freedom", address: "", port: "" });
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/outbounds");
            setItems(Array.isArray(res.data) ? res.data : []);
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/outbounds" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => { void reload(); }, []);
    async function onAdd() {
        if (!form.tag.trim())
            return;
        try {
            await api.post("/outbounds", {
                tag: form.tag.trim(),
                protocol: form.protocol,
                address: form.address.trim() || undefined,
                port: form.port ? Number(form.port) : undefined,
            });
            setAddOpen(false);
            setForm({ tag: "", protocol: "freedom", address: "", port: "" });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Add failed", message: form.tag });
        }
    }
    async function onDelete(tag) {
        if (!confirm(`Delete outbound "${tag}"?`))
            return;
        try {
            await api.post("/outbounds/delete", { tag });
            setItems((xs) => xs.filter((i) => i.tag !== tag));
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: tag });
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Outbounds</Title>
        <Group>
          <Button leftSection={<IconPlus size={16}/>} onClick={() => setAddOpen(true)}>Add</Button>
          <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>Refresh</Button>
        </Group>
      </Group>

      {loading ? (<Stack>{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} h={36}/>)}</Stack>) : items.length === 0 ? (<Stack align="center" py="xl"><Title order={5} c="dimmed">No outbounds</Title></Stack>) : (<Table striped withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Tag</Table.Th>
              <Table.Th>Protocol</Table.Th>
              <Table.Th>Address</Table.Th>
              <Table.Th>Port</Table.Th>
              <Table.Th w={60}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((i) => (<Table.Tr key={i.tag}>
                <Table.Td>{i.tag}</Table.Td>
                <Table.Td><Badge variant="light">{i.protocol ?? "—"}</Badge></Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{i.address ?? "—"}</Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{i.port ?? "—"}</Table.Td>
                <Table.Td>
                  <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(i.tag)}>
                    <IconTrash size={16}/>
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add outbound">
        <Stack>
          <TextInput label="Tag" placeholder="proxy-1" value={form.tag} onChange={(e) => setForm((f) => ({ ...f, tag: e.currentTarget.value }))}/>
          <Select label="Protocol" data={PROTOCOLS} value={form.protocol} onChange={(v) => setForm((f) => ({ ...f, protocol: v ?? "freedom" }))}/>
          <TextInput label="Address" placeholder="host.example.com" value={form.address} onChange={(e) => setForm((f) => ({ ...f, address: e.currentTarget.value }))}/>
          <TextInput label="Port" type="number" placeholder="443" value={form.port} onChange={(e) => setForm((f) => ({ ...f, port: e.currentTarget.value }))}/>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={() => void onAdd()}>Add</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>);
}
