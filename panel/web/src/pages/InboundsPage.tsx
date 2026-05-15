import { useEffect, useState } from "react";
import { Title, Stack, Group, Button, Table, Skeleton, ActionIcon, Modal, TextInput, Select, Badge, Code, CopyButton, Tooltip, } from "@mantine/core";
import { IconRefresh, IconTrash, IconPlus, IconCopy, IconCheck } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
const PROTOCOLS = [
    { value: "vless", label: "VLESS" },
    { value: "vmess", label: "VMess" },
    { value: "trojan", label: "Trojan" },
    { value: "shadowsocks", label: "Shadowsocks" },
];
export function InboundsPage() {
    const [items, setItems] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    const [addOpen, setAddOpen] = useState(false);
    const [form, setForm] = useState({ tag: "", protocol: "vless", port: "" });
    const [pubkey, setPubkey] = useState(null);
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/inbounds");
            setItems(Array.isArray(res.data) ? res.data : []);
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/inbounds" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => { void reload(); }, []);
    async function onAdd() {
        if (!form.tag.trim() || !form.port.trim())
            return;
        try {
            await api.post("/inbounds", {
                tag: form.tag.trim(),
                protocol: form.protocol,
                port: Number(form.port),
            });
            setAddOpen(false);
            setForm({ tag: "", protocol: "vless", port: "" });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Add failed", message: form.tag });
        }
    }
    async function onDelete(tag) {
        if (!confirm(`Delete inbound "${tag}"?`))
            return;
        try {
            await api.delete(`/inbounds/${encodeURIComponent(tag)}`);
            setItems((xs) => xs.filter((i) => i.tag !== tag));
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: tag });
        }
    }
    async function showPublicKey(port) {
        if (!port)
            return;
        try {
            const res = await api.get(`/publickey/${port}`);
            const key = res.data.publicKey ?? res.data.key ?? JSON.stringify(res.data);
            setPubkey({ port, key });
        }
        catch {
            notifications.show({ color: "red", title: "Key load failed", message: String(port) });
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Inbounds</Title>
        <Group>
          <Button leftSection={<IconPlus size={16}/>} onClick={() => setAddOpen(true)}>Add</Button>
          <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>Refresh</Button>
        </Group>
      </Group>

      {loading ? (<Stack>{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} h={36}/>)}</Stack>) : items.length === 0 ? (<Stack align="center" py="xl"><Title order={5} c="dimmed">No inbounds</Title></Stack>) : (<Table striped withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Tag</Table.Th>
              <Table.Th>Protocol</Table.Th>
              <Table.Th>Port</Table.Th>
              <Table.Th>Listen</Table.Th>
              <Table.Th>Security</Table.Th>
              <Table.Th w={120}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((i) => (<Table.Tr key={i.tag}>
                <Table.Td>{i.tag}</Table.Td>
                <Table.Td><Badge variant="light">{i.protocol ?? "—"}</Badge></Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{i.port ?? "—"}</Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{i.listen ?? "—"}</Table.Td>
                <Table.Td>{i.security ?? "—"}</Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    <Button size="xs" variant="subtle" onClick={() => void showPublicKey(i.port)}>
                      Key
                    </Button>
                    <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(i.tag)}>
                      <IconTrash size={16}/>
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add inbound">
        <Stack>
          <TextInput label="Tag" placeholder="main" value={form.tag} onChange={(e) => setForm((f) => ({ ...f, tag: e.currentTarget.value }))}/>
          <Select label="Protocol" data={PROTOCOLS} value={form.protocol} onChange={(v) => setForm((f) => ({ ...f, protocol: v ?? "vless" }))}/>
          <TextInput label="Port" placeholder="443" type="number" value={form.port} onChange={(e) => setForm((f) => ({ ...f, port: e.currentTarget.value }))}/>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={() => void onAdd()}>Add</Button>
          </Group>
        </Stack>
      </Modal>

      <Modal opened={!!pubkey} onClose={() => setPubkey(null)} title={`Public key (port ${pubkey?.port})`}>
        <Stack>
          <Code block style={{ wordBreak: "break-all" }}>{pubkey?.key}</Code>
          <Group justify="flex-end">
            <CopyButton value={pubkey?.key ?? ""}>
              {({ copied, copy }) => (<Tooltip label={copied ? "Copied" : "Copy"}>
                  <Button variant="light" onClick={copy} leftSection={copied ? <IconCheck size={16}/> : <IconCopy size={16}/>}>
                    {copied ? "Copied" : "Copy"}
                  </Button>
                </Tooltip>)}
            </CopyButton>
          </Group>
        </Stack>
      </Modal>
    </Stack>);
}
