import { useEffect, useState } from "react";
import { Table, Title, Stack, Group, Button, Skeleton, Badge, ActionIcon, TextInput, Modal, } from "@mantine/core";
import { IconRefresh, IconTrash, IconPlus } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
export function BridgesPage() {
    const [bridges, setBridges] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    const [addOpen, setAddOpen] = useState(false);
    const [newAddr, setNewAddr] = useState("");
    const [submitting, setSubmitting] = useState(false);
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/bridges");
            setBridges(Array.isArray(res.data) ? res.data : []);
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/bridges" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => {
        void reload();
    }, []);
    async function onAdd() {
        if (!newAddr.trim())
            return;
        setSubmitting(true);
        try {
            await api.post("/bridges", { address: newAddr.trim() });
            setAddOpen(false);
            setNewAddr("");
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Add failed", message: newAddr });
        }
        finally {
            setSubmitting(false);
        }
    }
    async function onDelete(id) {
        if (!confirm("Delete bridge?"))
            return;
        try {
            await api.post("/bridges/delete", { id });
            setBridges((xs) => xs.filter((b) => b.id !== id));
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: String(id) });
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Bridges</Title>
        <Group>
          <Button variant="filled" leftSection={<IconPlus size={16}/>} onClick={() => setAddOpen(true)}>
            Add
          </Button>
          <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>
            Refresh
          </Button>
        </Group>
      </Group>

      {loading ? (<Stack>
          {Array.from({ length: 4 }).map((_, i) => (<Skeleton key={i} h={36}/>))}
        </Stack>) : bridges.length === 0 ? (<Stack align="center" py="xl">
          <Title order={5} c="dimmed">No bridges</Title>
        </Stack>) : (<Table striped highlightOnHover withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Address</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th w={60}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {bridges.map((b, i) => (<Table.Tr key={b.id ?? i}>
                <Table.Td>{b.name ?? "—"}</Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{b.address ?? "—"}</Table.Td>
                <Table.Td>
                  <Badge color={b.alive ? "green" : "gray"} variant="light">
                    {b.status ?? (b.alive ? "alive" : "dead")}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(b.id)}>
                    <IconTrash size={16}/>
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}

      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add bridge">
        <Stack>
          <TextInput label="Address" placeholder="host:port" value={newAddr} onChange={(e) => setNewAddr(e.currentTarget.value)} data-autofocus/>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={() => void onAdd()} loading={submitting}>Add</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>);
}
