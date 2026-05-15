import { useState } from "react";
import { Title, Stack, Group, Button, Card, Text, Image, FileInput, Code, CopyButton, Tooltip, } from "@mantine/core";
import { IconUpload, IconCopy, IconCheck } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
export function UploadPage() {
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [result, setResult] = useState(null);
    async function onUpload() {
        if (!file)
            return;
        setUploading(true);
        try {
            const fd = new FormData();
            fd.append("file", file);
            const res = await api.post("/upload", fd, {
                headers: { "Content-Type": "multipart/form-data" },
            });
            setResult(res.data);
            notifications.show({ color: "green", title: "Uploaded", message: res.data.url });
        }
        catch (err) {
            const msg = err && typeof err === "object" && "message" in err
                ? String(err.message)
                : "upload failed";
            notifications.show({ color: "red", title: "Upload failed", message: msg });
        }
        finally {
            setUploading(false);
        }
    }
    return (<Stack>
      <Title order={2}>Upload media</Title>
      <Text size="sm" c="dimmed">
        Загрузка изображений (jpg/jpeg/png/gif) и видео (mp4/webm), до 50 MB.
        Файлы сохраняются в <Code>public/uploads/</Code>.
      </Text>

      <Card withBorder>
        <Stack>
          <FileInput label="Media file" placeholder="Click to select" accept="image/jpeg,image/png,image/gif,video/mp4,video/webm" value={file} onChange={setFile}/>
          <Group justify="flex-end">
            <Button leftSection={<IconUpload size={16}/>} disabled={!file} loading={uploading} onClick={() => void onUpload()}>
              Upload
            </Button>
          </Group>
        </Stack>
      </Card>

      {result && (<Card withBorder>
          <Stack>
            <Group justify="space-between">
              <Text fw={600}>Uploaded</Text>
              <CopyButton value={result.url}>
                {({ copied, copy }) => (<Tooltip label={copied ? "Copied" : "Copy URL"}>
                    <Button size="xs" variant="light" onClick={copy} leftSection={copied ? <IconCheck size={14}/> : <IconCopy size={14}/>}>
                      {copied ? "Copied" : "Copy URL"}
                    </Button>
                  </Tooltip>)}
              </CopyButton>
            </Group>
            <Code block style={{ wordBreak: "break-all" }}>{result.url}</Code>
            {result.type === "image" ? (<Image src={result.url} radius="md" fit="contain" h={200}/>) : (<video src={result.url} controls style={{ width: "100%", maxHeight: 300 }}/>)}
          </Stack>
        </Card>)}
    </Stack>);
}
