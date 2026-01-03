import {
  Close,
  Content,
  Description,
  Overlay,
  Portal,
  Root,
  Title,
  Trigger,
} from "@radix-ui/react-dialog";
import { Settings2, X } from "lucide-react";
import { type ReactElement, useEffect, useState } from "react";

import { Button } from "./Button";
import { Card } from "./Card";
import { Input } from "./Input";

export function SettingsDialog(props: {
  apiBaseUrl: string;
  onChangeApiBaseUrl: (next: string) => void;
}): ReactElement {
  const [draft, setDraft] = useState(props.apiBaseUrl);

  useEffect(() => {
    setDraft(props.apiBaseUrl);
  }, [props.apiBaseUrl]);

  return (
    <Root>
      <Trigger asChild={true}>
        <Button variant="outline">
          <Settings2 size={16} />
          设置
        </Button>
      </Trigger>

      <Portal>
        <Overlay className="fixed inset-0 bg-black/55 backdrop-blur-sm" />
        <Content className="fixed left-1/2 top-1/2 w-[560px] max-w-[92vw] -translate-x-1/2 -translate-y-1/2 focus:outline-none">
          <Card className="relative overflow-hidden p-5">
            <div className="absolute inset-0 zm-grid-overlay opacity-25" />
            <div className="relative">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <Title className="text-lg font-semibold">设置</Title>
                  <Description className="mt-1 text-sm text-muted">
                    配置后端 API 地址（默认：http://127.0.0.1:8080）
                  </Description>
                </div>
                <Close asChild={true}>
                  <Button variant="ghost" aria-label="关闭">
                    <X size={18} />
                  </Button>
                </Close>
              </div>

              <div className="mt-4 space-y-2">
                <label className="text-sm text-muted" htmlFor="apiBaseUrl">
                  API Base URL
                </label>
                <Input
                  id="apiBaseUrl"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder="http://127.0.0.1:8080"
                />
              </div>

              <div className="mt-5 flex items-center justify-end gap-3">
                <Close asChild={true}>
                  <Button variant="ghost">取消</Button>
                </Close>
                <Close asChild={true}>
                  <Button
                    onClick={() => props.onChangeApiBaseUrl(draft)}
                    variant="primary"
                  >
                    保存
                  </Button>
                </Close>
              </div>
            </div>
          </Card>
        </Content>
      </Portal>
    </Root>
  );
}
