// SPDX-License-Identifier: Apache-2.0
import { AlertDialog, Button, Modal } from "@heroui/react";
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface AppModalProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
  className?: string;
  isDismissable?: boolean;
}

/** HeroUI Modal composed with ExploitX's header/body/footer conventions. */
export function AppModal({ isOpen, onOpenChange, title, description, children, footer, size = "md", className, isDismissable = true }: AppModalProps) {
  return (
    // Controlled overlay without a trigger: drive Modal.Backdrop (React Aria ModalOverlay) directly,
    // so no DialogTrigger/PressResponder is rendered without a pressable child.
    <Modal.Backdrop isOpen={isOpen} onOpenChange={onOpenChange} isDismissable={isDismissable}>
      <Modal.Container size={size} placement="center" scroll="inside">
        <Modal.Dialog className={cn("bg-overlay", size === "lg" && "sm:max-w-[860px]", className)}>
          <Modal.CloseTrigger />
          <Modal.Header className="flex flex-col items-start gap-1">
            <Modal.Heading className="text-[16px] font-semibold tracking-tight">{title}</Modal.Heading>
            {description && <p className="text-[13px] text-muted">{description}</p>}
          </Modal.Header>
          <Modal.Body className="flex flex-col gap-4">{children}</Modal.Body>
          {footer && <Modal.Footer className="flex justify-end gap-2">{footer}</Modal.Footer>}
        </Modal.Dialog>
      </Modal.Container>
    </Modal.Backdrop>
  );
}

interface ConfirmOptions {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  tone?: "danger" | "accent";
}

/**
 * Imperative-feeling confirmation dialog:
 *   const confirm = useConfirm();
 *   if (await confirm.ask({...})) doIt();
 *   ...render {confirm.element}
 */
export function useConfirm() {
  const [state, setState] = useState<(ConfirmOptions & { resolve: (v: boolean) => void }) | null>(null);

  const ask = (opts: ConfirmOptions) => new Promise<boolean>((resolve) => setState({ ...opts, resolve }));
  const close = (v: boolean) => {
    state?.resolve(v);
    setState(null);
  };

  const element = (
    <AlertDialog.Backdrop isOpen={!!state} onOpenChange={(o) => !o && close(false)}>
      <AlertDialog.Container size="sm" placement="center">
          <AlertDialog.Dialog className="bg-overlay">
            <AlertDialog.Header>
              <AlertDialog.Icon status={state?.tone === "accent" ? "accent" : "danger"} />
              <AlertDialog.Heading className="text-[16px] font-semibold">{state?.title}</AlertDialog.Heading>
            </AlertDialog.Header>
            <AlertDialog.Body className="text-[13.5px] text-muted">{state?.body}</AlertDialog.Body>
            <AlertDialog.Footer>
              <Button variant="tertiary" onPress={() => close(false)}>
                Cancel
              </Button>
              <Button variant={state?.tone === "accent" ? "primary" : "danger"} onPress={() => close(true)}>
                {state?.confirmLabel}
              </Button>
            </AlertDialog.Footer>
          </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );

  return { ask, element };
}
