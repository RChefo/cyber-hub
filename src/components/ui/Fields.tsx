import { Description, FieldError, Input, Label, ListBox, SearchField, Select, Switch, TextArea, TextField } from "@heroui/react";
import type { Key, ReactNode } from "react";
import { cn } from "@/lib/utils";

interface TextInputProps {
  label?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  description?: ReactNode;
  error?: string | null;
  isRequired?: boolean;
  isDisabled?: boolean;
  type?: "text" | "url" | "password" | "date" | "number";
  mono?: boolean;
  className?: string;
  autoFocus?: boolean;
  onEnter?: () => void;
  "aria-label"?: string;
}

export function TextInput({ label, value, onChange, placeholder, description, error, isRequired, isDisabled, type = "text", mono, className, autoFocus, onEnter, ...rest }: TextInputProps) {
  return (
    <TextField
      className={cn("flex flex-col gap-1.5", className)}
      value={value}
      onChange={onChange}
      isRequired={isRequired}
      isDisabled={isDisabled}
      isInvalid={!!error}
      type={type}
      aria-label={rest["aria-label"] ?? (label ? undefined : placeholder)}
    >
      {label && <Label className="text-[12.5px] font-medium text-muted">{label}</Label>}
      <Input
        placeholder={placeholder}
        autoFocus={autoFocus}
        spellCheck={false}
        autoComplete="off"
        className={cn("h-9 text-[13.5px]", mono && "font-mono text-[12.5px]")}
        onKeyDown={(e) => {
          if (e.key === "Enter" && onEnter) onEnter();
        }}
      />
      {description && !error && <Description className="text-[12px] text-muted">{description}</Description>}
      {error && <FieldError className="text-[12px]">{error}</FieldError>}
    </TextField>
  );
}

export function TextAreaInput({
  label,
  value,
  onChange,
  placeholder,
  rows = 4,
  mono,
  description,
  className,
  isRequired,
  "aria-label": ariaLabel,
}: {
  label?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  rows?: number;
  mono?: boolean;
  description?: ReactNode;
  className?: string;
  isRequired?: boolean;
  "aria-label"?: string;
}) {
  return (
    <TextField className={cn("flex flex-col gap-1.5", className)} value={value} onChange={onChange} isRequired={isRequired} aria-label={ariaLabel ?? (label ? undefined : placeholder)}>
      {label && <Label className="text-[12.5px] font-medium text-muted">{label}</Label>}
      <TextArea
        rows={rows}
        placeholder={placeholder}
        spellCheck={false}
        className={cn("min-h-0 resize-y text-[13.5px] leading-relaxed", mono && "font-mono text-[12.5px]")}
      />
      {description && <Description className="text-[12px] text-muted">{description}</Description>}
    </TextField>
  );
}

export interface Option {
  id: string;
  label: string;
  description?: string;
}

export function SelectInput({
  label,
  value,
  onChange,
  options,
  placeholder = "Select…",
  className,
  isDisabled,
  "aria-label": ariaLabel,
}: {
  label?: string;
  value: string | null;
  onChange: (v: string) => void;
  options: Option[];
  placeholder?: string;
  className?: string;
  isDisabled?: boolean;
  "aria-label"?: string;
}) {
  return (
    <Select
      className={cn("flex flex-col gap-1.5", className)}
      selectedKey={value}
      onSelectionChange={(k: Key | null) => k != null && onChange(String(k))}
      placeholder={placeholder}
      isDisabled={isDisabled}
      aria-label={ariaLabel ?? (label ? undefined : placeholder)}
    >
      {label && <Label className="text-[12.5px] font-medium text-muted">{label}</Label>}
      <Select.Trigger className="h-9 text-[13.5px]">
        <Select.Value className="font-normal" />
        <Select.Indicator />
      </Select.Trigger>
      <Select.Popover>
        <ListBox className="max-h-72 overflow-auto">
          {options.map((o) => (
            <ListBox.Item key={o.id} id={o.id} textValue={o.label} className="text-[13.5px]">
              <div className="flex flex-col">
                <span>{o.label}</span>
                {o.description && <span className="text-[12px] text-muted">{o.description}</span>}
              </div>
              <ListBox.ItemIndicator />
            </ListBox.Item>
          ))}
        </ListBox>
      </Select.Popover>
    </Select>
  );
}

export function SwitchInput({ label, isSelected, onChange, description }: { label: string; isSelected: boolean; onChange: (v: boolean) => void; description?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <Switch isSelected={isSelected} onChange={onChange} size="sm">
        <Switch.Content className="flex items-center gap-2.5">
          <Switch.Control>
            <Switch.Thumb />
          </Switch.Control>
          <Label className="text-[13.5px] font-normal text-foreground">{label}</Label>
        </Switch.Content>
      </Switch>
      {description && <p className="pl-[46px] text-[12px] text-muted">{description}</p>}
    </div>
  );
}

export function SearchInput({ value, onChange, placeholder = "Search", className, autoFocus }: { value: string; onChange: (v: string) => void; placeholder?: string; className?: string; autoFocus?: boolean }) {
  return (
    <SearchField value={value} onChange={onChange} aria-label={placeholder} className={cn("w-full", className)}>
      <SearchField.Group className="h-9">
        <SearchField.SearchIcon />
        <SearchField.Input placeholder={placeholder} autoFocus={autoFocus} className="text-[13.5px]" />
        <SearchField.ClearButton />
      </SearchField.Group>
    </SearchField>
  );
}
