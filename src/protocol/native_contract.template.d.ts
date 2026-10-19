// Generated from Rust native-operation policy; do not edit by hand.
export as namespace PasswordManagerCommandContract;
export type SenderRole = "manager" | "popup" | "prompt" | "picker" | "duoPrompt" | "background";
export type ItemKind = "login" | "secure-note" | "payment-card" | "identity" | "wifi" | "software-license" | "ssh-key" | "api-secret";
export type OperationState = "pending" | "committed" | "committed_durability_unknown" | "failed" | "unknown";
export interface OperationReceipt { operationId: string; state: OperationState; revision: number | null; }
export interface ItemSummary { id: number; revision: number; name: string; username: string | null; kind: ItemKind; urls: string[]; has_totp: boolean; has_duo: boolean; }
export interface ItemPage { items: ItemSummary[]; total: number; }
export interface CustomField { name: string; value: string; secret: boolean; }
export interface ItemDetail extends ItemSummary { notes: string | null; password: string | null; has_secret: boolean; fields: { name: string; value: string | null; secret: boolean }[]; created: string; modified: string; }
export interface BrowserLogin { id: number; revision: number; name: string; username: string | null; password: string; has_totp: boolean; }
export interface AutofillItem { id: number; revision: number; name: string; kind: ItemKind; username: string | null; primary_secret: string; custom_fields: CustomField[]; }
export interface ManagementInput { name: string; username?: string; password?: string | null; kind?: ItemKind; urls?: string[]; notes?: string; fields?: CustomField[]; removeFields?: string[]; removeUrls?: string[]; }
export interface ServerStatus { locked: boolean; version: string; warning: string | null; }
export type Authenticator = { code: string; mode: "totp"; expires_in: number; counter: null } | { code: string; mode: "hotp"; expires_in: null; counter: string };
export interface DuoRequest { id: string; application: string; username: string; location: string; summary: string; expires_at: number; code_digits: number | null; unsupported: string | null; fingerprint: string; }
export interface NativeRequests {
__REQUESTS__}
export interface NativeResults {
__RESULTS__}
export type NativeAction = keyof NativeRequests;
export interface NativePolicy { readonly mutates: boolean; readonly lane: "control" | "work" | "duo"; readonly timeoutMs: number; readonly allowedSenders: readonly SenderRole[]; readonly requiredFields: readonly string[]; readonly optionalFields: readonly string[]; readonly resultShape: string; }
export const protocolVersion: __PROTOCOL_VERSION__;
export const operations: Readonly<Record<NativeAction, NativePolicy>>;
export function validateRequest<K extends NativeAction>(action: K, fields: NativeRequests[K]): NativeRequests[K];
export function validateResult<K extends NativeAction>(action: K, data: unknown): NativeResults[K];
export type NativeResponse<K extends NativeAction> = { id: number; protocolVersion: number; nativeVersion: string; success: true; data: NativeResults[K]; operation?: OperationReceipt; operationId?: string } | { id: number; protocolVersion: number; nativeVersion: string; success: false; error: string; uncertain?: boolean; operationId?: string; operation?: OperationReceipt; code?: number };
