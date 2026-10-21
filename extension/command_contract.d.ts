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
    status: { };
    lock: { operationId: string; };
    managerVaults: { };
    managerUnlock: { operationId: string; vaultFile?: string; password?: string; keyPath?: string; };
    managerList: { query?: string; };
    managerItem: { entryId: number; expectedSession: string; reveal?: boolean; };
    managerCopy: { operationId: string; entryId: number; expectedSession: string; };
    managerAdd: { operationId: string; item: ManagementInput; expectedSession: string; };
    managerUpdate: { operationId: string; entryId: number; expectedRevision: number; expectedSession: string; item: ManagementInput; };
    managerDelete: { operationId: string; entryId: number; expectedRevision: number; expectedSession: string; };
    managerDuoRequests: { entryId: number; expectedSession: string; };
    managerDuoRespond: { operationId: string; entryId: number; requestId: string; fingerprint: string; approve: boolean; expectedSession: string; verificationCode?: string; };
    getAutofillItems: { };
    getLoginItems: { domain: string; };
    getDuoItems: { domain: string; };
    getLoginItem: { domain: string; entryId: number; expectedRevision: number; expectedSession: string; };
    getAutofillItem: { entryId: number; expectedRevision: number; expectedSession: string; };
    getTotp: { operationId: string; domain: string; entryId: number; expectedRevision: number; expectedSession: string; };
    saveCredentials: { operationId: string; domain: string; password: string; name: string; expectedSession: string; username?: string; };
    updateCredentials: { operationId: string; domain: string; entryId: number; password: string; expectedRevision: number; expectedSession: string; username?: string; };
    operationStatus: { operationId: string; };
}
export interface NativeResults {
    status: ServerStatus;
    lock: string | OperationReceipt;
    managerVaults: string[];
    managerUnlock: string | OperationReceipt;
    managerList: ItemPage;
    managerItem: ItemDetail;
    managerCopy: string | OperationReceipt;
    managerAdd: string | OperationReceipt;
    managerUpdate: string | OperationReceipt;
    managerDelete: string | OperationReceipt;
    managerDuoRequests: DuoRequest[];
    managerDuoRespond: string | OperationReceipt;
    getAutofillItems: ItemSummary[];
    getLoginItems: ItemSummary[];
    getDuoItems: ItemSummary[];
    getLoginItem: BrowserLogin;
    getAutofillItem: AutofillItem;
    getTotp: Authenticator | OperationReceipt;
    saveCredentials: string | OperationReceipt;
    updateCredentials: string | OperationReceipt;
    operationStatus: OperationReceipt;
}
export type NativeAction = keyof NativeRequests;
export interface NativePolicy { readonly mutates: boolean; readonly lane: "control" | "work" | "duo"; readonly timeoutMs: number; readonly allowedSenders: readonly SenderRole[]; readonly requiredFields: readonly string[]; readonly optionalFields: readonly string[]; readonly resultShape: string; }
export const protocolVersion: 2;
export const operations: Readonly<Record<NativeAction, NativePolicy>>;
export function validateRequest<K extends NativeAction>(action: K, fields: NativeRequests[K]): NativeRequests[K];
export function validateResult<K extends NativeAction>(action: K, data: unknown): NativeResults[K];
export type NativeResponse<K extends NativeAction> = { id: number; protocolVersion: number; nativeVersion: string; sessionId?: string; success: true; data: NativeResults[K]; operation?: OperationReceipt; operationId?: string } | { id: number; protocolVersion: number; nativeVersion: string; sessionId?: string; success: false; error: string; uncertain?: boolean; operationId?: string; operation?: OperationReceipt; code?: number };
