/**
 * Mistral Vibe browser sign-in: the same flow the Vibe Code CLI uses
 * (mistralai/mistral-vibe, vibe/core/config/_defaults.py). Mistral's console
 * provisions and stores a regular API key; the browser session does the
 * authorizing, so no password ever transits this code.
 *
 * Flow, verified 2026-09-30 against a Pro plan:
 *  1. POST https://console.mistral.ai/api/vibe/sign-in
 *     { code_challenge, code_challenge_method: "S256" }  (no auth header)
 *     -> { process_id, sign_in_url, poll_url, expires_at }
 *  2. The user approves in the browser at sign_in_url.
 *  3. Poll GET poll_url -> { status: "pending" | "completed" | ... ,
 *     exchange_token? } (HTTP 410 once the process expires).
 *  4. POST .../vibe/sign-in/{process_id}/exchange
 *     { exchange_token, code_verifier } -> { api_key }
 *
 * The minted key authenticates https://api.mistral.ai/v1 over the plain
 * `openai-completions` transport; its usage is billed against the Vibe Code
 * quota of the signed-in plan, not against pay-as-you-go API credits
 * (observed 2026-09-30: sustained traffic moved the plan's Vibe Code
 * counter, not the API credits counter).
 */
import { createHash, randomBytes } from "node:crypto";

import * as AIError from "../../error";
import type { FetchImpl } from "../../types";
import type { OAuthController, OAuthCredentials } from "./types";

const AUTH_BASE_URL = "https://console.mistral.ai";
const AUTH_API_BASE_URL = `${AUTH_BASE_URL}/api`;
const SIGN_IN_PATH = "/vibe/sign-in";
const POLL_INTERVAL_SECONDS = 3;
// The console session is the authorizer; the minted key has no documented
// expiry, so the credential outlives any OAuth window.
const CREDENTIAL_EXPIRY_MS = 10 * 365 * 24 * 60 * 60 * 1000;

type SignInProcess = {
	processId: string;
	signInUrl: string;
	pollUrl: string;
	expiresAtMs: number;
};

type PollPayload = {
	status: "pending" | "completed" | "expired" | "denied" | "error";
	exchangeToken?: string;
	message?: string;
};

/** Narrow a decoded JSON body at the network boundary, once per response. */
function asRecord(value: unknown, message: string): Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new AIError.OAuthError(`${message}: malformed JSON response`, { kind: "validation", provider: "mistral" });
	}
	return value as Record<string, unknown>;
}

function requiredString(record: Record<string, unknown>, field: string, message: string): string {
	const value = record[field];
	if (typeof value === "string" && value.length > 0) return value;
	throw new AIError.OAuthError(`${message}: response is missing "${field}"`, {
		kind: "validation",
		provider: "mistral",
	});
}

/** Reject any URL the sign-in server returns outside its own origin. */
function assertUrlUnder(value: string, baseUrl: string, message: string): string {
	const url = new URL(value);
	const base = new URL(baseUrl);
	if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname.replace(/\/$/, ""))) {
		throw new AIError.OAuthError(`${message}: unexpected URL ${value}`, { kind: "validation", provider: "mistral" });
	}
	return value;
}

async function readJson(response: Response, message: string): Promise<unknown> {
	if (!response.ok)
		throw new AIError.OAuthError(`${message}: HTTP ${response.status}`, { kind: "validation", provider: "mistral" });
	try {
		return await response.json();
	} catch (cause) {
		throw new AIError.OAuthError(`${message}: malformed JSON response`, {
			kind: "validation",
			provider: "mistral",
			cause,
		});
	}
}

async function postJson(
	url: string,
	body: Record<string, string>,
	fetchImpl: FetchImpl,
	message: string,
): Promise<unknown> {
	const response = await fetchImpl(url, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	return readJson(response, message);
}

async function startSignIn(codeChallenge: string, fetchImpl: FetchImpl): Promise<SignInProcess> {
	const message = "Failed to start Mistral browser sign-in";
	const payload = asRecord(
		await postJson(
			`${AUTH_API_BASE_URL}${SIGN_IN_PATH}`,
			{ code_challenge: codeChallenge, code_challenge_method: "S256" },
			fetchImpl,
			message,
		),
		message,
	);
	const expiresAtMs = Date.parse(requiredString(payload, "expires_at", message));
	if (!Number.isFinite(expiresAtMs)) {
		throw new AIError.OAuthError(`${message}: invalid expires_at`, { kind: "validation", provider: "mistral" });
	}
	return {
		processId: requiredString(payload, "process_id", message),
		signInUrl: assertUrlUnder(requiredString(payload, "sign_in_url", message), AUTH_BASE_URL, message),
		pollUrl: assertUrlUnder(requiredString(payload, "poll_url", message), AUTH_API_BASE_URL, message),
		expiresAtMs,
	};
}

async function pollSignIn(process: SignInProcess, fetchImpl: FetchImpl): Promise<PollPayload> {
	const message = "Mistral sign-in status unavailable";
	const response = await fetchImpl(process.pollUrl);
	// The process is gone: 410 instead of a status payload.
	if (response.status === 410) return { status: "expired" };
	const payload = asRecord(await readJson(response, message), message);
	const status = payload.status;
	if (
		status !== "pending" &&
		status !== "completed" &&
		status !== "expired" &&
		status !== "denied" &&
		status !== "error"
	) {
		throw new AIError.OAuthError("Mistral sign-in returned an unknown state", {
			kind: "validation",
			provider: "mistral",
		});
	}
	const exchangeToken = payload.exchange_token;
	const detail = payload.message;
	return {
		status,
		exchangeToken: typeof exchangeToken === "string" && exchangeToken.length > 0 ? exchangeToken : undefined,
		message: typeof detail === "string" && detail.length > 0 ? detail : undefined,
	};
}

async function waitForCompletion(process: SignInProcess, ctrl: OAuthController, fetchImpl: FetchImpl): Promise<string> {
	while (Date.now() < process.expiresAtMs) {
		if (ctrl.signal?.aborted) throw new AIError.LoginCancelledError("Login cancelled");
		const result = await pollSignIn(process, fetchImpl);
		switch (result.status) {
			case "pending":
				await Bun.sleep(POLL_INTERVAL_SECONDS * 1000);
				break;
			case "completed":
				if (result.exchangeToken) return result.exchangeToken;
				throw new AIError.OAuthError("Mistral sign-in completed without an exchange token", {
					kind: "validation",
					provider: "mistral",
				});
			case "expired":
				throw new AIError.OAuthError("Mistral sign-in expired; run /login again", {
					kind: "polling",
					provider: "mistral",
				});
			case "denied":
				throw new AIError.OAuthError("Mistral sign-in was denied", { kind: "polling", provider: "mistral" });
			case "error":
				throw new AIError.OAuthError(result.message ?? "Mistral sign-in failed", {
					kind: "polling",
					provider: "mistral",
				});
		}
	}
	throw new AIError.OAuthError("Mistral sign-in timed out", { kind: "polling", provider: "mistral" });
}

async function exchangeForApiKey(
	process: SignInProcess,
	exchangeToken: string,
	codeVerifier: string,
	fetchImpl: FetchImpl,
): Promise<string> {
	const message = "Failed to exchange Mistral sign-in for an API key";
	const payload = asRecord(
		await postJson(
			`${AUTH_API_BASE_URL}${SIGN_IN_PATH}/${process.processId}/exchange`,
			{ exchange_token: exchangeToken, code_verifier: codeVerifier },
			fetchImpl,
			message,
		),
		message,
	);
	return requiredString(payload, "api_key", message);
}

/** `login "custom" hook="mistral-vibe-sign-in"`: whole-flow login for the Mistral provider. */
export async function loginMistralVibeSignIn(ctrl: OAuthController): Promise<OAuthCredentials> {
	const fetchImpl = ctrl.fetch ?? fetch;
	const codeVerifier = randomBytes(64).toString("base64url");
	const codeChallenge = createHash("sha256").update(codeVerifier, "ascii").digest("base64url");
	const process = await startSignIn(codeChallenge, fetchImpl);
	ctrl.onAuth?.({
		url: process.signInUrl,
		instructions: "Sign in with your Mistral account (Pro plan or higher), then return here.",
	});
	ctrl.onProgress?.("Waiting for Mistral sign-in to complete...");
	const exchangeToken = await waitForCompletion(process, ctrl, fetchImpl);
	ctrl.onProgress?.("Exchanging sign-in for a Mistral API key...");
	const apiKey = await exchangeForApiKey(process, exchangeToken, codeVerifier, fetchImpl);
	// The refresh token slot carries a sentinel, not a real grant: the key is
	// durable and there is nothing to refresh. `refresh "none"` in the rule
	// keeps the engine from ever presenting it.
	return { access: apiKey, refresh: "mistral-browser-sign-in", expires: Date.now() + CREDENTIAL_EXPIRY_MS };
}
