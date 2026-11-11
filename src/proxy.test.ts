import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { handleRequest } from "./proxy.ts";

describe("reDTF proxy security & rate limiting", () => {
	it("обрабатывает OPTIONS preflight", async () => {
		const req = new Request("https://example.com/v3.4/auth/email/login", {
			method: "OPTIONS",
			headers: { Origin: "https://re-dtf.github.io" },
		});
		const res = await handleRequest(req);
		assert.equal(res.status, 204);
		assert.equal(res.headers.get("Access-Control-Allow-Origin"), "https://re-dtf.github.io");
	});

	it("обрабатывает пинг GET /", async () => {
		const req = new Request("https://example.com/", { method: "GET" });
		const res = await handleRequest(req);
		assert.equal(res.status, 200);
		const json = await res.json();
		assert.equal(json.ok, true);
	});

	it("блокирует недопустимые маршруты и методы (403)", async () => {
		const disallowed = [
			new Request("https://example.com/v3.4/auth/email/login", { method: "GET" }),
			new Request("https://example.com/v2.10/search/posts", { method: "POST" }),
			new Request("https://example.com/v2.31/feed", { method: "GET" }),
			new Request("https://example.com/admin", { method: "GET" }),
		];

		for (const req of disallowed) {
			const res = await handleRequest(req);
			assert.equal(res.status, 403, `Ожидался 403 для ${req.method} ${new URL(req.url).pathname}`);
		}
	});

	it("блокирует запросы с телом больше 32 КБ (413)", async () => {
		const largeBody = new Uint8Array(33 * 1024);
		const req = new Request("https://example.com/v3.4/auth/refresh", {
			method: "POST",
			headers: {
				"cf-connecting-ip": "10.0.0.99",
				"content-length": String(largeBody.byteLength),
			},
			body: largeBody,
		});
		const res = await handleRequest(req);
		assert.equal(res.status, 413);
		const json = await res.json();
		assert.equal(json.error, "Payload too large");
	});

	it("применяет рейт-лимит для refresh: 2 запроса в минуту на IP (429 на 3-й)", async () => {
		const ip = "1.2.3.4";
		const makeReq = () =>
			new Request("https://example.com/v3.4/auth/refresh", {
				method: "POST",
				headers: { "cf-connecting-ip": ip },
				body: JSON.stringify({ token: "test" }),
			});

		// Подменим fetch, чтобы не слать реальный сетевой запрос в DTF во время теста
		const originalFetch = globalThis.fetch;
		globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), { status: 200 });

		try {
			const res1 = await handleRequest(makeReq());
			assert.equal(res1.status, 200);

			const res2 = await handleRequest(makeReq());
			assert.equal(res2.status, 200);

			const res3 = await handleRequest(makeReq());
			assert.equal(res3.status, 429);
			assert.ok(res3.headers.get("Retry-After"));

			// Другой IP не должен быть заблокирован
			const reqOtherIp = new Request("https://example.com/v3.4/auth/refresh", {
				method: "POST",
				headers: { "cf-connecting-ip": "1.2.3.5" },
				body: JSON.stringify({ token: "test" }),
			});
			const resOther = await handleRequest(reqOtherIp);
			assert.equal(resOther.status, 200);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it("применяет рейт-лимит для login: 5 запросов на IP (429 на 6-й)", async () => {
		const ip = "1.2.3.10";
		const makeReq = () =>
			new Request("https://example.com/v3.4/auth/email/login", {
				method: "POST",
				headers: { "cf-connecting-ip": ip },
				body: JSON.stringify({ email: "a@b.c", password: "123" }),
			});

		const originalFetch = globalThis.fetch;
		globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), { status: 200 });

		try {
			for (let i = 0; i < 5; i++) {
				const res = await handleRequest(makeReq());
				assert.equal(res.status, 200);
			}

			const res6 = await handleRequest(makeReq());
			assert.equal(res6.status, 429);
			assert.ok(res6.headers.get("Retry-After"));
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it("применяет рейт-лимит для search: 5 запросов на IP (429 на 6-й) суммарно для posts и subsites", async () => {
		const ip = "1.2.3.20";
		const originalFetch = globalThis.fetch;
		globalThis.fetch = async () => new Response(JSON.stringify({ result: [] }), { status: 200 });

		try {
			for (let i = 0; i < 3; i++) {
				const res = await handleRequest(
					new Request(`https://example.com/v2.10/search/posts?q=test${i}`, {
						method: "GET",
						headers: { "cf-connecting-ip": ip },
					})
				);
				assert.equal(res.status, 200);
			}

			for (let i = 0; i < 2; i++) {
				const res = await handleRequest(
					new Request(`https://example.com/v2.51/search/subsites?q=test${i}`, {
						method: "GET",
						headers: { "cf-connecting-ip": ip },
					})
				);
				assert.equal(res.status, 200);
			}

			// 6-й запрос поиска
			const res6 = await handleRequest(
				new Request("https://example.com/v2.10/search/posts?q=overflow", {
					method: "GET",
					headers: { "cf-connecting-ip": ip },
				})
			);
			assert.equal(res6.status, 429);
			assert.ok(res6.headers.get("Retry-After"));
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});
