/**
 * reDTF CORS Proxy — общее ядро обработки запросов с защитой от флуда и атак
 */

type RouteCategory = "login" | "refresh" | "search";
type RateRule = { max: number; windowMs: number };

const LIMITS: Record<RouteCategory, RateRule[]> = {
	login: [{ max: 5, windowMs: 30 * 60 * 1000 }], // 5 запросов на 30 минут
	refresh: [{ max: 2, windowMs: 60 * 1000 }], // 2 запроса в минуту
	search: [
		{ max: 5, windowMs: 60 * 1000 }, // до 5 запросов в минуту
		{ max: 30, windowMs: 60 * 60 * 1000 }, // до 30 запросов в час
	],
};

const SEARCH_PATHS = new Set([
	"/v2.10/search/posts",
	"/v2.51/search/subsites",
	"/v2.51/search/comments",
]);

const MAX_BODY_BYTES = 32 * 1024; // 32 KB максимум для POST-запросов
const rateLimitStore = new Map<string, number[]>();

function getRouteCategory(method: string, pathname: string): RouteCategory | null {
	if (method === "POST" && pathname === "/v3.4/auth/email/login") return "login";
	if (method === "POST" && pathname === "/v3.4/auth/refresh") return "refresh";
	if (method === "GET" && SEARCH_PATHS.has(pathname)) return "search";
	return null;
}

function getClientIp(request: Request): string {
	const cf = request.headers.get("cf-connecting-ip");
	if (cf) return cf.trim();
	const xff = request.headers.get("x-forwarded-for");
	if (xff) return xff.split(",")[0].trim();
	return "unknown";
}

function maxWindowFor(category: RouteCategory): number {
	const rules = LIMITS[category];
	if (!rules || rules.length === 0) return 60_000;
	return Math.max(...rules.map((r) => r.windowMs));
}

function checkRateLimit(category: RouteCategory, ip: string, now = Date.now()): { limited: boolean; retryAfter: number } {
	const rules = LIMITS[category];
	const key = `${category}:${ip}`;
	const maxWindowMs = maxWindowFor(category);

	// Очистка при разрастании памяти
	if (rateLimitStore.size > 1000) {
		for (const [k, timestamps] of rateLimitStore) {
			const cat = k.split(":")[0] as RouteCategory;
			const win = maxWindowFor(cat);
			if (timestamps.length === 0 || timestamps[timestamps.length - 1] < now - win) {
				rateLimitStore.delete(k);
			}
		}
	}

	const timestamps = (rateLimitStore.get(key) || []).filter((t) => t > now - maxWindowMs);

	let retryAfter = 0;
	for (const { max, windowMs } of rules) {
		const inWindow = timestamps.filter((t) => t > now - windowMs);
		if (inWindow.length >= max) {
			const wait = Math.max(1, Math.ceil((inWindow[0] + windowMs - now) / 1000));
			if (wait > retryAfter) retryAfter = wait;
		}
	}

	if (retryAfter > 0) {
		rateLimitStore.set(key, timestamps);
		return { limited: true, retryAfter };
	}

	timestamps.push(now);
	rateLimitStore.set(key, timestamps);
	return { limited: false, retryAfter: 0 };
}

export async function handleRequest(request: Request): Promise<Response> {
	const url = new URL(request.url);
	const corsHeaders: Record<string, string> = {
		"Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "*",
		"Access-Control-Allow-Credentials": "true",
	};

	if (request.method === "OPTIONS") {
		return new Response(null, { status: 204, headers: corsHeaders });
	}

	// Минимальный пинг для проверки в браузере
	if (url.pathname === "/" || url.pathname === "") {
		return Response.json({ ok: true, message: "reDTF proxy ready" }, { headers: corsHeaders });
	}

	// 1. Белый список маршрутов
	const category = getRouteCategory(request.method, url.pathname);
	if (!category) {
		return Response.json({ error: "Endpoint not allowed" }, { status: 403, headers: corsHeaders });
	}

	// 2. Ограничение размера входящего тела
	let body: ArrayBuffer | undefined;
	if (request.method !== "GET" && request.method !== "HEAD") {
		const contentLength = Number(request.headers.get("content-length") || 0);
		if (contentLength > MAX_BODY_BYTES) {
			return Response.json({ error: "Payload too large" }, { status: 413, headers: corsHeaders });
		}
		body = await request.arrayBuffer();
		if (body.byteLength > MAX_BODY_BYTES) {
			return Response.json({ error: "Payload too large" }, { status: 413, headers: corsHeaders });
		}
	}

	// 3. Рейт-лимит по IP
	const ip = getClientIp(request);
	const { limited, retryAfter } = checkRateLimit(category, ip);
	if (limited) {
		return Response.json(
			{ error: `Too many requests for ${category}. Try again in ${retryAfter}s.` },
			{
				status: 429,
				headers: {
					...corsHeaders,
					"Retry-After": String(retryAfter),
				},
			}
		);
	}

	// 4. Проксирование запроса к API DTF
	try {
		const targetUrl = new URL(url.pathname + url.search, "https://api.dtf.ru");
		const reqHeaders = new Headers(request.headers);
		for (const h of ["host", "origin", "referer", "cf-connecting-ip", "cf-ray", "accept-encoding", "content-length"]) {
			reqHeaders.delete(h);
		}
		reqHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36");

		const response = await fetch(targetUrl, {
			method: request.method,
			headers: reqHeaders,
			body,
		});

		const resHeaders = new Headers(response.headers);
		for (const [k, v] of Object.entries(corsHeaders)) resHeaders.set(k, v);
		for (const h of ["content-encoding", "content-length", "content-security-policy"]) {
			resHeaders.delete(h);
		}

		return new Response(await response.text(), {
			status: response.status,
			headers: resHeaders,
		});
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return Response.json({ error: message }, { status: 502, headers: corsHeaders });
	}
}
