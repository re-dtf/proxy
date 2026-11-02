/**
 * reDTF CORS Proxy — общее ядро обработки запросов
 */

export async function handleRequest(request: Request): Promise<Response> {
	const url = new URL(request.url);
	const corsHeaders = {
		"Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
		"Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
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

	try {
		const targetUrl = new URL(url.pathname + url.search, "https://api.dtf.ru");
		const reqHeaders = new Headers(request.headers);
		for (const h of ["host", "origin", "referer", "cf-connecting-ip", "cf-ray", "accept-encoding"]) {
			reqHeaders.delete(h);
		}
		reqHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36");

		const response = await fetch(targetUrl, {
			method: request.method,
			headers: reqHeaders,
			body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
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
