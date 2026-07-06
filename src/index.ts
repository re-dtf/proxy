export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // Если это OPTIONS (CORS preflight)
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "*",
          "Access-Control-Max-Age": "86400",
        }
      });
    }

    // Собираем новый URL к DTF API (проксируем путь, например /v3.4/auth/email/login)
    const targetUrl = new URL(`https://api.dtf.ru${url.pathname}${url.search}`);
    
    // Клонируем запрос, чтобы переслать его
    const proxyRequest = new Request(targetUrl.toString(), request);
    
    // Запрашиваем оригинальный API
    const response = await fetch(proxyRequest);
    
    // Клонируем ответ, чтобы добавить CORS
    const proxyResponse = new Response(response.body, response);
    proxyResponse.headers.set("Access-Control-Allow-Origin", "*");
    
    return proxyResponse;
  }
};
