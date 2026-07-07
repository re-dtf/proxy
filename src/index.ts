export default {
  async fetch(request, env, ctx) {
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

    // Собираем новый URL к DTF API, убирая двойные слеши если они есть
    const cleanPath = url.pathname.replace(/\/+/g, '/');
    const targetUrl = new URL(`https://api.dtf.ru${cleanPath}${url.search}`);
    
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
