const R2_PUBLIC_BASE = "https://pub-84b99924d959400aa97608c84bbd8000.r2.dev";

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  let key = (url.searchParams.get("key") || "").trim().replace(/^\/+/, "");
  if (!key || key.includes("..") || !/^[a-z0-9/_ .-]+$/i.test(key)) {
    return new Response(JSON.stringify({ error: "invalid key" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }
  if (!key.includes("/sealed-initrd/")) {
    return new Response(JSON.stringify({ error: "key must be under sealed-initrd" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const upstream = `${R2_PUBLIC_BASE}/${key}`;
  const resp = await fetch(upstream, {
    cf: { cacheTtl: 300, cacheEverything: true },
  });
  const body = await resp.arrayBuffer();
  const ct = resp.headers.get("content-type") || guessContentType(key);
  return new Response(body, {
    status: resp.status,
    headers: {
      "content-type": ct,
      "cache-control": "public, max-age=300",
      "access-control-allow-origin": "*",
    },
  });
}

function guessContentType(key) {
  if (key.endsWith(".json")) return "application/json; charset=utf-8";
  if (key.endsWith(".txt")) return "text/plain; charset=utf-8";
  return "application/octet-stream";
}
