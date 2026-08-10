const R2_PUBLIC_BASE = "https://pub-84b99924d959400aa97608c84bbd8000.r2.dev";

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const env = (url.searchParams.get("env") || "staging").trim();
  if (!/^[a-z0-9_-]+$/i.test(env)) {
    return new Response(JSON.stringify({ error: "invalid env" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const upstream = `${R2_PUBLIC_BASE}/${env}/sealed-initrd/latest/release.json`;
  const resp = await fetch(upstream, {
    cf: { cacheTtl: 60, cacheEverything: true },
  });
  const body = await resp.text();
  return new Response(body, {
    status: resp.status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=60",
      "access-control-allow-origin": "*",
    },
  });
}
