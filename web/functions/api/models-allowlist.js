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

  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "public, max-age=60",
    "access-control-allow-origin": "*",
  };

  const upstream = `${R2_PUBLIC_BASE}/${env}/sealed-models/allowlist.json`;
  try {
    const resp = await fetch(upstream, {
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (resp.ok) {
      return new Response(await resp.text(), { status: 200, headers });
    }
  } catch (_) {
    // continue to static
  }

  try {
    const local = new URL(`/sealed-models/${env}/allowlist.json`, url.origin);
    const localResp = await fetch(local.toString());
    if (localResp.ok) {
      return new Response(await localResp.text(), { status: 200, headers });
    }
  } catch (_) {
    // continue
  }

  return new Response(
    JSON.stringify({
      error: "sealed-models allowlist not found",
      env,
      tried: [upstream, `/sealed-models/${env}/allowlist.json`],
    }),
    { status: 404, headers },
  );
}
