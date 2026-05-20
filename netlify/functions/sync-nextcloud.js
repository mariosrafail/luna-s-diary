const NEXTCLOUD_WEBDAV_URL = process.env.NEXTCLOUD_WEBDAV_URL || "https://nextcloud.stinis.ddns.net/public.php/webdav/";
const NEXTCLOUD_SHARE_TOKEN = process.env.NEXTCLOUD_SHARE_TOKEN;
const NEXTCLOUD_SHARE_PASSWORD = process.env.NEXTCLOUD_SHARE_PASSWORD || "";

const typeLabels = {
  period: "Περίοδος",
  medicine: "Φάρμακο",
  injection: "Ένεση",
  side: "Παρενέργεια",
  intimacy: "Προσωπικό",
  note: "Σημείωση"
};

function response(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    },
    body: JSON.stringify(body)
  };
}

function cleanEntry(entry) {
  return {
    id: String(entry.id || ""),
    type: typeLabels[entry.type] ? entry.type : "note",
    label: typeLabels[entry.type] || typeLabels.note,
    date: String(entry.date || ""),
    title: String(entry.a || ""),
    detail: String(entry.b || ""),
    extra: String(entry.c || ""),
    notes: String(entry.notes || ""),
    createdAt: String(entry.createdAt || "")
  };
}

function organizeEntries(entries) {
  const cleanEntries = entries
    .filter(entry => entry && entry.date)
    .map(cleanEntry)
    .sort((a, b) => `${b.date} ${b.createdAt}`.localeCompare(`${a.date} ${a.createdAt}`));

  const days = cleanEntries.reduce((acc, entry) => {
    if (!acc[entry.date]) {
      acc[entry.date] = {
        date: entry.date,
        counts: {},
        entries: []
      };
    }
    acc[entry.date].entries.push(entry);
    acc[entry.date].counts[entry.type] = (acc[entry.date].counts[entry.type] || 0) + 1;
    return acc;
  }, {});

  return {
    app: "lunas-diary",
    version: 1,
    syncedAt: new Date().toISOString(),
    totalEntries: cleanEntries.length,
    counts: cleanEntries.reduce((acc, entry) => {
      acc[entry.type] = (acc[entry.type] || 0) + 1;
      return acc;
    }, {}),
    days
  };
}

exports.handler = async event => {
  if (event.httpMethod !== "POST") {
    return response(405, { ok: false, error: "Method not allowed" });
  }

  if (!NEXTCLOUD_SHARE_TOKEN) {
    return response(500, { ok: false, error: "Missing NEXTCLOUD_SHARE_TOKEN" });
  }

  try {
    const payload = JSON.parse(event.body || "{}");
    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    const organized = organizeEntries(entries);
    const auth = Buffer.from(`${NEXTCLOUD_SHARE_TOKEN}:${NEXTCLOUD_SHARE_PASSWORD}`).toString("base64");

    const nextcloudResponse = await fetch(NEXTCLOUD_WEBDAV_URL, {
      method: "PUT",
      headers: {
        authorization: `Basic ${auth}`,
        "content-type": "application/json; charset=utf-8"
      },
      body: JSON.stringify(organized, null, 2)
    });

    if (!nextcloudResponse.ok) {
      const text = await nextcloudResponse.text();
      return response(502, {
        ok: false,
        error: "Nextcloud write failed",
        status: nextcloudResponse.status,
        detail: text.slice(0, 500)
      });
    }

    return response(200, { ok: true, syncedAt: organized.syncedAt, totalEntries: organized.totalEntries });
  } catch (error) {
    return response(400, { ok: false, error: error.message || "Invalid request" });
  }
};
