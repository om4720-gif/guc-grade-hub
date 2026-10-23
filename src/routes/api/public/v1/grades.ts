import { createFileRoute } from "@tanstack/react-router";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

export const Route = createFileRoute("/api/public/v1/grades")({
  server: {
    handlers: {
      OPTIONS: async () => new Response(null, { status: 204, headers: cors }),
      GET: async ({ request }) => {
        const m = /^Bearer\s+(guc_[a-f0-9]{48})$/.exec(request.headers.get("authorization") ?? "");
        if (!m) return Response.json({ error: "Missing or invalid API key" }, { status: 401, headers: cors });
        const { sha256Hex } = await import("@/server/crypto.server");
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { data: key } = await supabaseAdmin
          .from("api_keys")
          .select("id,user_id")
          .eq("key_hash", await sha256Hex(m[1]))
          .maybeSingle();
        if (!key) return Response.json({ error: "Invalid API key" }, { status: 401, headers: cors });
        await supabaseAdmin.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", key.id);
        const [{ data: grades }, { data: acc }] = await Promise.all([
          supabaseAdmin
            .from("grades")
            .select("course,item,grade,updated_at")
            .eq("user_id", key.user_id)
            .order("course"),
          supabaseAdmin.from("guc_accounts").select("last_synced_at").eq("user_id", key.user_id).maybeSingle(),
        ]);
        return Response.json(
          { last_synced_at: acc?.last_synced_at ?? null, grades: grades ?? [] },
          { headers: cors },
        );
      },
    },
  },
});
