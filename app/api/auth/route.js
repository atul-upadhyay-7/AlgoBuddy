import { createClient } from "@supabase/supabase-js";
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

// Service-role client is only used for signup so it can create users regardless
// of RLS policies. It is never used for login — that goes through the anon client
// so that Supabase's own per-user RLS applies from the first request.
const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL || "https://placeholder.supabase.co",
  process.env.SUPABASE_SERVICE_KEY || "placeholder-key",
);

async function verifyTurnstile(captchaToken) {
  if (!process.env.TURNSTILE_SECRET_KEY) {
    return { ok: false, message: "Server misconfigured: TURNSTILE_SECRET_KEY is not set" };
  }

  let res;
  try {
    res = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: process.env.TURNSTILE_SECRET_KEY,
          response: captchaToken,
        }),
      },
    );
  } catch {
    return { ok: false, message: "Captcha verification request failed" };
  }

  const data = await res.json();
  if (!data.success) {
    return { ok: false, message: "Captcha verification failed" };
  }
  return { ok: true };
}

export async function POST(req) {
  try {
    let body;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ success: false, message: "Invalid request body" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const { email, password, captchaToken, action, name } = body || {};

    if (!email || !password) {
      return new Response(
        JSON.stringify({ success: false, message: "Email and password are required" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    if (!captchaToken) {
      return new Response(
        JSON.stringify({ success: false, message: "Captcha token missing" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const captcha = await verifyTurnstile(String(captchaToken));
    if (!captcha.ok) {
      return new Response(
        JSON.stringify({ success: false, message: captcha.message }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    if (action === "signup") {
      const { error } = await supabaseAdmin.auth.signUp({
        email,
        password,
        options: {
          data: { display_name: name },
        },
      });

      if (error) {
        return new Response(
          JSON.stringify({ success: false, message: error.message }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }

      return new Response(
        JSON.stringify({
          success: true,
          message: "Signup successful. Verification email sent.",
          trigger: true,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    if (action === "login") {
      const cookieStore = await cookies();

      // createServerClient writes the session into cookies automatically when
      // signInWithPassword resolves. Tokens are never placed in the response body.
      const client = createServerClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL || "https://placeholder.supabase.co",
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "placeholder-key",
        {
          cookies: {
            getAll() {
              return cookieStore.getAll();
            },
            setAll(cookiesToSet) {
              cookiesToSet.forEach(({ name, value, options }) => {
                cookieStore.set(name, value, options);
              });
            },
          },
        },
      );

      const { error } = await client.auth.signInWithPassword({ email, password });

      if (error) {
        return new Response(
          JSON.stringify({ success: false, message: error.message }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }

      // Session is now stored in httpOnly cookies by the createServerClient adapter.
      // Tokens must never appear in the response body — they would be visible in
      // server logs, CDN logs, and browser DevTools Network captures.
      return new Response(
        JSON.stringify({ success: true, message: "Login successful" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    return new Response(
      JSON.stringify({ success: false, message: "Invalid action" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ success: false, message: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
}
