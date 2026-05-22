import { createBrowserClient } from "@supabase/ssr";

const supabaseUrl =
  process.env.NEXT_PUBLIC_SUPABASE_URL || "https://placeholder.supabase.co";
const supabaseAnonKey =
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "placeholder-key";

// Singleton browser client — stores the session in cookies (shared with the
// server-side createServerClient) instead of localStorage.
const globalForSupabase = globalThis;

export const supabase =
  globalForSupabase.__algobuddySupabase ||
  createBrowserClient(supabaseUrl, supabaseAnonKey);

if (process.env.NODE_ENV !== "production") {
  globalForSupabase.__algobuddySupabase = supabase;
}
