import { createClient } from './client';

export interface SupabaseInitStatus {
  initialized: boolean;
  hasUrl: boolean;
  hasAnonKey: boolean;
  message: string;
}

export function checkSupabaseInitialization(): SupabaseInitStatus {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  const hasUrl = Boolean(url && url !== 'https://your-supabase-project-id.supabase.co');
  const hasAnonKey = Boolean(anonKey && anonKey !== 'your-supabase-anon-key-here');

  try {
    const supabase = createClient();
    const isReady = Boolean(supabase);

    if (hasUrl && hasAnonKey && isReady) {
      return {
        initialized: true,
        hasUrl: true,
        hasAnonKey: true,
        message: 'Supabase client successfully initialized with environment variables.'
      };
    }

    return {
      initialized: isReady,
      hasUrl,
      hasAnonKey,
      message: 'Supabase client initialized ready. Configure valid project keys in .env.local to connect to your remote instance.'
    };
  } catch (error) {
    return {
      initialized: false,
      hasUrl,
      hasAnonKey,
      message: `Failed to initialize Supabase client: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}
