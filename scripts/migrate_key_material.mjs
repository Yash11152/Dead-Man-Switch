// scripts/migrate_key_material.mjs
// Retry-safe, zero-loss migration script for recipient_claim_tokens.key_material.
// Performs byte-for-byte decryption verification before updating the database.
// NEVER nullifies or drops plaintext key_material until verification is complete.

import assert from 'assert';
import { createClient } from '@supabase/supabase-js';
import { encryptKeyMaterial, decryptKeyMaterial } from './serverCrypto.mjs';

async function runMigration() {
  console.log('🔒 Starting Recipient Key Material Encryption Migration...\n');

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    throw new Error('Supabase environment credentials not configured.');
  }

  const supabase = createClient(supabaseUrl, supabaseKey);

  // 1. Fetch rows that have plaintext key_material but no encrypted_key_material yet
  const { data: pendingRows, error: fetchErr } = await supabase
    .from('recipient_claim_tokens')
    .select('id, switch_id, recipient_id, key_material, encrypted_key_material')
    .not('key_material', 'is', null)
    .is('encrypted_key_material', null);

  if (fetchErr) {
    console.error('Fetch error:', fetchErr);
    throw fetchErr;
  }

  if (!pendingRows || pendingRows.length === 0) {
    console.log('✅ No unmigrated rows found. All records already have encrypted_key_material or lack plaintext keys.');
    return { migratedCount: 0, verifiedCount: 0 };
  }

  console.log(`Found ${pendingRows.length} record(s) requiring envelope encryption migration.`);

  let migratedCount = 0;
  let verifiedCount = 0;

  for (const row of pendingRows) {
    const rawSecret = row.key_material;
    assert.ok(rawSecret, `Row ${row.id} has null key_material`);

    // 2. Encrypt into AES-256-GCM envelope
    const envelopeStr = encryptKeyMaterial(rawSecret);

    // 3. In-memory roundtrip byte-for-byte verification
    const decryptedInMem = decryptKeyMaterial(envelopeStr);
    assert.strictEqual(
      decryptedInMem,
      rawSecret,
      `FATAL: In-memory roundtrip decryption mismatch on token ID ${row.id}`
    );

    // 4. Update row in database (preserves key_material intact)
    const { error: updateErr } = await supabase
      .from('recipient_claim_tokens')
      .update({
        encrypted_key_material: envelopeStr,
        updated_at: new Date().toISOString(),
      })
      .eq('id', row.id);

    if (updateErr) {
      console.error(`Failed to update row ${row.id}:`, updateErr);
      throw updateErr;
    }
    migratedCount++;

    // 5. Re-read from database and verify stored envelope decrypts byte-for-byte
    const { data: storedRow, error: verifyFetchErr } = await supabase
      .from('recipient_claim_tokens')
      .select('id, encrypted_key_material')
      .eq('id', row.id)
      .single();

    if (verifyFetchErr || !storedRow?.encrypted_key_material) {
      throw new Error(`Verification fetch failed for row ${row.id}`);
    }

    const decryptedFromDb = decryptKeyMaterial(storedRow.encrypted_key_material);
    assert.strictEqual(
      decryptedFromDb,
      rawSecret,
      `FATAL: Stored envelope decryption mismatch on token ID ${row.id}`
    );
    verifiedCount++;

    console.log(`  ✓ Token ID ${row.id}: Successfully migrated and verified byte-for-byte.`);
  }

  console.log(`\n🎉 Migration complete! ${migratedCount} migrated, ${verifiedCount} verified byte-for-byte.`);
  return { migratedCount, verifiedCount };
}

// Support direct execution
if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
  runMigration().catch((err) => {
    console.error('Migration failed:', err);
    process.exit(1);
  });
}

export { runMigration };
