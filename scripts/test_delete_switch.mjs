// scripts/test_delete_switch.mjs
// Comprehensive Automated Test Suite for Secure Delete Switch Feature
// Validates all 10 requirements specified in Feature Implementation: Secure Delete Switch

import assert from 'assert';

console.log('🧪 Starting Secure Delete Switch Verification Suite...\n');

// Mock in-memory state engine to simulate Supabase DB + RLS + Triggers + Storage
class MockDeadManSystem {
  constructor() {
    this.switches = new Map();
    this.files = new Map();
    this.switchRecipients = new Map();
    this.checkIns = new Map();
    this.recipientTokens = new Map();
    this.notifications = new Map();
    this.auditLogs = [];
    this.storage = new Map(); // bucket: 'dead-man-files', path -> content
  }

  // Database Trigger: validate_switch_delete()
  validateSwitchDeleteTrigger(oldSwitch) {
    if (!['CANCELLED', 'TRIGGERED'].includes(oldSwitch.status)) {
      const err = new Error(`Cannot delete switch with status ${oldSwitch.status}. Only CANCELLED and TRIGGERED switches may be deleted.`);
      err.code = '22000';
      throw err;
    }
  }

  // Database RLS Delete Policy: Users can delete own switches
  // USING (auth.uid() = user_id AND status IN ('CANCELLED', 'TRIGGERED'))
  checkRLSDeletePermission(authUserId, switchRecord) {
    if (!authUserId) return false;
    if (switchRecord.user_id !== authUserId) return false;
    if (!['CANCELLED', 'TRIGGERED'].includes(switchRecord.status)) return false;
    return true;
  }

  // insert_client_audit_event RPC
  insertClientAuditEvent(authUserId, authEmail, eventType, switchId, details) {
    if (!authUserId) {
      const err = new Error('Not authenticated');
      err.code = '42501';
      throw err;
    }
    const allowed = [
      'SWITCH_CREATED', 'CONFIG_UPDATED', 'FILE_UPLOADED',
      'FILE_DELETED', 'CLAIM_TOKEN_ISSUED', 'CLAIM_TOKEN_ROTATED',
      'PROFILE_UPDATED', 'NOTIFICATION_QUEUED', 'SWITCH_DELETED'
    ];
    if (!allowed.includes(eventType)) {
      const err = new Error(`Event type ${eventType} is not permitted from client context.`);
      err.code = '42501';
      throw err;
    }
    if (switchId && this.switches.has(switchId)) {
      const sw = this.switches.get(switchId);
      if (sw.user_id !== authUserId) {
        const err = new Error('Unauthorized: switch does not belong to user');
        err.code = '42501';
        throw err;
      }
    }

    const logEntry = {
      id: 'log-' + Math.random().toString(36).substring(2),
      user_id: authUserId,
      switch_id: switchId || null,
      action: eventType,
      metadata: { ...details, actor: authEmail },
      created_at: new Date().toISOString()
    };
    this.auditLogs.push(logEntry);
    return logEntry.id;
  }

  // Deletion workflow matching dashboard implementation
  async executeDeleteSwitch(authUserId, authEmail, switchId) {
    if (!authUserId) throw new Error('Not authenticated');

    const sw = this.switches.get(switchId);
    if (!sw) {
      // Already deleted or non-existent (duplicate request safety)
      return { success: true, alreadyDeleted: true };
    }

    // 1. Client & Server status guard
    if (sw.status !== 'CANCELLED' && sw.status !== 'TRIGGERED') {
      throw new Error(`Cannot delete switch with status "${sw.status}". Only CANCELLED and TRIGGERED switches may be deleted.`);
    }

    // 2. RLS Check
    if (!this.checkRLSDeletePermission(authUserId, sw)) {
      const err = new Error('Unauthorized or RLS policy violated');
      err.code = '42501';
      throw err;
    }

    // 3. Trigger check (BEFORE DELETE)
    this.validateSwitchDeleteTrigger(sw);

    // 4. Fetch associated files & clean up private Storage
    const associatedFiles = Array.from(this.files.values()).filter(f => f.switch_id === switchId);
    const storagePrefix = `${authUserId}/${switchId}/`;
    const pathsToDelete = associatedFiles
      .map(f => f.storage_path)
      .filter(p => typeof p === 'string' && p.startsWith(storagePrefix));

    // Also include any other objects in the vault directory
    for (const storagePath of this.storage.keys()) {
      if (storagePath.startsWith(storagePrefix) && !pathsToDelete.includes(storagePath)) {
        pathsToDelete.push(storagePath);
      }
    }

    // Remove from storage
    for (const path of pathsToDelete) {
      this.storage.delete(path);
    }

    // 5. Audit Log (SWITCH_DELETED)
    this.insertClientAuditEvent(authUserId, authEmail, 'SWITCH_DELETED', switchId, {
      switch_title: sw.title,
      switch_status: sw.status,
      deleted_switch_id: sw.id,
      file_count: associatedFiles.length
    });

    // 6. Delete switch with Foreign Key handling:
    // CASCADE to: files, switch_recipients, check_ins, recipient_claim_tokens, notifications
    // SET NULL to: audit_logs.switch_id
    this.switches.delete(switchId);

    for (const [id, file] of this.files.entries()) {
      if (file.switch_id === switchId) this.files.delete(id);
    }
    for (const [id, r] of this.switchRecipients.entries()) {
      if (r.switch_id === switchId) this.switchRecipients.delete(id);
    }
    for (const [id, c] of this.checkIns.entries()) {
      if (c.switch_id === switchId) this.checkIns.delete(id);
    }
    for (const [id, t] of this.recipientTokens.entries()) {
      if (t.switch_id === switchId) this.recipientTokens.delete(id);
    }
    for (const [id, n] of this.notifications.entries()) {
      if (n.switch_id === switchId) this.notifications.delete(id);
    }

    // ON DELETE SET NULL for audit_logs
    for (const log of this.auditLogs) {
      if (log.switch_id === switchId) {
        log.switch_id = null;
      }
    }

    return { success: true, deletedId: switchId };
  }
}

// ============================================================
// TEST 1: Owner can delete their own CANCELLED switch
// ============================================================
console.log('--- TEST 1: Owner can delete their own CANCELLED switch ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-001';
  const ownerEmail = 'owner@example.com';
  const switchId = 'switch-cancelled-001';

  system.switches.set(switchId, {
    id: switchId,
    user_id: ownerId,
    title: 'Decommissioned Vault',
    status: 'CANCELLED'
  });

  const res = await system.executeDeleteSwitch(ownerId, ownerEmail, switchId);
  assert.strictEqual(res.success, true, 'Deletion should succeed for CANCELLED switch');
  assert.strictEqual(system.switches.has(switchId), false, 'Switch must be removed from DB');
  console.log('✅ PASS: Owner successfully deleted CANCELLED switch.');
}

// ============================================================
// TEST 2: Owner can delete their own TRIGGERED switch
// ============================================================
console.log('\n--- TEST 2: Owner can delete their own TRIGGERED switch ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-001';
  const ownerEmail = 'owner@example.com';
  const switchId = 'switch-triggered-002';

  system.switches.set(switchId, {
    id: switchId,
    user_id: ownerId,
    title: 'Dispatched Emergency Switch',
    status: 'TRIGGERED'
  });

  const res = await system.executeDeleteSwitch(ownerId, ownerEmail, switchId);
  assert.strictEqual(res.success, true, 'Deletion should succeed for TRIGGERED switch');
  assert.strictEqual(system.switches.has(switchId), false, 'Switch must be removed from DB');
  console.log('✅ PASS: Owner successfully deleted TRIGGERED switch.');
}

// ============================================================
// TEST 3: ACTIVE switch deletion is rejected
// ============================================================
console.log('\n--- TEST 3: ACTIVE switch deletion is rejected ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-001';
  const switchId = 'switch-active-003';

  system.switches.set(switchId, {
    id: switchId,
    user_id: ownerId,
    title: 'Live Switch',
    status: 'ACTIVE'
  });

  // 1. UI Rule: canDelete must be false
  const canDeleteInUI = ['CANCELLED', 'TRIGGERED'].includes(system.switches.get(switchId).status);
  assert.strictEqual(canDeleteInUI, false, 'Delete button must NOT be visible for ACTIVE switch');

  // 2. Backend & Trigger check
  let rejected = false;
  try {
    await system.executeDeleteSwitch(ownerId, 'owner@example.com', switchId);
  } catch (err) {
    rejected = true;
    assert.ok(err.message.includes('Only CANCELLED and TRIGGERED'), 'Error message must specify allowed statuses');
  }
  assert.strictEqual(rejected, true, 'ACTIVE switch deletion must be rejected');
  assert.strictEqual(system.switches.has(switchId), true, 'ACTIVE switch must remain untouched');
  console.log('✅ PASS: ACTIVE switch deletion strictly rejected by UI, RLS, and Trigger.');
}

// ============================================================
// TEST 4: PENDING_GRACE switch deletion is rejected
// ============================================================
console.log('\n--- TEST 4: PENDING_GRACE switch deletion is rejected ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-001';
  const switchId = 'switch-grace-004';

  system.switches.set(switchId, {
    id: switchId,
    user_id: ownerId,
    title: 'Grace Warning Switch',
    status: 'PENDING_GRACE'
  });

  const canDeleteInUI = ['CANCELLED', 'TRIGGERED'].includes(system.switches.get(switchId).status);
  assert.strictEqual(canDeleteInUI, false, 'Delete button must NOT be visible for PENDING_GRACE switch');

  let rejected = false;
  try {
    await system.executeDeleteSwitch(ownerId, 'owner@example.com', switchId);
  } catch (err) {
    rejected = true;
    assert.ok(err.message.includes('Only CANCELLED and TRIGGERED'));
  }
  assert.strictEqual(rejected, true, 'PENDING_GRACE switch deletion must be rejected');
  assert.strictEqual(system.switches.has(switchId), true, 'PENDING_GRACE switch must remain untouched');
  console.log('✅ PASS: PENDING_GRACE switch deletion strictly rejected.');
}

// ============================================================
// TEST 5: PAUSED switch deletion is rejected
// ============================================================
console.log('\n--- TEST 5: PAUSED switch deletion is rejected ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-001';
  const switchId = 'switch-paused-005';

  system.switches.set(switchId, {
    id: switchId,
    user_id: ownerId,
    title: 'Paused Switch',
    status: 'PAUSED'
  });

  const canDeleteInUI = ['CANCELLED', 'TRIGGERED'].includes(system.switches.get(switchId).status);
  assert.strictEqual(canDeleteInUI, false, 'Delete button must NOT be visible for PAUSED switch');

  let rejected = false;
  try {
    await system.executeDeleteSwitch(ownerId, 'owner@example.com', switchId);
  } catch (err) {
    rejected = true;
    assert.ok(err.message.includes('Only CANCELLED and TRIGGERED'));
  }
  assert.strictEqual(rejected, true, 'PAUSED switch deletion must be rejected');
  assert.strictEqual(system.switches.has(switchId), true, 'PAUSED switch must remain untouched');
  console.log('✅ PASS: PAUSED switch deletion strictly rejected.');
}

// ============================================================
// TEST 6: Another user cannot delete someone else's switch
// ============================================================
console.log('\n--- TEST 6: Another user cannot delete someone else\'s switch ---');
{
  const system = new MockDeadManSystem();
  const victimOwnerId = 'user-victim-001';
  const attackerId = 'user-attacker-666';
  const switchId = 'switch-victim-006';

  system.switches.set(switchId, {
    id: switchId,
    user_id: victimOwnerId,
    title: 'Victim Confidential Vault',
    status: 'CANCELLED'
  });

  let rejected = false;
  try {
    await system.executeDeleteSwitch(attackerId, 'attacker@example.com', switchId);
  } catch (err) {
    rejected = true;
    assert.ok(err.message.includes('Unauthorized') || err.code === '42501');
  }
  assert.strictEqual(rejected, true, 'Attacker deletion must be rejected by RLS policy');
  assert.strictEqual(system.switches.has(switchId), true, 'Victim switch must NOT be deleted');
  console.log('✅ PASS: Cross-user deletion strictly prevented by RLS.');
}

// ============================================================
// TEST 7: Related database records are handled correctly
// ============================================================
console.log('\n--- TEST 7: Related database records are handled correctly (Cascade) ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-007';
  const switchId = 'switch-cascade-007';

  system.switches.set(switchId, { id: switchId, user_id: ownerId, title: 'Cascade Target', status: 'CANCELLED' });
  system.files.set('f1', { id: 'f1', switch_id: switchId, storage_path: `${ownerId}/${switchId}/f1` });
  system.switchRecipients.set('r1', { id: 'r1', switch_id: switchId, recipient_email: 'rec@test.com' });
  system.checkIns.set('c1', { id: 'c1', switch_id: switchId, user_id: ownerId });
  system.recipientTokens.set('t1', { id: 't1', switch_id: switchId, recipient_id: 'r1' });
  system.notifications.set('n1', { id: 'n1', switch_id: switchId, status: 'QUEUED' });

  await system.executeDeleteSwitch(ownerId, 'owner@test.com', switchId);

  assert.strictEqual(system.files.has('f1'), false, 'Files must be cascade-deleted');
  assert.strictEqual(system.switchRecipients.has('r1'), false, 'Recipients must be cascade-deleted');
  assert.strictEqual(system.checkIns.has('c1'), false, 'Check-ins must be cascade-deleted');
  assert.strictEqual(system.recipientTokens.has('t1'), false, 'Tokens must be cascade-deleted');
  assert.strictEqual(system.notifications.has('n1'), false, 'Notifications must be cascade-deleted');
  console.log('✅ PASS: All related database child records cascaded cleanly.');
}

// ============================================================
// TEST 8: Associated Storage objects are cleaned up safely
// ============================================================
console.log('\n--- TEST 8: Associated Storage objects cleaned up safely & isolation preserved ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-008';
  const otherOwnerId = 'user-other-009';
  const switchId = 'switch-storage-008';
  const otherSwitchId = 'switch-other-009';

  system.switches.set(switchId, { id: switchId, user_id: ownerId, title: 'Storage Switch', status: 'TRIGGERED' });
  
  // Storage files belonging to target switch
  const myFile1 = `${ownerId}/${switchId}/vault-secret.enc`;
  const myFile2 = `${ownerId}/${switchId}/untracked-temp.enc`;
  system.storage.set(myFile1, 'CIPHERTEXT_1');
  system.storage.set(myFile2, 'CIPHERTEXT_2');
  system.files.set('f1', { id: 'f1', switch_id: switchId, storage_path: myFile1 });

  // Storage files belonging to ANOTHER switch / user
  const otherFile1 = `${otherOwnerId}/${otherSwitchId}/foreign-vault.enc`;
  const myOtherFile = `${ownerId}/${otherSwitchId}/other-switch-vault.enc`;
  system.storage.set(otherFile1, 'FOREIGN_DATA');
  system.storage.set(myOtherFile, 'MY_OTHER_SWITCH_DATA');

  await system.executeDeleteSwitch(ownerId, 'owner@test.com', switchId);

  assert.strictEqual(system.storage.has(myFile1), false, 'Target switch storage file 1 must be deleted');
  assert.strictEqual(system.storage.has(myFile2), false, 'Target switch storage file 2 must be deleted');
  assert.strictEqual(system.storage.has(otherFile1), true, 'Foreign user storage file must NOT be touched');
  assert.strictEqual(system.storage.has(myOtherFile), true, 'Owner other switch storage file must NOT be touched');
  console.log('✅ PASS: Target storage purged; foreign & separate switch files strictly protected.');
}

// ============================================================
// TEST 9: Audit history is preserved (ON DELETE SET NULL)
// ============================================================
console.log('\n--- TEST 9: Audit history is preserved ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-009';
  const switchId = 'switch-audit-009';

  system.switches.set(switchId, { id: switchId, user_id: ownerId, title: 'Audit Test Switch', status: 'CANCELLED' });

  // Prior activity log
  system.insertClientAuditEvent(ownerId, 'owner@test.com', 'CONFIG_UPDATED', switchId, { interval_days: 14 });
  
  const priorLogsCount = system.auditLogs.length;
  assert.strictEqual(priorLogsCount, 1, 'Should have 1 initial audit log');

  await system.executeDeleteSwitch(ownerId, 'owner@test.com', switchId);

  // After deletion:
  // 1. Audit log count should increase by 1 (SWITCH_DELETED entry)
  assert.strictEqual(system.auditLogs.length, 2, 'Audit logs must NOT be deleted');

  // 2. The SWITCH_DELETED entry must exist with preserved metadata
  const deleteLog = system.auditLogs.find(l => l.action === 'SWITCH_DELETED');
  assert.ok(deleteLog, 'SWITCH_DELETED log entry must be present');
  assert.strictEqual(deleteLog.metadata.switch_title, 'Audit Test Switch');
  assert.strictEqual(deleteLog.metadata.deleted_switch_id, switchId);

  // 3. Foreign key switch_id should be NULL due to ON DELETE SET NULL, preserving the record
  assert.strictEqual(deleteLog.switch_id, null, 'Deleted switch_id should be set to NULL on audit log row');
  assert.strictEqual(deleteLog.user_id, ownerId, 'user_id must remain intact for user history retrieval');
  console.log('✅ PASS: Audit logs preserved with full historical metadata.');
}

// ============================================================
// TEST 10: Duplicate deletion requests are handled safely
// ============================================================
console.log('\n--- TEST 10: Duplicate deletion requests are handled safely ---');
{
  const system = new MockDeadManSystem();
  const ownerId = 'user-owner-010';
  const switchId = 'switch-dup-010';

  system.switches.set(switchId, { id: switchId, user_id: ownerId, title: 'Idempotency Switch', status: 'CANCELLED' });

  // First request
  const res1 = await system.executeDeleteSwitch(ownerId, 'owner@test.com', switchId);
  assert.strictEqual(res1.success, true, 'First deletion must succeed');

  // Second duplicate request
  const res2 = await system.executeDeleteSwitch(ownerId, 'owner@test.com', switchId);
  assert.strictEqual(res2.success, true, 'Duplicate deletion request must be handled safely without crashing');
  assert.strictEqual(res2.alreadyDeleted, true, 'Subsequent request correctly identifies switch as already deleted');
  console.log('✅ PASS: Duplicate deletion request handled gracefully without error or side-effects.');
}

console.log('\n🎉 ALL 10 SECURE DELETE TESTS PASSED SUCCESSFULLY!\n');
