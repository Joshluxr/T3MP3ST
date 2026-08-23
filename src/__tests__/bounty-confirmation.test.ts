import { describe, expect, it } from 'vitest';
import { bountyReportDigest, hackeroneConnector, type BountyReport } from '../integrations/bounty.js';
import { SubmissionReceiptError, SubmissionReceiptStore } from '../server/bounty-confirmation.js';

const report: BountyReport = {
  platform: 'hackerone', programHandle: 'example', title: 'Finding', severity: 'high',
  body: 'Reviewed body', apiPayload: { data: { attributes: { title: 'Finding' } } }, checklist: [],
};

describe('live bounty submission receipts', () => {
  it('binds one confirmed, one-shot receipt to the exact report', () => {
    const store = new SubmissionReceiptStore();
    const receipt = store.issue(report);
    expect(() => store.claim(receipt.id, report)).toThrow(SubmissionReceiptError);
    expect(() => store.confirm(receipt.id, 'wrong-digest')).toThrow(/digest/);
    store.confirm(receipt.id, bountyReportDigest(report));
    expect(() => store.claim(receipt.id, { ...report, body: 'changed after review' })).toThrow(/exact report/);
    expect(store.claim(receipt.id, report)).toMatchObject({ receiptId: receipt.id, reportDigest: bountyReportDigest(report) });
    expect(() => store.claim(receipt.id, report)).toThrow(/consumed/);
  });

  it('defaults connector calls to dry-run and rejects live calls without confirmation', async () => {
    await expect(hackeroneConnector.submit(report, { platform: 'hackerone' })).resolves.toMatchObject({ success: true, reportId: 'DRY-RUN' });
    await expect(hackeroneConnector.submit(report, { platform: 'hackerone' }, { dryRun: false })).resolves.toMatchObject({
      success: false, error: expect.stringContaining('confirmed submission receipt'),
    });
  });
});
