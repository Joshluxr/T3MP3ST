import { randomUUID } from 'crypto';
import { bountyReportDigest, type BountyReport, type LiveSubmissionConfirmation } from '../integrations/bounty.js';

export type SubmissionReceiptStatus = 'pending' | 'confirmed' | 'consumed' | 'expired';

export interface SubmissionReceipt {
  id: string;
  platform: string;
  programHandle: string;
  reportDigest: string;
  status: SubmissionReceiptStatus;
  createdAt: string;
  expiresAt: string;
  confirmedAt?: string;
  consumedAt?: string;
}

export class SubmissionReceiptError extends Error {
  constructor(message: string, readonly statusCode: number) {
    super(message);
  }
}

export class SubmissionReceiptStore {
  private readonly receipts = new Map<string, SubmissionReceipt>();

  issue(report: BountyReport, ttlMinutes = 10): SubmissionReceipt {
    const now = new Date();
    const ttl = Math.max(1, Math.min(30, Number.isFinite(ttlMinutes) ? ttlMinutes : 10));
    const receipt: SubmissionReceipt = {
      id: `submission_${randomUUID()}`,
      platform: report.platform,
      programHandle: report.programHandle,
      reportDigest: bountyReportDigest(report),
      status: 'pending',
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttl * 60_000).toISOString(),
    };
    this.receipts.set(receipt.id, receipt);
    return receipt;
  }

  confirm(id: string, reportDigest: string): SubmissionReceipt {
    const receipt = this.require(id);
    this.refresh(receipt);
    if (receipt.status !== 'pending') throw new SubmissionReceiptError(`Submission receipt is ${receipt.status}.`, 409);
    if (receipt.reportDigest !== reportDigest) throw new SubmissionReceiptError('Submission receipt digest does not match the reviewed report.', 400);
    receipt.status = 'confirmed';
    receipt.confirmedAt = new Date().toISOString();
    return receipt;
  }

  claim(id: string, report: BountyReport): LiveSubmissionConfirmation {
    const receipt = this.require(id);
    this.refresh(receipt);
    if (receipt.status !== 'confirmed' || !receipt.confirmedAt) {
      throw new SubmissionReceiptError(`Submission receipt is ${receipt.status}; explicit confirmation is required.`, 409);
    }
    if (receipt.reportDigest !== bountyReportDigest(report)
      || receipt.platform !== report.platform
      || receipt.programHandle !== report.programHandle) {
      throw new SubmissionReceiptError('Submission receipt does not match this exact report.', 400);
    }
    receipt.status = 'consumed';
    receipt.consumedAt = new Date().toISOString();
    return { receiptId: receipt.id, reportDigest: receipt.reportDigest, confirmedAt: receipt.confirmedAt };
  }

  get(id: string): SubmissionReceipt | undefined {
    const receipt = this.receipts.get(id);
    if (receipt) this.refresh(receipt);
    return receipt;
  }

  private require(id: string): SubmissionReceipt {
    const receipt = this.receipts.get(id);
    if (!receipt) throw new SubmissionReceiptError('Submission receipt not found.', 404);
    return receipt;
  }

  private refresh(receipt: SubmissionReceipt): void {
    if ((receipt.status === 'pending' || receipt.status === 'confirmed') && Date.parse(receipt.expiresAt) <= Date.now()) {
      receipt.status = 'expired';
    }
  }
}
