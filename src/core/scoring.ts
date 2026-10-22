import { RiskLevel, FindingType, Environment, DataClass } from './types';

export interface AssetContext {
  criticality: 1 | 2 | 3 | 4;
  internetFacing: boolean;
  environment: Environment;
  dataClass: DataClass;
}

export interface FindingSignals {
  type: FindingType;
  // Dependency signals
  inKev?: boolean;
  reachable?: boolean;
  epssScore?: number;
  cvssScore?: number;
  // SAST signals
  cweCategory?: string;
  isProductionPath?: boolean;
  ruleSeverity?: 'ERROR' | 'WARNING' | 'INFO';
  ruleConfidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  // Secret signals
  secretActive?: boolean;
  secretType?: string;
  isGitHistory?: boolean;
}

export interface RiskScoreResult {
  riskLevel: RiskLevel;
  slaDays: number | null;
  riskReasons: string[];
}

/**
 * Deterministic Risk Scoring Engine
 * SSVC-like Decision Tree based on real exploit signals + asset context.
 * Explanations are captured in riskReasons.
 */
export function calculateRiskScore(
  signals: FindingSignals,
  asset: AssetContext
): RiskScoreResult {
  const reasons: string[] = [];
  const isHighImpactAsset = asset.criticality <= 2 || asset.environment === 'production';

  // 1. DEPENDENCY SCORING
  if (signals.type === 'dependency') {
    const inKev = Boolean(signals.inKev);
    const reachable = Boolean(signals.reachable);
    const epss = signals.epssScore ?? 0;
    const cvss = signals.cvssScore ?? 0;

    // Rule: KEV + reachable on internet-facing / high-impact asset -> P1
    if (inKev && reachable && (asset.internetFacing || isHighImpactAsset)) {
      reasons.push('Lỗ hổng nằm trong CISA KEV (đang bị khai thác thực tế)');
      reasons.push('Hàm có lỗ hổng được gọi trực tiếp trong mã nguồn (Reachable call-chain)');
      if (asset.internetFacing) reasons.push('Tài sản tiếp xúc Internet (Internet-facing)');
      if (isHighImpactAsset) reasons.push(`Môi trường ${asset.environment} (Độ quan trọng cấp ${asset.criticality})`);
      return { riskLevel: 'P1', slaDays: 7, riskReasons: reasons };
    }

    // Rule: In KEV even if reachability is unknown/false on prod asset -> P1
    if (inKev && asset.environment === 'production') {
      reasons.push('Lỗ hổng nằm trong CISA KEV trên hệ thống Production');
      return { riskLevel: 'P1', slaDays: 7, riskReasons: reasons };
    }

    // Rule: High EPSS (> 0.1) or CVSS >= 7.0 on production -> P2
    if ((epss > 0.1 || cvss >= 7.0) && isHighImpactAsset) {
      if (epss > 0.1) reasons.push(`Xác suất bị khai thác cao (EPSS > 0.1: ${(epss * 100).toFixed(1)}%)`);
      if (cvss >= 7.0) reasons.push(`Điểm CVSS cao (${cvss.toFixed(1)}/10)`);
      reasons.push(`Hệ thống ${asset.environment} (Độ quan trọng cấp ${asset.criticality})`);
      return { riskLevel: 'P2', slaDays: 30, riskReasons: reasons };
    }

    // Rule: CVSS >= 7.0 on non-prod or moderate EPSS -> P3
    if (cvss >= 7.0 || epss > 0.05) {
      reasons.push(`Lỗ hổng CVSS ${cvss.toFixed(1)} trên môi trường nội bộ / phát triển (${asset.environment})`);
      return { riskLevel: 'P3', slaDays: 90, riskReasons: reasons };
    }

    // Default Low
    reasons.push('Lỗ hổng rủi ro thấp hoặc không có dấu hiệu khai thác trong thực tế');
    return { riskLevel: 'P4', slaDays: null, riskReasons: reasons };
  }

  // 2. SAST SCORING
  if (signals.type === 'sast') {
    const cwe = signals.cweCategory ?? '';
    const isInjectionOrAuth =
      /injection|sqli|rce|xss|auth|credential|deserialization|ssrf/i.test(cwe);
    const isProdPath = signals.isProductionPath ?? true;
    const isHighConf = signals.ruleConfidence === 'HIGH';
    const isError = signals.ruleSeverity === 'ERROR';

    // Rule: Injection / Auth on internet-facing / prod endpoint -> P1
    if (isInjectionOrAuth && asset.internetFacing && isProdPath) {
      reasons.push('Lỗ hổng Injection/Auth nguy hiểm phát hiện trong mã nguồn chính');
      reasons.push('Endpoint nằm trên tài sản tiếp xúc Internet công cộng');
      return { riskLevel: 'P1', slaDays: 7, riskReasons: reasons };
    }

    // Rule: High confidence flaw in production code -> P2
    if ((isError || isHighConf) && isProdPath && isHighImpactAsset) {
      reasons.push(`Lỗi bảo mật mức ${signals.ruleSeverity || 'HIGH'} trên nhánh production`);
      reasons.push(`Phân loại CWE: ${cwe || 'Code Flaw'}`);
      return { riskLevel: 'P2', slaDays: 30, riskReasons: reasons };
    }

    // Rule: Flaw in development / staging or non-critical path -> P3
    if (isProdPath) {
      reasons.push(`Lỗ hổng mức trung bình trên ${asset.environment}`);
      return { riskLevel: 'P3', slaDays: 90, riskReasons: reasons };
    }

    // Rule: Flaw in test directory or low confidence -> P4
    reasons.push('Phát hiện trong thư mục test hoặc rule có độ tin cậy thấp (Info/Low)');
    return { riskLevel: 'P4', slaDays: null, riskReasons: reasons };
  }

  // 3. SECRET SCORING
  if (signals.type === 'secret') {
    const isActive = Boolean(signals.secretActive);
    const isGitHistory = Boolean(signals.isGitHistory);

    // Rule: Active secret in internet-facing or production -> P1
    if (isActive && (asset.internetFacing || asset.environment === 'production')) {
      reasons.push('Secret còn hiệu lực (Active credential verification)');
      reasons.push('Nằm trong kho mã nguồn ứng dụng tiếp xúc Internet / Production');
      return { riskLevel: 'P1', slaDays: 7, riskReasons: reasons };
    }

    // Rule: Active secret on internal repo, or unverified high-privilege token -> P2
    if (isActive || (!isGitHistory && isHighImpactAsset)) {
      reasons.push('Secret hợp lệ hoặc xuất hiện trong commit hiện tại của repo');
      return { riskLevel: 'P2', slaDays: 30, riskReasons: reasons };
    }

    // Rule: Inactive or historical secret in dev/internal -> P3
    if (isGitHistory || asset.environment === 'development') {
      reasons.push('Secret cũ trong lịch sử git hoặc môi trường phát triển');
      return { riskLevel: 'P3', slaDays: 90, riskReasons: reasons };
    }

    // Default P4
    reasons.push('Secret kiểm thử hoặc độ nhạy cảm thấp');
    return { riskLevel: 'P4', slaDays: null, riskReasons: reasons };
  }

  return { riskLevel: 'P4', slaDays: null, riskReasons: ['Chưa đủ tín hiệu đánh giá'] };
}

/**
 * Calculate SLA Due Date given SLA days from now
 */
export function calculateSlaDueDate(slaDays: number | null): Date | null {
  if (slaDays === null) return null;
  const now = new Date();
  now.setDate(now.getDate() + slaDays);
  return now;
}
