import {
  PromptDecorator as Prompt,
  ControllerDecorator as Controller,
  ExecutionContext
} from '@nitrostack/core';

export interface PromptMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

/**
 * Controller exposing Digital Evidence Integrity MCP Prompts
 */
@Controller()
export class DigitalEvidencePrompts {
  /**
   * Prompt to guide investigators through initial evidence triage and verification workflow.
   */
  @Prompt({
    name: 'evidence-triage',
    title: 'Digital Evidence Intake Triage',
    description:
      'Structured prompt workflow for initial digital evidence intake, hash verification, and risk assessment',
    arguments: [
      {
        name: 'evidenceId',
        description: 'ID of the evidence item to triage',
        required: true
      },
      {
        name: 'evidenceType',
        description: 'Type of evidence (IMAGE, VIDEO, AUDIO, DOCUMENT)',
        required: false
      }
    ]
  })
  async evidenceTriage(
    args: Record<string, any>,
    context: ExecutionContext
  ): Promise<PromptMessage[]> {
    context.logger?.info?.('Executing prompt evidence-triage', { evidenceId: String(args?.evidenceId || '') });

    const evidenceId = String(args?.evidenceId || 'UNKNOWN');
    const evidenceType = String(args?.evidenceType || 'GENERAL');

    return [
      {
        role: 'system',
        content:
          'You are Sentinel AI Forensic Assistant, an expert in digital forensics, ISO 27037 standards, and evidence chain of custody verification.'
      },
      {
        role: 'user',
        content: `Please guide the forensic triage for Evidence Item ID: ${evidenceId} (Type: ${evidenceType}).
Perform the following steps:
1. Verify the cryptographic hash (SHA-256) against the intake log.
2. Extract all embedded EXIF headers and metadata attributes.
3. Check for signs of temporal or spatial modification.
4. Provide a preliminary risk classification and recommended next actions.`
      }
    ];
  }

  /**
   * Prompt to evaluate evidence compliance with legal evidence rules (FRE 901/902).
   */
  @Prompt({
    name: 'court-admissibility-review',
    title: 'Court Admissibility Assessment',
    description:
      'Evaluates digital evidence integrity against legal admissibility standards (FRE 901/902)',
    arguments: [
      {
        name: 'evidenceId',
        description: 'ID of the evidence item',
        required: true
      },
      {
        name: 'jurisdiction',
        description: 'Target legal jurisdiction (e.g. US_FEDERAL, EU_GDPR, UK_PACE)',
        required: false
      }
    ]
  })
  async courtAdmissibilityReview(
    args: Record<string, any>,
    context: ExecutionContext
  ): Promise<PromptMessage[]> {
    context.logger?.info?.('Executing prompt court-admissibility-review', { evidenceId: String(args?.evidenceId || '') });

    const evidenceId = String(args?.evidenceId || 'UNKNOWN');
    const jurisdiction = String(args?.jurisdiction || 'US_FEDERAL');

    return [
      {
        role: 'system',
        content:
          'You are a Senior Digital Forensics Legal Consultant specializing in electronic evidence admissibility under Federal Rules of Evidence (FRE 902(11), FRE 902(14)) and international standards.'
      },
      {
        role: 'user',
        content: `Conduct an admissibility analysis for Evidence ID ${evidenceId} under ${jurisdiction} jurisdiction rules.
Evaluate:
1. Self-authentication capability via digital hash certificates.
2. Chain of custody continuity and audit log integrity.
3. Defense challenge vulnerability (e.g., potential deepfake or metadata alteration arguments).
4. Expert witness foundation requirements.`
      }
    ];
  }

  /**
   * Prompt to guide investigation of flagged synthetic/manipulated artifacts.
   */
  @Prompt({
    name: 'anomaly-investigation',
    title: 'Deepfake & Manipulation Investigation',
    description:
      'Detailed investigation plan for flagged anomalies, Error Level Analysis (ELA), and generative AI artifacts',
    arguments: [
      {
        name: 'evidenceId',
        description: 'ID of the flagged evidence item',
        required: true
      },
      {
        name: 'flaggedAnomalies',
        description: 'Comma-separated list of detected anomalies',
        required: true
      }
    ]
  })
  async anomalyInvestigation(
    args: Record<string, any>,
    context: ExecutionContext
  ): Promise<PromptMessage[]> {
    context.logger?.info?.('Executing prompt anomaly-investigation', { evidenceId: String(args?.evidenceId || '') });

    const evidenceId = String(args?.evidenceId || 'UNKNOWN');
    const flaggedAnomalies = String(args?.flaggedAnomalies || 'ELA_COMPRESSION_VARIANCE');

    return [
      {
        role: 'system',
        content:
          'You are Sentinel AI Lead Manipulation Analyst, specializing in computer vision forensics, generative AI deepfake detection, and audio-visual splicing analysis.'
      },
      {
        role: 'user',
        content: `Investigate the following flagged anomalies for Evidence ID ${evidenceId}:
Flagged Items: ${flaggedAnomalies}

Steps to follow:
1. Break down each detected anomaly and explain its technical root cause.
2. Differentiate between benign editing/compression vs malicious forgery.
3. Recommend targeted secondary forensic tools (e.g., frequency spectrum analysis, PRNU sensor noise matching).
4. Summarize confidence level in the tampering verdict.`
      }
    ];
  }
}
