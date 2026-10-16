import { useState } from 'react';
import { Download } from 'lucide-react';
import { toast } from 'sonner';
import { download, errorText } from '../lib/api';
import { Action, Field, Panel, Select } from './workspace-ui';

export function FindingExports({ assessments }) {
  const [assessmentId, setAssessmentId] = useState('');
  const [busy, setBusy] = useState(false);
  async function exportFile(format) {
    if (!assessmentId) return;
    setBusy(true);
    try {
      await download(`/assessments/${encodeURIComponent(assessmentId)}/findings/export?format=${format}`, `VAPT-X-findings.${format}`);
    } catch (error) { toast.error(errorText(error)); }
    finally { setBusy(false); }
  }
  return <Panel title="Finding exports" subtitle="Export a complete assessment dataset with source and verification labels. CSV cells are protected against spreadsheet formulas.">
    <Field label="Assessment" name="export-assessment"><Select name="export-assessment" value={assessmentId} onChange={event => setAssessmentId(event.target.value)}>
      <option value="">Select an assessment</option>
      {assessments.map(assessment => <option key={assessment.id} value={assessment.id}>{assessment.name}</option>)}
    </Select></Field>
    <div className="assessment-actions">
      <Action secondary testId="export-findings-json" disabled={!assessmentId || busy} onClick={() => exportFile('json')}><Download size={14}/>JSON findings</Action>
      <Action secondary testId="export-findings-csv" disabled={!assessmentId || busy} onClick={() => exportFile('csv')}><Download size={14}/>CSV findings</Action>
    </div>
    <p className="muted tiny">Exports contain up to 5,000 findings. Larger datasets are rejected explicitly. Review sensitive evidence before sharing.</p>
  </Panel>;
}
