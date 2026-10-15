import { AlertTriangle } from 'lucide-react';

const collectionLabels = {
  projects: 'projects', scopes: 'scope records', assets: 'assets',
  assessments: 'assessments', jobs: 'scan jobs', findings: 'findings',
  tasks: 'remediation tasks', evidence: 'evidence records', reports: 'reports',
  audit: 'audit events',
};

export function WorkspaceCompletenessNotice({ collections = [], projectSelected = false }) {
  const labels = collections.filter(name => collectionLabels[name]).map(name => collectionLabels[name]);
  if (!labels.length) return null;

  return (
    <div className="form-notice workspace-completeness" role="status" data-testid="workspace-truncated">
      <AlertTriangle size={18} aria-hidden="true" />
      <div>
        <strong>Only part of this workspace is loaded.</strong>
        <p>Some {labels.join(', ')} are omitted. List previews, search, and project filters reflect only the loaded records and may be incomplete. Overview totals and severity charts use complete server counts.</p>
        {!projectSelected && <p>Choose a project above to load a narrower dataset from the server.</p>}
      </div>
    </div>
  );
}
