import { useState } from 'react';
import { toast } from 'sonner';
import { api, errorText } from '../lib/api';
import { Action, Field, Modal } from './workspace-ui';

export function ScopeRevocation({ scope, refresh }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  async function revoke(event) {
    event.preventDefault();
    setBusy(true);
    try {
      await api.post(`/scopes/${encodeURIComponent(scope.id)}/revoke`, { reason: reason.trim() });
      await refresh();
      setOpen(false);
      toast.success('Authorization revoked. New work is blocked.');
    } catch (error) { toast.error(errorText(error)); }
    finally { setBusy(false); }
  }
  if (!scope.authorized) return <span className="muted tiny">Not authorized</span>;
  return <>
    <Action secondary testId={`revoke-scope-${scope.id}`} onClick={() => setOpen(true)}>Revoke</Action>
    {open && <Modal open onClose={() => !busy && setOpen(false)} title="Revoke scope authorization" description={scope.target}>
      <form onSubmit={revoke}>
        <p className="form-notice">Revocation blocks new scans and imports. Queued work rechecks authorization before execution. A check already running may finish within its timeout.</p>
        <Field label="Revocation reason" name="revocation-reason"><textarea data-testid="revocation-reason" value={reason} onChange={event => setReason(event.target.value)} required minLength={5} maxLength={500} rows={3}/></Field>
        <Action type="submit" testId="confirm-scope-revocation" disabled={busy || reason.trim().length < 5}>{busy ? 'Revoking…' : 'Revoke authorization'}</Action>
      </form>
    </Modal>}
  </>;
}
