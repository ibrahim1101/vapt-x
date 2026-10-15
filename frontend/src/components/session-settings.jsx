import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { api, errorText } from '../lib/api';
import { Action, Badge, DataTable, Panel } from './workspace-ui';

export function SessionSettings() {
  const [sessions, setSessions] = useState([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    try {
      const { data } = await api.get('/auth/sessions');
      setSessions(data.sessions);
      setHasMore(data.has_more);
      setError('');
    } catch (failure) { setError(errorText(failure)); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);
  async function revoke(session) {
    setBusy(true);
    try {
      await api.post(`/auth/sessions/${encodeURIComponent(session.id)}/revoke`);
      if (session.current) window.dispatchEvent(new Event('vaptx-session-expired'));
      else { await load(); toast.success('Session revoked.'); }
    } catch (failure) { toast.error(errorText(failure)); }
    finally { setBusy(false); }
  }
  async function revokeOthers() {
    setBusy(true);
    try {
      const { data } = await api.post('/auth/sessions/revoke-others');
      await load();
      toast.success(`${data.revoked_count} other sessions revoked.`);
    } catch (failure) { toast.error(errorText(failure)); }
    finally { setBusy(false); }
  }
  return <Panel title="Your active sessions" subtitle="Sessions belong to your account across organizations. Revocation takes effect on the next authenticated request." className="section-gap">
    {error ? <div role="alert"><p>{error}</p><Action secondary onClick={load}>Retry sessions</Action></div> : loading ? <p role="status">Loading sessions…</p> : <>
      <DataTable name="sessions" rows={sessions} columns={[
        { key: 'id', label: 'Session', render: session => <span className="mono tiny">{session.id.slice(0, 8)} {session.current && <Badge type="completed">Current</Badge>}</span> },
        { key: 'created_at', label: 'Signed in', render: session => new Date(session.created_at).toLocaleString() },
        { key: 'expires_at', label: 'Expires', render: session => new Date(session.expires_at).toLocaleString() },
        { key: 'action', label: 'Action', render: session => <Action secondary disabled={busy} testId={`revoke-session-${session.id}`} onClick={() => revoke(session)}>{session.current ? 'Sign out here' : 'Revoke'}</Action> },
      ]}/>
      {hasMore && <p className="form-notice">Only the latest 100 active sessions are shown. Revoke other sessions below to invalidate all except this one.</p>}
      <Action secondary testId="revoke-other-sessions" disabled={busy} onClick={revokeOthers}>Revoke all other sessions</Action>
    </>}
  </Panel>;
}
