import { useCallback, useEffect, useState } from 'react';
import { api, errorText } from '../lib/api';
import { Action, Badge } from './workspace-ui';

export function FindingHistory({ findingId }) {
  const [history, setHistory] = useState(null);
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    try {
      const { data } = await api.get(`/findings/${encodeURIComponent(findingId)}/history`);
      setHistory(data); setError('');
    } catch (failure) { setError(errorText(failure)); }
  }, [findingId]);
  useEffect(() => { setHistory(null); load(); }, [load]);
  return <section className="section-gap" aria-label="Finding triage history">
    <h3>Triage history</h3>
    {error ? <div role="alert"><p>{error}</p><Action secondary onClick={load}>Retry history</Action></div> : !history ? <p role="status">Loading history…</p> : <>
      {history.has_more && <p className="form-notice">Showing the latest 100 of {history.total} recorded changes.</p>}
      {!history.events.length && <p className="muted tiny">No triage changes recorded. Changes made before history tracking are not reconstructed.</p>}
      {[...history.events].reverse().map((event, index) => <article className="section-gap" key={`${event.created_at}-${index}`}>
        <p><Badge type={event.previous_status}>{event.previous_status}</Badge> → <Badge type={event.status}>{event.status}</Badge></p>
        <p className="muted tiny">{event.actor_email || event.actor_id} · {new Date(event.created_at).toLocaleString()}</p>
        {event.owner !== undefined && event.owner !== event.previous_owner && <p className="tiny">Owner: {event.previous_owner||'Unassigned'} → {event.owner||'Unassigned'}</p>}
        {event.notes !== event.previous_notes && <><p className="tiny">Updated analyst notes</p><pre>{event.notes || 'Notes cleared'}</pre></>}
      </article>)}
    </>}
  </section>;
}
