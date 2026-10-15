import { useState } from 'react';
import { Action, Badge, DataTable, Field, Panel, Select } from './workspace-ui';

export function AssetInventory({ data, open, canWrite }) {
  const [criticality, setCriticality] = useState('all');
  return <Panel title="Asset inventory" subtitle="Targets retain their exact host scope; business criticality is analyst supplied">
    <Field label="Business criticality" name="asset-criticality-filter"><Select name="asset-criticality-filter" value={criticality} onChange={e=>setCriticality(e.target.value)}>
      {['all','critical','high','medium','low'].map(c=><option key={c} value={c}>{c}</option>)}
    </Select></Field>
    <DataTable name="assets" rows={data.assets.filter(a=>criticality==='all'||(a.criticality||'medium')===criticality)} columns={[
      {key:'name',label:'Asset',render:a=><div className="cell-main"><strong>{a.name}</strong><small>{a.target}</small></div>},
      {key:'kind',label:'Type'},
      {key:'owner',label:'Owner',render:a=>a.owner||'Unassigned'},
      {key:'criticality',label:'Criticality',render:a=><Badge type={a.criticality||'medium'}>{a.criticality||'medium'}</Badge>},
      {key:'tags',label:'Tags',render:a=>(a.tags||[]).join(', ')||'—'},
      {key:'project_id',label:'Project',render:a=>data.projects.find(p=>p.id===a.project_id)?.name},
      ...(canWrite?[{key:'id',label:'Manage',render:a=><Action secondary testId={`edit-asset-${a.id}`} onClick={()=>open('asset-edit',a)}>Edit metadata</Action>}]:[]),
    ]}/>
  </Panel>;
}
