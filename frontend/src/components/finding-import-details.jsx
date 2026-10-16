export function FindingImportDetails({finding}) {
  const metadata=finding.import_metadata;
  if(!metadata)return null;
  const labels={format:'Report format',source_id:'Source finding ID',account_id:'Cloud account',region:'Region',resource_type:'Resource type',scanner_status:'Scanner status',package_name:'Android package',scanner_version:'Scanner version',file_path:'Source file',line_numbers:'Source lines',component:'Manifest component',resource:'Configuration resource',start_line:'Start line',end_line:'End line'};
  return <section data-testid="finding-import-details" className="form-notice"><div><h3>Imported source details</h3><p>{finding.finding_type?.replaceAll('_',' ')} · Scanner-authored and unverified until reviewed.</p><dl>{Object.entries(labels).filter(([key])=>metadata[key]!==undefined&&metadata[key]!=='').map(([key,label])=><div key={key}><dt>{label}</dt><dd>{String(metadata[key])}</dd></div>)}</dl></div></section>;
}
