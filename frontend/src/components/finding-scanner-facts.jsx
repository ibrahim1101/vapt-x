export function FindingScannerFacts({finding}) {
  const packageInfo=finding.package_info,scores=finding.scanner_cvss||[],references=finding.reference_urls||[];
  if(!packageInfo&&!scores.length&&!references.length)return null;
  return <section className="section-gap" data-testid="finding-scanner-facts">
    <h3>Scanner-provided facts</h3>
    <p className="muted tiny">Separate from scanner severity and analyst triage. CVSS 3.0/3.1 base-only vectors are checked against the FIRST formula. Contextual vectors and CVSS 4.0 remain source assertions and are not recalculated locally. Package version ordering and fix applicability are not evaluated.</p>
    {packageInfo&&<dl>{[['name','Package'],['ecosystem','Ecosystem'],['installed_version','Installed version'],['fixed_version','Fixed version'],['path','Package path']].map(([key,label])=><div key={key}><dt>{label}</dt><dd>{packageInfo[key]||'Not reported'}</dd></div>)}</dl>}
    {scores.map((score,index)=><div key={index}>
      <strong>CVSS {score.version}: {score.score??'Score not supplied'}</strong>
      <p>{score.source}</p>
      {score.score_consistency==='consistent'&&<p className="muted tiny">Matches the calculated CVSS base score: {score.calculated_base_score}.</p>}
      {score.score_consistency==='mismatch'&&<p className="muted tiny" role="note">The source score does not match this base vector. Calculated base score: {score.calculated_base_score}. The source score is preserved.</p>}
      <code>{score.vector}</code>
    </div>)}
    {references.map(url=><p key={url}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></p>)}
  </section>;
}
