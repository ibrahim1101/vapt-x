export function FindingScannerFacts({finding}) {
  const packageInfo=finding.package_info,scores=finding.scanner_cvss||[],references=finding.reference_urls||[];
  if(!packageInfo&&!scores.length&&!references.length)return null;
  return <section className="section-gap" data-testid="finding-scanner-facts">
    <h3>Scanner-provided facts</h3>
    <p className="muted tiny">Separate from scanner severity and analyst triage. CVSS 3.0/3.1 base-only vectors are checked against the FIRST formula. Contextual vectors and CVSS 4.0 remain source assertions and are not recalculated locally. Exact npm SemVer comparisons are version-order clues only; they do not establish affected ranges or fix applicability.</p>
    {packageInfo&&<dl>{[['name','Package'],['ecosystem','Ecosystem'],['installed_version','Installed version'],['fixed_version','Fixed version'],['path','Package path']].map(([key,label])=><div key={key}><dt>{label}</dt><dd>{packageInfo[key]||'Not reported'}</dd></div>)}</dl>}
    {packageInfo?.version_comparison&&<p className="muted tiny" role="note">{packageInfo.version_comparison.scheme}: {packageInfo.version_comparison.relation==='installed_before_reported_fix'?'installed version sorts before':'installed version sorts at or after'} the reported fix version. This does not confirm vulnerability or remediation status.</p>}
    {scores.map((score,index)=><div key={index}>
      <strong>CVSS {score.version}: {score.score??'Score not supplied'}</strong>
      <p>{score.source}</p>
      {score.score_consistency==='consistent'&&<p className="muted tiny">Matches the calculated CVSS base score: {score.calculated_base_score}.</p>}
      {score.score_consistency==='score_missing'&&<p className="muted tiny">Calculated CVSS base score from this vector: {score.calculated_base_score}. No source score was supplied.</p>}
      {score.score_consistency==='mismatch'&&<p className="muted tiny" role="note">The source score does not match this base vector. Calculated base score: {score.calculated_base_score}. The source score is preserved.</p>}
      <code>{score.vector}</code>
    </div>)}
    {references.map(url=><p key={url}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></p>)}
  </section>;
}
