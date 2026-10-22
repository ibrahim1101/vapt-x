/** @jest-environment node */
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { WorkspaceCompletenessNotice } from './workspace-completeness';

test('omits the notice when the workspace is complete', () => {
  expect(renderToStaticMarkup(<WorkspaceCompletenessNotice />)).toBe('');
});

test('identifies incomplete collections and explains filter limitations', () => {
  const markup = renderToStaticMarkup(<WorkspaceCompletenessNotice collections={['findings', 'jobs']} />);
  expect(markup).toContain('role="status"');
  expect(markup).toContain('findings, scan jobs');
  expect(markup).toContain('Dedicated registers search and page through complete server collections');
});


test('only suggests narrowing when no project is already selected', () => {
  const allProjects = renderToStaticMarkup(<WorkspaceCompletenessNotice collections={['findings']} />);
  const selectedProject = renderToStaticMarkup(<WorkspaceCompletenessNotice collections={['findings']} projectSelected />);
  expect(allProjects).toContain('Choose a project above');
  expect(selectedProject).not.toContain('Choose a project above');
  expect(selectedProject).toContain('may be incomplete');
});
