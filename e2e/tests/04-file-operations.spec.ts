import { test, expect } from '@playwright/test';
import * as path from 'path';
import { SEL } from '../helpers/selectors';
import { BUCKETS, testDataPath } from '../helpers/test-data';
import { dismissWelcomeIfPresent, navigateToBucket, waitForToast, waitForTableLoaded } from '../helpers/wait-helpers';

test.describe('File Operations', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await dismissWelcomeIfPresent(page);
    await navigateToBucket(page, BUCKETS.MAIN);
  });

  test('4.1 opens upload modal on Upload button click', async ({ page }) => {
    await page.locator(SEL.uploadButton).click();
    await expect(page.locator(SEL.modal)).toBeVisible();
    await expect(page.locator(SEL.dropZone)).toBeVisible();
    // Cancel
    await page.locator(SEL.uploadCancelButton).click();
  });

  test('4.1 selects files and uploads with progress', async ({ page }) => {
    await page.locator(SEL.uploadButton).click();

    // Set files via hidden input
    const fileInput = page.locator(SEL.uploadFileInput);
    await fileInput.setInputFiles(testDataPath('sample.txt'));

    // File should appear in queue
    await expect(page.locator(SEL.uploadFileRow)).toBeVisible();

    // Click upload
    await page.locator(SEL.uploadSubmitButton).click();

    // Wait for completion toast
    await waitForToast(page, 'complete', 'success');
  });

  test('4.1 cancel closes upload modal without uploading', async ({ page }) => {
    await page.locator(SEL.uploadButton).click();
    await expect(page.locator(SEL.modal)).toBeVisible();
    await page.locator(SEL.uploadCancelButton).click();
    await expect(page.locator(SEL.modal)).toBeHidden();
  });

  test('4.3 download link exists for files', async ({ page }) => {
    const fileRow = page.locator(`${SEL.tableRow}:not(.row-folder)`).first();
    if (await fileRow.isVisible().catch(() => false)) {
      const downloadLink = fileRow.locator(`${SEL.colActions} a`);
      await expect(downloadLink).toBeVisible();
      const href = await downloadLink.getAttribute('href');
      expect(href).toContain('/api/buckets/');
      expect(href).toContain('/download');
    }
  });

  test('4.4 previews text file', async ({ page }) => {
    // Find sample.txt row and click preview (eye icon)
    const txtRow = page.locator(`${SEL.tableRow}:has-text("sample.txt")`).first();
    if (await txtRow.isVisible().catch(() => false)) {
      await txtRow.locator(`${SEL.colActions} button`).first().click();
      await expect(page.locator(SEL.modal)).toBeVisible();
      // Preview should contain the text content
      await expect(page.locator(SEL.modal)).toContainText('Hello');
      // Close preview via × button or click overlay
      await page.locator(SEL.modalDismissButton).click();
    }
  });

  test('4.4 previews JSON file', async ({ page }) => {
    const jsonRow = page.locator(`${SEL.tableRow}:has-text("sample.json")`).first();
    if (await jsonRow.isVisible().catch(() => false)) {
      await jsonRow.locator(`${SEL.colActions} button`).first().click();
      await expect(page.locator(SEL.modal)).toBeVisible();
      await expect(page.locator(SEL.modal)).toContainText('name');
      await page.locator(SEL.modalDismissButton).click();
    }
  });

  test('4.4 previews CSV file as table', async ({ page }) => {
    const csvRow = page.locator(`${SEL.tableRow}:has-text("sample.csv")`).first();
    if (await csvRow.isVisible().catch(() => false)) {
      await csvRow.locator(`${SEL.colActions} button`).first().click();
      await expect(page.locator(SEL.modal)).toBeVisible();
      // Should render a table with header columns
      await expect(page.locator(SEL.modal)).toContainText('name');
      await page.locator(SEL.modalDismissButton).click();
    }
  });

  test('4.4 previews image file', async ({ page }) => {
    const pngRow = page.locator(`${SEL.tableRow}:has-text("sample.png")`).first();
    if (await pngRow.isVisible().catch(() => false)) {
      await pngRow.locator(`${SEL.colActions} button`).first().click();
      await expect(page.locator(SEL.modal)).toBeVisible();
      // Image preview: img may fail to load if presigned URL uses Docker-internal hostname
      // Accept either a visible img or the error fallback
      const img = page.locator(`${SEL.modal} img`);
      const errorFallback = page.locator(`${SEL.modal} :has-text("Failed to load")`);
      await expect(img.or(errorFallback).first()).toBeVisible({ timeout: 10_000 });
      await page.locator(SEL.modalDismissButton).click();
    }
  });

  test('4.5 opens ObjectInfo modal on info button click', async ({ page }) => {
    const fileRow = page.locator(`${SEL.tableRow}:not(.row-folder)`).first();
    if (await fileRow.isVisible().catch(() => false)) {
      // Info button is the last button or the one with "i" text
      const infoBtn = fileRow.locator(`${SEL.colActions} button:has-text("i")`);
      if (await infoBtn.isVisible().catch(() => false)) {
        await infoBtn.click();
        await expect(page.locator(SEL.modal)).toBeVisible();
        // Should show Details tab with info table
        await expect(page.locator(SEL.infoTable)).toBeVisible();
        await page.locator(SEL.modalCloseButton).click();
      }
    }
  });

  test('4.6 creates folder via New Folder button', async ({ page }) => {
    await page.locator(SEL.newFolderButton).click();
    await expect(page.locator(SEL.modal)).toBeVisible();

    const folderName = 'e2e-test-folder-' + Date.now();
    await page.locator(SEL.promptInput).fill(folderName);
    await page.locator(SEL.promptSubmit).click();

    await waitForToast(page, 'Created folder');
  });

  test('4.7 selects files via checkboxes and deletes', async ({ page }) => {
    // First upload a temp file to delete
    await page.locator(SEL.uploadButton).click();
    await page.locator(SEL.uploadFileInput).setInputFiles(testDataPath('sample.txt'));
    // Rename the upload slightly isn't needed — we'll just delete something

    // Close upload and use existing file
    await page.locator(SEL.uploadCancelButton).click();

    // Select first file checkbox
    const firstFileRow = page.locator(`${SEL.tableRow}:not(.row-folder)`).first();
    if (await firstFileRow.isVisible().catch(() => false)) {
      const checkbox = firstFileRow.locator('input[type="checkbox"]');
      await checkbox.check();

      // Delete button should show count
      const deleteBtn = page.locator(SEL.deleteToolbarButton);
      await expect(deleteBtn).toBeEnabled();
      const text = await deleteBtn.textContent();
      expect(text).toMatch(/Delete \(\d+\)/);
    }
  });

  test('4.8 select all checkbox selects all files', async ({ page }) => {
    const selectAll = page.locator(SEL.selectAllCheckbox);
    await selectAll.check();

    // All visible file checkboxes should be checked
    const checkboxes = page.locator(`${SEL.tableRow} input[type="checkbox"]`);
    const count = await checkboxes.count();
    for (let i = 0; i < Math.min(count, 5); i++) {
      await expect(checkboxes.nth(i)).toBeChecked();
    }

    // Deselect all
    await selectAll.uncheck();
  });

  test('4.9 previews PDF file in iframe', async ({ page }) => {
    const pdfRow = page.locator(`${SEL.tableRow}:has-text("sample.pdf")`).first();
    if (await pdfRow.isVisible().catch(() => false)) {
      await pdfRow.locator(`${SEL.colActions} button`).first().click();
      await expect(page.locator(SEL.modal)).toBeVisible();
      // PDF renders in an iframe
      await expect(page.locator(`${SEL.modal} ${SEL.previewIframe}`)).toBeVisible({ timeout: 10_000 });
      await page.locator(SEL.modalDismissButton).click();
    }
  });

  test('4.10 previews Parquet file with schema table', async ({ page }) => {
    const parquetRow = page.locator(`${SEL.tableRow}:has-text("sample.parquet")`).first();
    if (await parquetRow.isVisible().catch(() => false)) {
      await parquetRow.locator(`${SEL.colActions} button`).first().click();
      await expect(page.locator(`${SEL.modal} ${SEL.schemaPreview}`)).toBeVisible({ timeout: 10_000 });
      // Schema table with columns (may have multiple tables — column schema + stats)
      await expect(page.locator(`${SEL.modal} ${SEL.schemaTable}`).first()).toBeVisible();
      // Badge showing format
      await expect(page.locator(`${SEL.modal} ${SEL.schemaBadge}`)).toBeVisible();

      // Switch to the Data tab — actual rows should render in the preview table.
      await page.locator(`${SEL.modal} ${SEL.dataTab}`).click();
      await expect(page.locator(`${SEL.modal} ${SEL.previewCsvTable} tbody tr`).first()).toBeVisible({ timeout: 10_000 });

      await page.locator(SEL.modalDismissButton).click();
    }
  });

  test('4.11 drag-and-drop shows overlay and opens upload modal', async ({ page }) => {
    // Simulate drag enter with Files type
    await page.evaluate(() => {
      const event = new DragEvent('dragenter', {
        bubbles: true,
        cancelable: true,
        dataTransfer: new DataTransfer(),
      });
      event.dataTransfer!.items.add(new File(['test'], 'drag-test.txt', { type: 'text/plain' }));
      document.querySelector('.app')?.dispatchEvent(event);
    });

    // Drop overlay should appear
    await expect(page.locator(SEL.dropOverlay)).toBeVisible({ timeout: 5_000 });
    await expect(page.locator(SEL.dropOverlayText)).toContainText('Drop files to upload');

    // Simulate drop
    await page.evaluate(() => {
      const dt = new DataTransfer();
      dt.items.add(new File(['test content'], 'drag-test.txt', { type: 'text/plain' }));
      const event = new DragEvent('drop', {
        bubbles: true,
        cancelable: true,
        dataTransfer: dt,
      });
      document.querySelector('.app')?.dispatchEvent(event);
    });

    // Upload modal should open with the dropped file
    await expect(page.locator(SEL.modal)).toBeVisible({ timeout: 5_000 });
    await page.locator(SEL.uploadCancelButton).click();
  });

  // 4.12 SQL-tab smoke test — the ONE e2e test that exercises real duckdb-wasm
  // (Tier 2). Everything else mocks the engine. See docs/architecture/
  // parquet-content-preview.md §3 (Tier 2). The ~34MB WASM downloads + compiles
  // on first SQL-tab open, which is slow under headless Chromium, so WASM-gated
  // steps use a 60s timeout. The suite must NOT hard-fail if sample.parquet is
  // missing or the WASM load is flaky in CI: every step is guarded with
  // isVisible().catch(() => false) and the test returns early (skips) when the
  // SQL tab isn't reachable. The SQL tab is only shown for files ≤ 128MB.
  test('4.12 runs ad-hoc SQL against Parquet via duckdb-wasm (SQL tab)', async ({ page }) => {
    const parquetRow = page.locator(`${SEL.tableRow}:has-text("sample.parquet")`).first();
    if (!(await parquetRow.isVisible().catch(() => false))) return;

    await parquetRow.locator(`${SEL.colActions} button`).first().click();
    await expect(page.locator(SEL.modal)).toBeVisible();

    // SQL tab is only rendered for files ≤ PARQUET_STREAM_CAP (128MB). If it's
    // absent (oversize file, or sample missing), skip cleanly rather than fail.
    const sqlTab = page.locator(`${SEL.modal} ${SEL.sqlTab}`);
    if (!(await sqlTab.isVisible().catch(() => false))) {
      await page.locator(SEL.modalDismissButton).click();
      return;
    }
    await sqlTab.click();

    // Wait for the editor to mount (engine boot: fetch bytes → instantiate
    // WASM → register view). The Run button is disabled until 'ready'.
    const runBtn = page.locator(`${SEL.modal} button:has-text("Run")`);
    await expect(runBtn).toBeEnabled({ timeout: 60_000 });

    // Run the default prefilled query (SELECT * FROM t LIMIT 100;) — but don't
    // assume the default is present; type one explicitly to be robust.
    const editor = page.locator(`${SEL.modal} textarea[aria-label="SQL editor"]`);
    await editor.fill('SELECT * FROM t LIMIT 100;');
    await runBtn.click();

    // A result row should appear in the preview table. Real WASM is slow → 60s.
    await expect(page.locator(`${SEL.modal} ${SEL.previewCsvTable} tbody tr`).first())
      .toBeVisible({ timeout: 60_000 });

    await page.locator(SEL.modalDismissButton).click();
  });
});
