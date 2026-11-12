/** @jsxImportSource @opentui/solid */
import { testRender } from "@opentui/solid"
import { expect, test } from "bun:test"
import { onMount } from "solid-js"
import { ConfigProvider } from "../../src/config"
import { Keymap } from "../../src/context/keymap"
import { ThemeProvider, useTheme } from "../../src/context/theme"
import { DialogProvider, useDialog } from "../../src/ui/dialog"
import { DialogExportOptions } from "../../src/ui/dialog-export-options"
import { ToastProvider } from "../../src/ui/toast"
import { emptyThemeSource, tmpdir } from "../fixture/fixture"
import { TestTuiContexts } from "../fixture/tui-environment"
import { createTuiResolvedConfig } from "../fixture/tui-runtime"

// fork: the export dialog is the fork-owned profile UI; its navigation and privacy behavior are
// covered by fork-cyber-export-options.test.tsx. This upstream focus-color test targets the
// previous DialogSelect implementation (F-023).
test.skip("tab and shift+tab move a visible focus through the export options", async () => {
  await using temporary = await tmpdir()
  let theme: ReturnType<ReturnType<typeof useTheme>["surface"]> | undefined
  const app = await testRender(
    () => (
      <TestTuiContexts directory={temporary.path} paths={{ state: temporary.path }}>
        <ConfigProvider config={createTuiResolvedConfig()}>
          <ThemeProvider mode="dark" source={emptyThemeSource}>
            <Keymap.Provider>
              <ToastProvider>
                <DialogProvider>
                  {(() => {
                    theme = useTheme().surface("dialog")
                    const dialog = useDialog()
                    onMount(() => dialog.replace(() => <DialogExportOptions defaultThinking={true} />))
                    return null
                  })()}
                </DialogProvider>
              </ToastProvider>
            </Keymap.Provider>
          </ThemeProvider>
        </ConfigProvider>
      </TestTuiContexts>
    ),
    { width: 80, height: 24, kittyKeyboard: true },
  )
  const span = (text: string) =>
    app
      .captureSpans()
      .lines.flatMap((line) => line.spans)
      .find((span) => span.text.includes(text))
  const focusedButton = () => theme!.background.action.primary.focused
  const focusedField = () => theme!.text.formfield.focused
  const selectedField = () => theme!.text.formfield.selected

  try {
    app.renderer.start()
    await app.waitForFrame((frame) => frame.includes("Copy") && frame.includes("Include tools"))
    // Only the focused field is highlighted; checked fields use the selected colour.
    expect(span("Markdown")?.fg.equals(focusedField())).toBe(true)
    expect(span("Include thinking")?.fg.equals(selectedField())).toBe(true)
    expect(span("Copy")?.bg.equals(focusedButton())).toBe(false)

    // fork: the profile row adds two positions to the export-option cycle (F-023).
    for (const _ of [1, 2, 3, 4, 5, 6]) {
      app.mockInput.pressTab()
      await app.renderOnce()
    }
    await app.waitForFrame(() => span("Copy")?.bg.equals(focusedButton()) === true)
    expect(span("Include tools")?.fg.equals(selectedField())).toBe(true)

    for (const _ of [1, 2]) {
      app.mockInput.pressTab({ shift: true })
      await app.renderOnce()
    }
    await app.waitForFrame(() => span("Include tools")?.fg.equals(focusedField()) === true)
    expect(span("Copy")?.bg.equals(focusedButton())).toBe(false)
  } finally {
    app.renderer.destroy()
  }
})
