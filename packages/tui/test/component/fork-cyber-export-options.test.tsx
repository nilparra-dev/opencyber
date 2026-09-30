/** @jsxImportSource @opentui/solid */
import { testRender } from "@opentui/solid"
import { expect, test } from "bun:test"
import { onMount } from "solid-js"
import { ConfigProvider } from "../../src/config"
import { ClientProvider } from "../../src/context/client"
import { DataProvider } from "../../src/context/data"
import { Keymap } from "../../src/context/keymap"
import { LocationProvider } from "../../src/context/location"
import { RouteProvider } from "../../src/context/route"
import { ThemeProvider } from "../../src/context/theme"
import { DialogProvider, useDialog } from "../../src/ui/dialog"
import { DialogExportOptions, type DialogExportOptionsProps } from "../../src/ui/dialog-export-options"
import { ToastProvider } from "../../src/ui/toast"
import { emptyThemeSource, tmpdir } from "../fixture/fixture"
import { createApi, createEventStream, createFetch } from "../fixture/tui-client"
import { TestTuiContexts } from "../fixture/tui-environment"
import { createTuiResolvedConfig } from "../fixture/tui-runtime"

for (const width of [40, 100])
  for (const format of ["markdown", "json"] as const) {
    test(`export options preserve privacy and thinking for copy and save in ${format} at ${width} columns`, async () => {
      await using temporary = await tmpdir()
      const submissions: Array<Parameters<NonNullable<DialogExportOptionsProps["onConfirm"]>>[0]> = []
      const api = createApi(createFetch(() => undefined, createEventStream()).fetch)
      function OpenDialog() {
        const dialog = useDialog()
        onMount(() =>
          dialog.replace(() => (
            <DialogExportOptions defaultThinking={true} onConfirm={(options) => submissions.push(options)} />
          )),
        )
        return null
      }
      const app = await testRender(
        () => (
          <TestTuiContexts directory={temporary.path} paths={{ state: temporary.path }}>
            <ConfigProvider config={createTuiResolvedConfig()}>
              <RouteProvider initialRoute={{ type: "home" }}>
                <ClientProvider api={api}>
                  <DataProvider directory={temporary.path}>
                    <LocationProvider>
                      <ThemeProvider mode={width === 40 ? "light" : "dark"} source={emptyThemeSource}>
                        <Keymap.Provider>
                          <ToastProvider>
                            <DialogProvider>
                              <OpenDialog />
                            </DialogProvider>
                          </ToastProvider>
                        </Keymap.Provider>
                      </ThemeProvider>
                    </LocationProvider>
                  </DataProvider>
                </ClientProvider>
              </RouteProvider>
            </ConfigProvider>
          </TestTuiContexts>
        ),
        { width, height: 30, kittyKeyboard: true },
      )
      const press = async (key: "tab" | "return") => {
        if (key === "return") app.mockInput.pressEnter()
        if (key === "tab") app.mockInput.pressTab()
        await app.renderOnce()
      }
      try {
        app.renderer.start()
        await app.waitForFrame((frame) => frame.includes("Profile: redacted"))
        await press("tab")
        if (format === "json") await press("return")
        await press("tab")
        await press("return")
        await app.waitForFrame((frame) => frame.includes("Profile: analysis"))
        await press("tab")
        await press("return")
        if (format === "markdown") {
          await press("tab")
          await press("return")
        }
        await press("tab")
        await press("tab")
        await press("return")
        await app.waitFor(() => submissions.length === 1)
        await press("tab")
        await press("return")
        await app.waitFor(() => submissions.length === 2)
        expect(submissions).toEqual(
          (["copy", "export"] as const).map((action) => ({
            action,
            format,
            profile: "analysis",
            thinking: false,
            tools: format === "json",
            sanitize: false,
          })),
        )
        expect(app.captureCharFrame()).toContain("Include thinking")
        expect(app.captureCharFrame()).toContain("Copy")
        expect(app.captureCharFrame()).toContain("Export")
      } finally {
        app.renderer.destroy()
      }
    })
  }
