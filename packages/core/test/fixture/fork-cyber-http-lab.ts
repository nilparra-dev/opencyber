import { Effect } from "effect"
import http from "node:http"

// A loopback HTTP target for fork-cyber tests. The listener closes with the enclosing scope.
export const lab = (handler: http.RequestListener) =>
  Effect.acquireRelease(
    Effect.promise(
      () =>
        new Promise<{ server: http.Server; url: string }>((resolve) => {
          const server = http.createServer(handler)
          server.listen(0, "127.0.0.1", () => {
            const address = server.address()
            if (!address || typeof address === "string") throw new Error("Expected TCP listener")
            resolve({ server, url: `http://127.0.0.1:${address.port}` })
          })
        }),
    ),
    ({ server }) =>
      Effect.promise(
        () =>
          new Promise<void>((resolve) => {
            server.closeAllConnections()
            server.close(() => resolve())
          }),
      ),
  )
