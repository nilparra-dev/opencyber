export * as ForkCyberPagination from "./pagination.js"

export function page<T>(rows: readonly T[], offset = 0, limit = 25) {
  return {
    items: rows.slice(0, limit),
    offset,
    limit,
    has_more: rows.length > limit,
    next_offset: rows.length > limit ? offset + limit : null,
  }
}
