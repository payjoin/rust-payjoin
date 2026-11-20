- Report storage failures as server errors instead of `400 Bad Request`. A
  v1 response for a sender that is no longer waiting now returns
  `410 Gone`, and a mailbox write that hits a storage error returns
  `500 Internal Server Error`, matching what mailbox reads already
  return. A mailbox write when storage is full now returns
  `503 Service Unavailable` instead of `500`.
